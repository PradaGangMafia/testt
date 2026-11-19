#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Durable relay queue HTTP service.

use std::{io, path::PathBuf, sync::Arc};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

struct Queue {
    root: PathBuf,
    next: u64,
    max_bytes: u64,
    max_frames: usize,
}

impl Queue {
    async fn open(root: PathBuf, max_bytes: u64, max_frames: usize) -> io::Result<Self> {
        fs::create_dir_all(&root).await?;
        let mut next = 0;
        let mut entries = fs::read_dir(&root).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(stem) = name.strip_suffix(".bin") {
                if let Ok(index) = stem.parse::<u64>() {
                    next = next.max(index);
                }
            } else if name.ends_with(".tmp") {
                let _ = fs::remove_file(entry.path()).await;
            }
        }
        Ok(Self {
            root,
            next,
            max_bytes,
            max_frames,
        })
    }
    async fn put(&mut self, body: &[u8]) -> io::Result<()> {
        let mut entries = fs::read_dir(&self.root).await?;
        let mut count = 0_usize;
        let mut total = 0_u64;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_name().to_string_lossy().ends_with(".bin") {
                count += 1;
                total += entry.metadata().await?.len();
            }
        }
        if count >= self.max_frames || total.saturating_add(body.len() as u64) > self.max_bytes {
            return Err(io::Error::other("queue capacity exceeded"));
        }
        self.next += 1;
        let final_path = self.root.join(format!("{:012}.bin", self.next));
        let temp_path = self.root.join(format!("{:012}.tmp", self.next));
        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(body).await?;
        file.sync_all().await?;
        fs::rename(&temp_path, &final_path).await?;
        sync_dir(&self.root).await
    }
    async fn list(&self, since: u64) -> io::Result<Vec<(u64, Vec<u8>)>> {
        let mut entries = fs::read_dir(&self.root).await?;
        let mut found = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".bin") else {
                continue;
            };
            let Ok(index) = stem.parse::<u64>() else {
                continue;
            };
            if index > since {
                found.push((index, fs::read(entry.path()).await?));
            }
        }
        found.sort_by_key(|(index, _)| *index);
        Ok(found)
    }
    async fn prune(&self, before: u64) -> io::Result<()> {
        let mut entries = fs::read_dir(&self.root).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(stem) = name.strip_suffix(".bin") {
                if stem
                    .parse::<u64>()
                    .ok()
                    .is_some_and(|index| index <= before)
                {
                    fs::remove_file(entry.path()).await?;
                }
            }
        }
        sync_dir(&self.root).await
    }
}

async fn sync_dir(path: &PathBuf) -> io::Result<()> {
    fs::File::open(path).await?.sync_all().await
}

async fn response(mut stream: TcpStream, status: &str, body: &[u8]) -> io::Result<()> {
    let header = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n", body.len());
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut diff = (left.len() ^ right.len()) as u8;
    for index in 0..left.len().max(right.len()) {
        diff |= left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0);
    }
    diff == 0
}
fn authorized(headers: &str, token: &Option<Vec<u8>>) -> bool {
    let Some(token) = token else { return true };
    headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("Authorization: ")
                .or_else(|| line.strip_prefix("authorization: "))
        })
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| constant_time_equal(value.as_bytes(), token))
}

async fn handle(
    mut stream: TcpStream,
    queue: Arc<Mutex<Queue>>,
    token: Option<Vec<u8>>,
) -> io::Result<()> {
    let mut bytes = Vec::new();
    let header_end;
    loop {
        let mut chunk = [0_u8; 1024];
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Ok(());
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = index + 4;
            break;
        }
    }
    let headers = String::from_utf8_lossy(&bytes[..header_end]).into_owned();
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("Content-Length:")
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    while bytes.len() < header_end + content_length {
        let mut chunk = [0_u8; 4096];
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let first = headers.lines().next().unwrap_or_default();
    if (first.starts_with("POST /put ") || first.starts_with("POST /prune "))
        && !authorized(&headers, &token)
    {
        return response(stream, "401 Unauthorized", b"{}\n").await;
    }
    if first.starts_with("POST /put ") {
        let result = queue.lock().await.put(&bytes[header_end..]).await;
        return match result {
            Ok(()) => response(stream, "200 OK", b"{}\n").await,
            Err(_) => response(stream, "507 Insufficient Storage", b"{}\n").await,
        };
    }
    if let Some(query) = first.strip_prefix("GET /list?since=") {
        let since = query
            .split_whitespace()
            .next()
            .unwrap_or("0")
            .parse::<u64>()
            .unwrap_or(0);
        let found = queue.lock().await.list(since).await?;
        let body = format!(
            "[{}]",
            found
                .iter()
                .map(|(index, frame)| format!("[{index},\"{}\"]", hex(frame)))
                .collect::<Vec<_>>()
                .join(",")
        );
        return response(stream, "200 OK", body.as_bytes()).await;
    }
    if let Some(query) = first.strip_prefix("POST /prune?before=") {
        let before = query
            .split_whitespace()
            .next()
            .unwrap_or("0")
            .parse::<u64>()
            .unwrap_or(0);
        queue.lock().await.prune(before).await?;
        return response(stream, "200 OK", b"{}\n").await;
    }
    if first.starts_with("GET /health ") {
        return response(stream, "200 OK", b"{}\n").await;
    }
    response(stream, "404 Not Found", b"{}\n").await
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut bind = "127.0.0.1:8787".to_owned();
    let mut root = PathBuf::from("relay-queue");
    let mut token = None;
    let mut max_bytes = 1_u64 << 30;
    let mut max_frames = 100_000_usize;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => {
                bind = args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--bind requires an address")
                })?
            }
            "--token-file" => {
                token = Some(PathBuf::from(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--token-file requires a path")
                })?))
            }
            "--max-bytes" => {
                max_bytes = args
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "--max-bytes requires a value")
                    })?
                    .parse()
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid --max-bytes")
                    })?
            }
            "--max-frames" => {
                max_frames = args
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "--max-frames requires a value")
                    })?
                    .parse()
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid --max-frames")
                    })?
            }
            value if value.starts_with('-') => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown option",
                ))
            }
            value if bind == "127.0.0.1:8787" => bind = value.to_owned(),
            value if root == *"relay-queue" => root = PathBuf::from(value),
            value => token = Some(PathBuf::from(value)),
        }
    }
    let token = match token {
        Some(path) => Some(
            fs::read(path)
                .await?
                .iter()
                .copied()
                .filter(|byte| *byte != b'\n' && *byte != b'\r')
                .collect(),
        ),
        None => None,
    };
    let listener = TcpListener::bind(bind).await?;
    let queue = Arc::new(Mutex::new(Queue::open(root, max_bytes, max_frames).await?));
    loop {
        let (stream, _) = listener.accept().await?;
        let queue = Arc::clone(&queue);
        let token = token.clone();
        tokio::spawn(async move {
            let _ = handle(stream, queue, token).await;
        });
    }
}
