//! Dashboard rendering over a live (encrypted) database.

use fleetui::{draw, load, Tab};
use ratatui::{backend::TestBackend, Terminal};
use tempfile::TempDir;

fn render(state: &std::path::Path, tab: Tab) -> String {
    let database = coordd::open_database(state).unwrap();
    let snapshot = load(&database).unwrap();
    let mut terminal = Terminal::new(TestBackend::new(140, 30)).unwrap();
    terminal.draw(|frame| draw(frame, &snapshot, tab)).unwrap();
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

#[test]
fn dashboard_shows_agents_and_switches_tabs() {
    let state = TempDir::new().unwrap();
    std::fs::write(state.path().join("agent.key"), [1_u8; 32]).unwrap();
    std::fs::write(state.path().join("enc.key"), [2_u8; 32]).unwrap();
    let database = coordd::open_database(state.path()).unwrap();
    let agent = [7_u8; 32];
    let tag = msgfmt::route_tag_from_key(&agent);
    database
        .upsert_agent(&agent, &tag, "host", "1", &[3_u8; 32])
        .unwrap();
    database.record_event("agent_seen", "host").unwrap();
    drop(database);

    let hex: String = tag.iter().map(|byte| format!("{byte:02x}")).collect();
    let agents = render(state.path(), Tab::Agents);
    assert!(agents.contains("AGENT FLEET"), "{agents}");
    assert!(agents.contains(&hex), "{agents}");
    assert!(agents.contains("Agents"), "{agents}");

    let events = render(state.path(), Tab::Events);
    assert!(events.contains("agent_seen"), "{events}");
    assert!(events.contains("Events"), "{events}");
}

#[test]
fn empty_coordinator_renders_without_panicking() {
    let state = TempDir::new().unwrap();
    std::fs::write(state.path().join("agent.key"), [1_u8; 32]).unwrap();
    std::fs::write(state.path().join("enc.key"), [2_u8; 32]).unwrap();
    let text = render(state.path(), Tab::Findings);
    assert!(text.contains("Findings"), "{text}");
}

#[test]
fn tab_titles_are_stable() {
    let titles: Vec<&str> = Tab::ALL.iter().map(|tab| tab.title()).collect();
    assert_eq!(
        titles,
        ["Agents", "Findings", "Artifacts", "Schedules", "Events"]
    );
}
