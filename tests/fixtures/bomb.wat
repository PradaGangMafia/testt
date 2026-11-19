(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "dealloc") (param i32) (param i32))
  (func (export "handle") (param i32) (param i32) (result i32)
    (local $i i64)
    (loop $spin
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $spin))
    (i32.wrap_i64 (local.get $i)))
)
