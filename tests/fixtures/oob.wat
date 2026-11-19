(module
  (import "env" "log" (func $log (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "dealloc") (param i32) (param i32))
  (func (export "handle") (param i32) (param i32) (result i32)
    (call $log (i32.const 999999) (i32.const 8))
    (i32.const 0))
)
