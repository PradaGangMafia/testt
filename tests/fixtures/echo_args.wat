(module
  (import "env" "result" (func $result (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "dealloc") (param i32) (param i32))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i32)
    (call $result (local.get $ptr) (local.get $len))
    (i32.const 0))
)
