(module
  (memory (export "memory") 1)
  (func (export "dealloc") (param i32) (param i32))
  (func (export "handle") (param i32) (param i32) (result i32)
    (i32.const 0))
)
