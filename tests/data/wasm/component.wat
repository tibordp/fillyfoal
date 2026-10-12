;; A small WebAssembly component (component model, layer 1) for
;; tests/fixtures/external/wasm/component.wasm: a core module, a nested
;; component, core and component instances, aliases, types, canonical
;; lift/lower, imports (a function with a version suffix, an instance, a
;; resource type bound) and exports. Built by tests/data/wasm/make-component.sh.
(component $outer
  (type $log-t (func (param "msg" string)))
  (import "fillyfoal:demo/log@0.1.0" (func $log (type $log-t)))
  (import "settings" (instance $settings
    (export "level" (func (result u32)))
  ))
  (import "handle" (type $handle (sub resource)))

  (core module $m
    (import "host" "log" (func $log (param i32 i32)))
    (memory (export "memory") 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      i32.const 1024)
    (func (export "add") (param i32 i32) (result i32)
      local.get 0
      local.get 1
      i32.add)
    (func (export "hello")
      i32.const 0
      i32.const 5
      call $log)
    (data (i32.const 0) "hello")
  )

  (core module $libc
    (memory (export "memory") 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      i32.const 0)
  )
  (core instance $libc-inst (instantiate $libc))

  (core func $log-lowered (canon lower (func $log)
    (memory $libc-inst "memory")
    (realloc (func $libc-inst "realloc"))))
  (core instance $host (export "log" (func $log-lowered)))
  (core instance $inst (instantiate $m (with "host" (instance $host))))

  (type $add-t (func (param "a" s32) (param "b" s32) (result s32)))
  (func $add (type $add-t) (canon lift (core func $inst "add")))
  (func $hello (canon lift (core func $inst "hello")))

  (component $inner
    (import "add" (func $f (param "a" s32) (param "b" s32) (result s32)))
    (export "sum" (func $f))
  )
  (instance $inner-inst (instantiate $inner (with "add" (func $add))))
  (alias export $inner-inst "sum" (func $sum))

  (export "add" (func $add))
  (export "hello" (func $hello))
  (export "sum" (func $sum))
  (export "settings-level" (func $settings "level"))
)
