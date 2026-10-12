;; A WebAssembly component exercising the component model's type, canon,
;; core type, core instance, instance and start sections, for
;; tests/fixtures/external/wasm/component-types.wasm. Built by
;; tests/data/wasm/make-component.sh.
(component
  (core type $mt (module
    (import "env" "f" (func (param i32) (result i32)))
    (type $ft (func (param i64)))
    (export "mem" (memory 1))
    (export "g" (func (type $ft)))
  ))
  (core type $cft (func (param i32 i32) (result i32)))

  (type $point (record (field "x" s32) (field "y" s32)))
  (type $shape (variant (case "none") (case "circle" f64) (case "pt" $point)))
  (type $bytes (list u8))
  (type $pair (tuple u8 string))
  (type $perm (flags "read" "write" "exec"))
  (type $color (enum "red" "green" "blue"))
  (type $maybe (option u32))
  (type $res (result $point (error string)))
  (type $res2 (result))
  (type $r (resource (rep i32)))
  (type $own (own $r))
  (type $f (func (param "p" $point) (param "c" $color) (result $res)))
  (type $it (instance
    (type $t (record (field "a" u64)))
    (export "t" (type $tt (eq $t)))
    (export "get" (func (result $tt)))
    (export "res" (type (sub resource)))
  ))
  (type $ct (component
    (import "in" (func (param "x" bool)))
    (export "out" (func (result char)))
  ))

  (import "host" (instance $host (type $it)))
  (import "cfg" (value $cfg string))

  (core module $m
    (func (export "make") (param i32 i32) (result i32) local.get 0)
    (func (export "drop") (param i32))
    (func (export "run") (param i32 i32 i32) (result i32) local.get 0)
    (memory (export "memory") 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32) i32.const 0)
    (func (export "post") (param i32))
  )
  (core func $new (canon resource.new $r))
  (core func $drop (canon resource.drop $r))
  (core func $rep (canon resource.rep $r))
  (core instance $deps
    (export "new" (func $new))
    (export "drop" (func $drop))
    (export "rep" (func $rep))
  )
  (core instance $i (instantiate $m))
  (func $run (type $f) (canon lift (core func $i "run")
    (memory $i "memory") (realloc (func $i "realloc"))
    string-encoding=utf16 (post-return (func $i "post"))))
  (func $start (param "s" string) (result u32)
    (canon lift (core func $i "make") (memory $i "memory") (realloc (func $i "realloc"))))
  (instance $bundle
    (export "point" (type $point))
    (export "start" (func $start))
  )
  (start $start (value $cfg) (result (value $out)))
  (export "start" (func $start))
  (export "out" (value $out))
)
