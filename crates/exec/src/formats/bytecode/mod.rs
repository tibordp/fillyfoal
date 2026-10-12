//! Bytecode and compiled intermediate code: WebAssembly, LLVM bitcode,
//! SPIR-V, DXBC shaders, Python `.pyc`, Lua and LuaJIT, Erlang BEAM, OCaml,
//! Hermes, Dart kernels, Ruby YARB, Emacs `.elc`, PHP OPcache, Quake III
//! QVM, Unity IL2CPP metadata and compiled AppleScript.

pub mod applescript;
pub mod beam;
pub mod bitcode;
pub mod dart;
pub mod dxbc;
pub mod elc;
pub mod hermes;
pub mod il2cpp;
pub mod lua;
#[rustfmt::skip]
mod lua_ops;
pub mod luajit;
pub mod ocaml;
pub mod opcache;
pub mod pyc;
#[rustfmt::skip]
mod pyc_ops;
pub mod qvm;
pub mod spirv;
pub mod wasm;
pub mod yarb;
