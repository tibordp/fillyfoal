//! Profiling and coverage data written by compilers and runtimes: GCC's
//! gcov notes and counts (`.gcno`, `.gcda`), LLVM instrumentation profiles
//! (raw `.profraw` and indexed `.profdata`), JDK Flight Recorder
//! recordings (`.jfr`) and .NET EventPipe traces (`.nettrace`).

pub mod gcov;
pub mod jfr;
pub mod llvm;
pub mod nettrace;
