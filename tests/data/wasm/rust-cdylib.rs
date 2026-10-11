#![no_std]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

static GREETING: &[u8] = b"hello from rust";
static mut COUNTER: u32 = 0;

#[no_mangle]
pub extern "C" fn fib(n: u32) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n {
        let t = a.wrapping_add(b);
        a = b;
        b = t;
    }
    a
}

#[no_mangle]
pub extern "C" fn greeting() -> *const u8 {
    GREETING.as_ptr()
}

#[no_mangle]
pub extern "C" fn bump() -> u32 {
    unsafe {
        COUNTER = COUNTER.wrapping_add(1);
        COUNTER
    }
}

#[inline(never)]
fn mix(h: u32, b: u8) -> u32 {
    (h ^ b as u32).wrapping_mul(0x0100_0193)
}

#[no_mangle]
pub extern "C" fn checksum(ptr: *const u8, len: usize) -> u32 {
    let mut h = 0x811c_9dc5u32;
    for i in 0..len {
        h = mix(h, unsafe { *ptr.add(i) });
    }
    h.wrapping_add(fib(10) as u32)
}
