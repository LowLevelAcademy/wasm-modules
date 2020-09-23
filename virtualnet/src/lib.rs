//! This crate implements the virtual network for the 'TCP/IP Fundamentals' course on lowlvl.org
//! It is based on smoltcp, the pure Rust TCP/IP stack implementation.

#[cfg(test)]
mod interface;

mod middleware;
mod vnet;

use std::alloc::{alloc, dealloc, realloc, Layout};
use std::mem;

pub use vnet::*;

#[cfg(test)]
mod test {
    #[no_mangle]
    unsafe fn print_log(src: *const u8, len: usize) {
        let str = String::from_utf8_lossy(std::slice::from_raw_parts(src, len));
        println!("{}", str);
    }

    #[no_mangle]
    fn notify_rx(_packet: *const u8, _len: usize) {}

    #[no_mangle]
    fn notify_tx(_packet: *const u8, _len: usize) {}

    #[no_mangle]
    fn test_completed(_test_num: u8) {}

    #[cfg(test)]
    #[test]
    fn test_vnet() {
        use std::net::Ipv4Addr;

        let src_ip = Ipv4Addr::new(10, 0, 0, 1).octets();
        let dst_ip = Ipv4Addr::new(10, 0, 0, 99).octets();
        // let dst_ip = Ipv4Addr::new(1, 2, 3, 4).octets();
        let data = b"Alice";

        unsafe {
            crate::setup_network(false);

            let sock = crate::udp_bind(u32::from_be_bytes(src_ip), 1000);
            crate::udp_send_to(
                sock,
                data.as_ptr(),
                data.len() as u16,
                u32::from_be_bytes(dst_ip),
                1000,
                // 53,
            );

            let mut polls = 0;

            while polls < 3 {
                crate::poll_network();
                polls += 1;
            }
        }
    }
}

/// Allocate memory in the virtual network module.
#[no_mangle]
pub extern "C" fn __wbindgen_malloc(size: usize) -> *mut u8 {
    let align = mem::align_of::<usize>();
    if let Ok(layout) = Layout::from_size_align(size, align) {
        unsafe {
            if layout.size() > 0 {
                let ptr = alloc(layout);
                if !ptr.is_null() {
                    return ptr;
                }
            } else {
                return align as *mut u8;
            }
        }
    }

    malloc_failure();
}

/// Reallocate memory in the virtual network module.
#[no_mangle]
pub unsafe extern "C" fn __wbindgen_realloc(
    ptr: *mut u8,
    old_size: usize,
    new_size: usize,
) -> *mut u8 {
    let align = mem::align_of::<usize>();
    debug_assert!(old_size > 0);
    debug_assert!(new_size > 0);
    if let Ok(layout) = Layout::from_size_align(old_size, align) {
        let ptr = realloc(ptr, layout, new_size);
        if !ptr.is_null() {
            return ptr;
        }
    }
    malloc_failure();
}

#[cold]
fn malloc_failure() -> ! {
    if cfg!(debug_assertions) {
        panic!("invalid malloc request")
    // throw_str("invalid malloc request")
    } else {
        std::process::abort();
    }
}

/// Deallocate memory in the virtual network module.
#[no_mangle]
pub unsafe extern "C" fn __wbindgen_free(ptr: *mut u8, size: usize) {
    // This happens for zero-length slices, and in that case `ptr` is
    // likely bogus so don't actually send this to the system allocator
    if size == 0 {
        return;
    }
    let align = mem::align_of::<usize>();
    let layout = Layout::from_size_align_unchecked(size, align);
    dealloc(ptr, layout);
}
