//! glibc_rust core crate.
//!
//! This crate introduces the first version of a Transparent Safety Membrane (TSM)
//! substrate at the libc ABI boundary.

pub mod safety;

use std::ffi::c_void;

use safety::{
    CopyDecision, CopyDisposition, PointerFacts, classify_pointer, decide_copy, global_registry,
};

/// Preview entrypoint for TSM-mediated memcpy semantics.
///
/// This symbol is intentionally namespaced until the project flips to real libc
/// symbol exports.
///
/// # Safety
///
/// - `dst` and `src` must be valid for reads/writes for the resulting number of
///   copied bytes under C ABI expectations.
/// - The membrane may clamp the requested length if metadata is available.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn glibc_rust_memcpy_preview(
    dst: *mut c_void,
    src: *const c_void,
    requested_len: usize,
) -> *mut c_void {
    if requested_len == 0 {
        return dst;
    }

    if dst.is_null() || src.is_null() {
        return std::ptr::null_mut();
    }

    let registry = global_registry();
    let src_facts: PointerFacts = classify_pointer(registry, src);
    let dst_facts: PointerFacts = classify_pointer(registry, dst.cast_const());

    let decision = decide_copy(requested_len, src_facts, dst_facts);

    let copy_len = match decision {
        CopyDecision {
            disposition: CopyDisposition::Allow,
            effective_len,
            ..
        }
        | CopyDecision {
            disposition: CopyDisposition::Repair,
            effective_len,
            ..
        } => effective_len,
        CopyDecision {
            disposition: CopyDisposition::Deny,
            ..
        } => 0,
    };

    if copy_len == 0 {
        return dst;
    }

    // SAFETY: We validated non-null pointers above; caller retains the C ABI
    // contract for pointer validity. The membrane only constrains length.
    unsafe {
        std::ptr::copy_nonoverlapping(src.cast::<u8>(), dst.cast::<u8>(), copy_len);
    }

    dst
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memcpy_preview_zero_len_returns_dst() {
        let mut dst = [0_u8; 4];
        let src = [1_u8, 2_u8, 3_u8, 4_u8];

        // SAFETY: test uses valid pointers and len=0.
        let result = unsafe {
            glibc_rust_memcpy_preview(
                dst.as_mut_ptr().cast::<c_void>(),
                src.as_ptr().cast::<c_void>(),
                0,
            )
        };

        assert_eq!(result, dst.as_mut_ptr().cast::<c_void>());
        assert_eq!(dst, [0_u8; 4]);
    }

    #[test]
    fn memcpy_preview_copies_when_valid() {
        let mut dst = [0_u8; 4];
        let src = [1_u8, 2_u8, 3_u8, 4_u8];

        // SAFETY: test uses valid pointers and bounded len.
        let _result = unsafe {
            glibc_rust_memcpy_preview(
                dst.as_mut_ptr().cast::<c_void>(),
                src.as_ptr().cast::<c_void>(),
                src.len(),
            )
        };

        assert_eq!(dst, src);
    }
}
