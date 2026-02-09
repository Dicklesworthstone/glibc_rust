//! Helper macros for ABI function generation.
//!
//! Provides the `abi_fn!` macro that generates `#[unsafe(no_mangle)] pub unsafe extern "C" fn`
//! wrappers with membrane validation hookpoints.

/// Generate an ABI-compatible extern "C" function with membrane validation hookpoint.
///
/// # Usage
///
/// ```ignore
/// abi_fn! {
///     /// Doc comment for the function.
///     fn my_func(arg1: Type1, arg2: Type2) -> ReturnType {
///         // implementation body
///     }
///
/// }
/// ```
///
/// This expands to a `#[unsafe(no_mangle)] pub unsafe extern "C" fn` with the given
/// signature and body. The body should include membrane validation calls as needed.
#[allow(unused_macros)]
macro_rules! abi_fn {
    (
        $(#[$meta:meta])*
        fn $name:ident( $($arg:ident : $argty:ty),* $(,)? ) -> $ret:ty
        $body:block
    ) => {
        $(#[$meta])*
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name( $($arg : $argty),* ) -> $ret {
            // Membrane validation hookpoint: validation logic is inlined
            // in the body to allow per-function customization of pointer
            // checks, bounds clamping, and healing actions.
            unsafe { $body }
        }
    };

    // Variant without return type (returns ())
    (
        $(#[$meta:meta])*
        fn $name:ident( $($arg:ident : $argty:ty),* $(,)? )
        $body:block
    ) => {
        $(#[$meta])*
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name( $($arg : $argty),* ) {
            unsafe { $body }
        }
    };
}

#[allow(unused_imports)]
pub(crate) use abi_fn;
