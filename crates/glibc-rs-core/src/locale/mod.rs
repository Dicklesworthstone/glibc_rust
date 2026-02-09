//! Locale support.
//!
//! Implements `<locale.h>` functions for locale-dependent behavior.

/// Locale categories.
pub const LC_ALL: i32 = 0;
pub const LC_COLLATE: i32 = 1;
pub const LC_CTYPE: i32 = 2;
pub const LC_MONETARY: i32 = 3;
pub const LC_NUMERIC: i32 = 4;
pub const LC_TIME: i32 = 5;

/// Sets or queries the program's current locale.
///
/// Equivalent to C `setlocale`. If `locale` is empty, queries the current locale.
/// Returns the name of the locale that was set, or `None` on error.
pub fn setlocale(_category: i32, _locale: &[u8]) -> Option<Vec<u8>> {
    todo!("POSIX setlocale: implementation pending")
}

/// Returns locale-specific numeric and monetary formatting information.
///
/// Equivalent to C `localeconv`. Returns a snapshot of the current locale's
/// formatting conventions.
pub fn localeconv() -> LocaleConv {
    todo!("POSIX localeconv: implementation pending")
}

/// Numeric and monetary formatting conventions (like `struct lconv`).
#[derive(Debug, Clone, Default)]
pub struct LocaleConv {
    /// Decimal point character.
    pub decimal_point: Vec<u8>,
    /// Thousands separator.
    pub thousands_sep: Vec<u8>,
    /// Currency symbol.
    pub currency_symbol: Vec<u8>,
}
