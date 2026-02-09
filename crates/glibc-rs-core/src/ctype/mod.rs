//! Character classification and conversion.
//!
//! Implements `<ctype.h>` functions for classifying and transforming
//! individual bytes/characters.

/// Returns `true` if `c` is an alphabetic character (`[A-Za-z]`).
///
/// Equivalent to C `isalpha`.
pub fn is_alpha(_c: u8) -> bool {
    todo!("POSIX isalpha: implementation pending")
}

/// Returns `true` if `c` is a decimal digit (`[0-9]`).
///
/// Equivalent to C `isdigit`.
pub fn is_digit(_c: u8) -> bool {
    todo!("POSIX isdigit: implementation pending")
}

/// Returns `true` if `c` is an alphanumeric character (`[A-Za-z0-9]`).
///
/// Equivalent to C `isalnum`.
pub fn is_alnum(_c: u8) -> bool {
    todo!("POSIX isalnum: implementation pending")
}

/// Returns `true` if `c` is a whitespace character.
///
/// Equivalent to C `isspace`. Whitespace: space, tab, newline, vertical tab,
/// form feed, carriage return.
pub fn is_space(_c: u8) -> bool {
    todo!("POSIX isspace: implementation pending")
}

/// Returns `true` if `c` is an uppercase letter (`[A-Z]`).
///
/// Equivalent to C `isupper`.
pub fn is_upper(_c: u8) -> bool {
    todo!("POSIX isupper: implementation pending")
}

/// Returns `true` if `c` is a lowercase letter (`[a-z]`).
///
/// Equivalent to C `islower`.
pub fn is_lower(_c: u8) -> bool {
    todo!("POSIX islower: implementation pending")
}

/// Returns `true` if `c` is a printable character (including space).
///
/// Equivalent to C `isprint`.
pub fn is_print(_c: u8) -> bool {
    todo!("POSIX isprint: implementation pending")
}

/// Returns `true` if `c` is a punctuation character.
///
/// Equivalent to C `ispunct`.
pub fn is_punct(_c: u8) -> bool {
    todo!("POSIX ispunct: implementation pending")
}

/// Returns `true` if `c` is a hexadecimal digit (`[0-9A-Fa-f]`).
///
/// Equivalent to C `isxdigit`.
pub fn is_xdigit(_c: u8) -> bool {
    todo!("POSIX isxdigit: implementation pending")
}

/// Converts `c` to uppercase if it is a lowercase letter.
///
/// Equivalent to C `toupper`.
pub fn to_upper(_c: u8) -> u8 {
    todo!("POSIX toupper: implementation pending")
}

/// Converts `c` to lowercase if it is an uppercase letter.
///
/// Equivalent to C `tolower`.
pub fn to_lower(_c: u8) -> u8 {
    todo!("POSIX tolower: implementation pending")
}
