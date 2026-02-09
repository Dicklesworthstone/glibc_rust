//! Floating-point utility functions.

#[inline]
pub fn fabs(x: f64) -> f64 {
    x.abs()
}

#[inline]
pub fn ceil(x: f64) -> f64 {
    x.ceil()
}

#[inline]
pub fn floor(x: f64) -> f64 {
    x.floor()
}

#[inline]
pub fn round(x: f64) -> f64 {
    x.round()
}

#[inline]
pub fn fmod(x: f64, y: f64) -> f64 {
    x % y
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_sanity() {
        assert_eq!(fabs(-3.5), 3.5);
        assert_eq!(ceil(2.1), 3.0);
        assert_eq!(floor(2.9), 2.0);
        assert_eq!(round(2.5), 3.0);
        assert!((fmod(5.5, 2.0) - 1.5).abs() < 1e-12);
    }
}
