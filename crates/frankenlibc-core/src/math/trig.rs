//! Trigonometric functions.

#[inline]
pub fn sin(x: f64) -> f64 {
    x.sin()
}

#[inline]
pub fn cos(x: f64) -> f64 {
    x.cos()
}

#[inline]
pub fn tan(x: f64) -> f64 {
    x.tan()
}

#[inline]
pub fn asin(x: f64) -> f64 {
    x.asin()
}

#[inline]
pub fn acos(x: f64) -> f64 {
    x.acos()
}

#[inline]
pub fn atan(x: f64) -> f64 {
    x.atan()
}

#[inline]
pub fn atan2(y: f64, x: f64) -> f64 {
    y.atan2(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trig_sanity() {
        let x = 0.5_f64;
        assert!((sin(x) - x.sin()).abs() < 1e-12);
        assert!((cos(x) - x.cos()).abs() < 1e-12);
        assert!((tan(x) - x.tan()).abs() < 1e-12);
        assert!((asin(x) - x.asin()).abs() < 1e-12);
        assert!((acos(x) - x.acos()).abs() < 1e-12);
        assert!((atan(x) - x.atan()).abs() < 1e-12);
        assert!((atan2(1.0, 2.0) - 1.0_f64.atan2(2.0)).abs() < 1e-12);
    }
}
