//! Special mathematical functions.
//!
//! These implementations are compact approximations intended for bootstrap
//! coverage; conformance tightening can swap in higher-precision kernels later.

const SQRT_2PI: f64 = 2.506_628_274_631_000_7;
const LANCZOS_G: f64 = 7.0;
const LANCZOS_COEFFS: [f64; 9] = [
    0.999_999_999_999_809_9,
    676.520_368_121_885_1,
    -1_259.139_216_722_402_8,
    771.323_428_777_653_1,
    -176.615_029_162_140_6,
    12.507_343_278_686_905,
    -0.138_571_095_265_720_12,
    9.984_369_578_019_572e-6,
    1.505_632_735_149_311_6e-7,
];

#[inline]
pub fn erf(x: f64) -> f64 {
    if x == 0.0 {
        return 0.0;
    }
    // Abramowitz-Stegun 7.1.26 approximation.
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let ax = x.abs();
    let t = 1.0 / (1.0 + 0.327_591_1 * ax);
    let y = 1.0
        - (((((1.061_405_429 * t - 1.453_152_027) * t) + 1.421_413_741) * t - 0.284_496_736) * t
            + 0.254_829_592)
            * t
            * (-ax * ax).exp();
    sign * y
}

#[inline]
pub fn tgamma(x: f64) -> f64 {
    if x.is_nan() {
        return f64::NAN;
    }
    if x <= 0.0 && x.fract() == 0.0 {
        return f64::NAN;
    }

    if x < 0.5 {
        // Reflection formula: Γ(x) = π / (sin(πx) Γ(1-x))
        let denom = (std::f64::consts::PI * x).sin() * tgamma(1.0 - x);
        return std::f64::consts::PI / denom;
    }

    let z = x - 1.0;
    let mut acc = LANCZOS_COEFFS[0];
    for (i, coeff) in LANCZOS_COEFFS.iter().enumerate().skip(1) {
        acc += coeff / (z + i as f64);
    }
    let t = z + LANCZOS_G + 0.5;
    SQRT_2PI * t.powf(z + 0.5) * (-t).exp() * acc
}

#[inline]
pub fn lgamma(x: f64) -> f64 {
    tgamma(x).abs().ln()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erf_sanity() {
        assert!(erf(0.0).abs() < 1e-12);
        assert!((erf(1.0) - 0.8427).abs() < 5e-4);
    }

    #[test]
    fn gamma_sanity() {
        assert!((tgamma(5.0) - 24.0).abs() < 1e-8);
        assert!((lgamma(5.0) - 24.0_f64.ln()).abs() < 1e-8);
    }
}
