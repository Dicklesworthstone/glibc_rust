//! Mathematical functions.
//!
//! Implements `<math.h>` functions: trigonometric, exponential/logarithmic,
//! special functions, and floating-point utilities.

pub mod exp;
pub mod float;
pub mod special;
pub mod trig;

pub use exp::{exp, log, log10, pow};
pub use float::{ceil, fabs, floor, fmod, round};
pub use special::{erf, lgamma, tgamma};
pub use trig::{acos, asin, atan, atan2, cos, sin, tan};
