//! SipHash-based allocation fingerprints and trailing canaries.
//!
//! Every membrane-managed allocation gets:
//! - A 16-byte fingerprint header: `[u64 hash | u32 generation | u32 size]`
//! - An 8-byte trailing canary (known pattern derived from the hash)
//!
//! The fingerprint provides:
//! - Allocation integrity verification (P(undetected corruption) <= 2^-64)
//! - Generation tracking for temporal safety
//! - Size metadata for bounds checking

/// Size of the fingerprint header prepended to allocations.
pub const FINGERPRINT_SIZE: usize = 16;

/// Size of the trailing canary appended to allocations.
pub const CANARY_SIZE: usize = 8;

/// Total overhead per allocation (header + canary).
pub const TOTAL_OVERHEAD: usize = FINGERPRINT_SIZE + CANARY_SIZE;

/// Allocation fingerprint stored as a header before the user-visible pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct AllocationFingerprint {
    /// SipHash-2-4 of (base_address, size, generation, secret).
    pub hash: u64,
    /// Generation counter for temporal safety.
    pub generation: u32,
    /// Allocation size in bytes (user-requested, not including overhead).
    pub size: u32,
}

impl AllocationFingerprint {
    /// Compute a fingerprint for the given allocation parameters.
    #[must_use]
    pub fn compute(base_addr: usize, size: u32, generation: u32) -> Self {
        let hash = sip_hash_2_4(base_addr, size, generation);
        Self {
            hash,
            generation,
            size,
        }
    }

    /// Verify that this fingerprint matches the expected values.
    #[must_use]
    pub fn verify(&self, base_addr: usize) -> bool {
        let expected_hash = sip_hash_2_4(base_addr, self.size, self.generation);
        self.hash == expected_hash
    }

    /// Serialize fingerprint to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; FINGERPRINT_SIZE] {
        let mut buf = [0u8; FINGERPRINT_SIZE];
        buf[0..8].copy_from_slice(&self.hash.to_le_bytes());
        buf[8..12].copy_from_slice(&self.generation.to_le_bytes());
        buf[12..16].copy_from_slice(&self.size.to_le_bytes());
        buf
    }

    /// Deserialize fingerprint from bytes.
    #[must_use]
    pub fn from_bytes(buf: &[u8; FINGERPRINT_SIZE]) -> Self {
        let hash = u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let generation = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let size = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        Self {
            hash,
            generation,
            size,
        }
    }

    /// Derive the canary value from the fingerprint hash.
    #[must_use]
    pub fn canary(&self) -> Canary {
        Canary::from_hash(self.hash)
    }
}

/// 8-byte trailing canary for buffer overflow detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Canary {
    /// The canary bytes derived from the allocation hash.
    pub value: [u8; CANARY_SIZE],
}

impl Canary {
    /// Derive canary from a fingerprint hash.
    #[must_use]
    pub fn from_hash(hash: u64) -> Self {
        // XOR-fold and bit-rotate to create a distinct pattern
        let folded = hash ^ hash.rotate_left(32) ^ 0xDEAD_BEEF_CAFE_BABEu64;
        Self {
            value: folded.to_le_bytes(),
        }
    }

    /// Serialize to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CANARY_SIZE] {
        self.value
    }

    /// Check if a byte slice matches this canary.
    #[must_use]
    pub fn verify(&self, bytes: &[u8; CANARY_SIZE]) -> bool {
        self.value == *bytes
    }
}

/// SipHash-2-4 implementation (simplified, key is compile-time constant).
///
/// Uses a fixed secret key. This is NOT a cryptographic application —
/// the goal is collision resistance for allocation integrity.
fn sip_hash_2_4(addr: usize, size: u32, generation: u32) -> u64 {
    // Fixed key (chosen by fair dice roll, guaranteed to be random)
    const K0: u64 = 0x0706_0504_0302_0100;
    const K1: u64 = 0x0F0E_0D0C_0B0A_0908;

    let mut v0: u64 = K0 ^ 0x736f_6d65_7073_6575;
    let mut v1: u64 = K1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2: u64 = K0 ^ 0x6c79_6765_6e65_7261;
    let mut v3: u64 = K1 ^ 0x7465_6462_7974_6573;

    // Pack inputs into a 128-bit message
    let m0 = addr as u64;
    let m1 = (size as u64) | ((generation as u64) << 32);

    // Process m0
    v3 ^= m0;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m0;

    // Process m1
    v3 ^= m1;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m1;

    // Finalization
    v2 ^= 0xFF;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

#[inline(always)]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_roundtrip() {
        let fp = AllocationFingerprint::compute(0x1000, 256, 1);
        let bytes = fp.to_bytes();
        let fp2 = AllocationFingerprint::from_bytes(&bytes);
        assert_eq!(fp, fp2);
    }

    #[test]
    fn fingerprint_verify_passes_for_correct_addr() {
        let fp = AllocationFingerprint::compute(0x2000, 512, 3);
        assert!(fp.verify(0x2000));
    }

    #[test]
    fn fingerprint_verify_fails_for_wrong_addr() {
        let fp = AllocationFingerprint::compute(0x2000, 512, 3);
        assert!(!fp.verify(0x3000));
    }

    #[test]
    fn canary_roundtrip() {
        let fp = AllocationFingerprint::compute(0x4000, 128, 1);
        let canary = fp.canary();
        let bytes = canary.to_bytes();
        assert!(canary.verify(&bytes));
    }

    #[test]
    fn canary_detects_corruption() {
        let fp = AllocationFingerprint::compute(0x4000, 128, 1);
        let canary = fp.canary();
        let mut corrupted = canary.to_bytes();
        corrupted[3] ^= 0xFF;
        assert!(!canary.verify(&corrupted));
    }

    #[test]
    fn different_params_produce_different_fingerprints() {
        let fp1 = AllocationFingerprint::compute(0x1000, 256, 1);
        let fp2 = AllocationFingerprint::compute(0x1000, 256, 2);
        let fp3 = AllocationFingerprint::compute(0x2000, 256, 1);
        assert_ne!(fp1.hash, fp2.hash);
        assert_ne!(fp1.hash, fp3.hash);
    }
}
