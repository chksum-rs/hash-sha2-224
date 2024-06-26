//! Module contains items related to the [`State`] structure which allows to the direct MD5 state manipulation.
//!
//! # Example
//!
//! ```rust
//! use chksum_hash_sha2_224 as sha2_224;
//!
//! // Create new state
//! let mut state = sha2_224::state::default();
//!
//! // By default it returns initialization values
//! assert_eq!(
//!     state.digest(),
//!     [0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7]
//! );
//!
//! // Manually create block of data with proper padding
//! let data = [
//!     u32::from_be_bytes([0x80, 0x00, 0x00, 0x00]),
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     # u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//!     // ...
//!     u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
//! ];
//!
//! // Update state and own new value
//! state = state.update(data);
//!
//! // Proper digest of empty input
//! assert_eq!(
//!     state.digest(),
//!     [0xD14A028C, 0x2A3A2BC9, 0x476102BB, 0x288234C4, 0x15A2B01F, 0x828EA62A, 0xC5B3E42F]
//! );
//!
//! // Reset state to initial values
//! state = state.reset();
//! assert_eq!(
//!     state.digest(),
//!     [0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7]
//! );
//! ```
//!
//! # Warning
//!
//! The [`State`] structure does not modify internal state, each function returns a new state that must be used.

use crate::block::LENGTH_DWORDS as BLOCK_LENGTH_DWORDS;
use crate::digest::LENGTH_DWORDS as DIGEST_LENGTH_DWORDS;

#[allow(clippy::unreadable_literal)]
#[rustfmt::skip]
const H: [u32; 8] = [
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
    0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,
];

#[allow(clippy::unreadable_literal)]
#[rustfmt::skip]
const K: [u32; 64] = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
];

/// Create a new state.
#[must_use]
pub const fn new() -> State {
    State::new()
}

/// Creates a default state.
#[must_use]
pub fn default() -> State {
    State::default()
}

/// A low-level hash state.
///
/// Check [`state`](self) module for usage examples.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct State {
    pub(crate) a: u32,
    pub(crate) b: u32,
    pub(crate) c: u32,
    pub(crate) d: u32,
    pub(crate) e: u32,
    pub(crate) f: u32,
    pub(crate) g: u32,
    pub(crate) h: u32,
}

impl State {
    /// Creates a new state.
    #[must_use]
    pub const fn new() -> Self {
        let [a, b, c, d, e, f, g, h] = H;
        Self { a, b, c, d, e, f, g, h }
    }

    /// Returns modified state with the passed data.
    ///
    /// **Warning!** Input block must be in the big-endian byte order.
    #[must_use]
    pub const fn update(&self, block: [u32; BLOCK_LENGTH_DWORDS]) -> Self {
        const fn small_sigma0(x: u32) -> u32 {
            x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
        }

        const fn small_sigma1(x: u32) -> u32 {
            x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
        }

        #[rustfmt::skip]
        let mut w = [
            block[0x0], block[0x1], block[0x2], block[0x3],
            block[0x4], block[0x5], block[0x6], block[0x7],
            block[0x8], block[0x9], block[0xA], block[0xB],
            block[0xC], block[0xD], block[0xE], block[0xF],
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
                     0,          0,          0,          0,
        ];
        w[0x10] = small_sigma1(w[0x0E])
            .wrapping_add(w[0x09])
            .wrapping_add(small_sigma0(w[0x01]))
            .wrapping_add(w[0x00]);
        w[0x11] = small_sigma1(w[0x0F])
            .wrapping_add(w[0x0A])
            .wrapping_add(small_sigma0(w[0x02]))
            .wrapping_add(w[0x01]);
        w[0x12] = small_sigma1(w[0x10])
            .wrapping_add(w[0x0B])
            .wrapping_add(small_sigma0(w[0x03]))
            .wrapping_add(w[0x02]);
        w[0x13] = small_sigma1(w[0x11])
            .wrapping_add(w[0x0C])
            .wrapping_add(small_sigma0(w[0x04]))
            .wrapping_add(w[0x03]);
        w[0x14] = small_sigma1(w[0x12])
            .wrapping_add(w[0x0D])
            .wrapping_add(small_sigma0(w[0x05]))
            .wrapping_add(w[0x04]);
        w[0x15] = small_sigma1(w[0x13])
            .wrapping_add(w[0x0E])
            .wrapping_add(small_sigma0(w[0x06]))
            .wrapping_add(w[0x05]);
        w[0x16] = small_sigma1(w[0x14])
            .wrapping_add(w[0x0F])
            .wrapping_add(small_sigma0(w[0x07]))
            .wrapping_add(w[0x06]);
        w[0x17] = small_sigma1(w[0x15])
            .wrapping_add(w[0x10])
            .wrapping_add(small_sigma0(w[0x08]))
            .wrapping_add(w[0x07]);
        w[0x18] = small_sigma1(w[0x16])
            .wrapping_add(w[0x11])
            .wrapping_add(small_sigma0(w[0x09]))
            .wrapping_add(w[0x08]);
        w[0x19] = small_sigma1(w[0x17])
            .wrapping_add(w[0x12])
            .wrapping_add(small_sigma0(w[0x0A]))
            .wrapping_add(w[0x09]);
        w[0x1A] = small_sigma1(w[0x18])
            .wrapping_add(w[0x13])
            .wrapping_add(small_sigma0(w[0x0B]))
            .wrapping_add(w[0x0A]);
        w[0x1B] = small_sigma1(w[0x19])
            .wrapping_add(w[0x14])
            .wrapping_add(small_sigma0(w[0x0C]))
            .wrapping_add(w[0x0B]);
        w[0x1C] = small_sigma1(w[0x1A])
            .wrapping_add(w[0x15])
            .wrapping_add(small_sigma0(w[0x0D]))
            .wrapping_add(w[0x0C]);
        w[0x1D] = small_sigma1(w[0x1B])
            .wrapping_add(w[0x16])
            .wrapping_add(small_sigma0(w[0x0E]))
            .wrapping_add(w[0x0D]);
        w[0x1E] = small_sigma1(w[0x1C])
            .wrapping_add(w[0x17])
            .wrapping_add(small_sigma0(w[0x0F]))
            .wrapping_add(w[0x0E]);
        w[0x1F] = small_sigma1(w[0x1D])
            .wrapping_add(w[0x18])
            .wrapping_add(small_sigma0(w[0x10]))
            .wrapping_add(w[0x0F]);
        w[0x20] = small_sigma1(w[0x1E])
            .wrapping_add(w[0x19])
            .wrapping_add(small_sigma0(w[0x11]))
            .wrapping_add(w[0x10]);
        w[0x21] = small_sigma1(w[0x1F])
            .wrapping_add(w[0x1A])
            .wrapping_add(small_sigma0(w[0x12]))
            .wrapping_add(w[0x11]);
        w[0x22] = small_sigma1(w[0x20])
            .wrapping_add(w[0x1B])
            .wrapping_add(small_sigma0(w[0x13]))
            .wrapping_add(w[0x12]);
        w[0x23] = small_sigma1(w[0x21])
            .wrapping_add(w[0x1C])
            .wrapping_add(small_sigma0(w[0x14]))
            .wrapping_add(w[0x13]);
        w[0x24] = small_sigma1(w[0x22])
            .wrapping_add(w[0x1D])
            .wrapping_add(small_sigma0(w[0x15]))
            .wrapping_add(w[0x14]);
        w[0x25] = small_sigma1(w[0x23])
            .wrapping_add(w[0x1E])
            .wrapping_add(small_sigma0(w[0x16]))
            .wrapping_add(w[0x15]);
        w[0x26] = small_sigma1(w[0x24])
            .wrapping_add(w[0x1F])
            .wrapping_add(small_sigma0(w[0x17]))
            .wrapping_add(w[0x16]);
        w[0x27] = small_sigma1(w[0x25])
            .wrapping_add(w[0x20])
            .wrapping_add(small_sigma0(w[0x18]))
            .wrapping_add(w[0x17]);
        w[0x28] = small_sigma1(w[0x26])
            .wrapping_add(w[0x21])
            .wrapping_add(small_sigma0(w[0x19]))
            .wrapping_add(w[0x18]);
        w[0x29] = small_sigma1(w[0x27])
            .wrapping_add(w[0x22])
            .wrapping_add(small_sigma0(w[0x1A]))
            .wrapping_add(w[0x19]);
        w[0x2A] = small_sigma1(w[0x28])
            .wrapping_add(w[0x23])
            .wrapping_add(small_sigma0(w[0x1B]))
            .wrapping_add(w[0x1A]);
        w[0x2B] = small_sigma1(w[0x29])
            .wrapping_add(w[0x24])
            .wrapping_add(small_sigma0(w[0x1C]))
            .wrapping_add(w[0x1B]);
        w[0x2C] = small_sigma1(w[0x2A])
            .wrapping_add(w[0x25])
            .wrapping_add(small_sigma0(w[0x1D]))
            .wrapping_add(w[0x1C]);
        w[0x2D] = small_sigma1(w[0x2B])
            .wrapping_add(w[0x26])
            .wrapping_add(small_sigma0(w[0x1E]))
            .wrapping_add(w[0x1D]);
        w[0x2E] = small_sigma1(w[0x2C])
            .wrapping_add(w[0x27])
            .wrapping_add(small_sigma0(w[0x1F]))
            .wrapping_add(w[0x1E]);
        w[0x2F] = small_sigma1(w[0x2D])
            .wrapping_add(w[0x28])
            .wrapping_add(small_sigma0(w[0x20]))
            .wrapping_add(w[0x1F]);
        w[0x30] = small_sigma1(w[0x2E])
            .wrapping_add(w[0x29])
            .wrapping_add(small_sigma0(w[0x21]))
            .wrapping_add(w[0x20]);
        w[0x31] = small_sigma1(w[0x2F])
            .wrapping_add(w[0x2A])
            .wrapping_add(small_sigma0(w[0x22]))
            .wrapping_add(w[0x21]);
        w[0x32] = small_sigma1(w[0x30])
            .wrapping_add(w[0x2B])
            .wrapping_add(small_sigma0(w[0x23]))
            .wrapping_add(w[0x22]);
        w[0x33] = small_sigma1(w[0x31])
            .wrapping_add(w[0x2C])
            .wrapping_add(small_sigma0(w[0x24]))
            .wrapping_add(w[0x23]);
        w[0x34] = small_sigma1(w[0x32])
            .wrapping_add(w[0x2D])
            .wrapping_add(small_sigma0(w[0x25]))
            .wrapping_add(w[0x24]);
        w[0x35] = small_sigma1(w[0x33])
            .wrapping_add(w[0x2E])
            .wrapping_add(small_sigma0(w[0x26]))
            .wrapping_add(w[0x25]);
        w[0x36] = small_sigma1(w[0x34])
            .wrapping_add(w[0x2F])
            .wrapping_add(small_sigma0(w[0x27]))
            .wrapping_add(w[0x26]);
        w[0x37] = small_sigma1(w[0x35])
            .wrapping_add(w[0x30])
            .wrapping_add(small_sigma0(w[0x28]))
            .wrapping_add(w[0x27]);
        w[0x38] = small_sigma1(w[0x36])
            .wrapping_add(w[0x31])
            .wrapping_add(small_sigma0(w[0x29]))
            .wrapping_add(w[0x28]);
        w[0x39] = small_sigma1(w[0x37])
            .wrapping_add(w[0x32])
            .wrapping_add(small_sigma0(w[0x2A]))
            .wrapping_add(w[0x29]);
        w[0x3A] = small_sigma1(w[0x38])
            .wrapping_add(w[0x33])
            .wrapping_add(small_sigma0(w[0x2B]))
            .wrapping_add(w[0x2A]);
        w[0x3B] = small_sigma1(w[0x39])
            .wrapping_add(w[0x34])
            .wrapping_add(small_sigma0(w[0x2C]))
            .wrapping_add(w[0x2B]);
        w[0x3C] = small_sigma1(w[0x3A])
            .wrapping_add(w[0x35])
            .wrapping_add(small_sigma0(w[0x2D]))
            .wrapping_add(w[0x2C]);
        w[0x3D] = small_sigma1(w[0x3B])
            .wrapping_add(w[0x36])
            .wrapping_add(small_sigma0(w[0x2E]))
            .wrapping_add(w[0x2D]);
        w[0x3E] = small_sigma1(w[0x3C])
            .wrapping_add(w[0x37])
            .wrapping_add(small_sigma0(w[0x2F]))
            .wrapping_add(w[0x2E]);
        w[0x3F] = small_sigma1(w[0x3D])
            .wrapping_add(w[0x38])
            .wrapping_add(small_sigma0(w[0x30]))
            .wrapping_add(w[0x2F]);

        let state = *self;

        const fn ch(x: u32, y: u32, z: u32) -> u32 {
            (x & y) ^ (!x & z)
        }

        const fn maj(x: u32, y: u32, z: u32) -> u32 {
            (x & y) ^ (x & z) ^ (y & z)
        }

        const fn capital_sigma0(x: u32) -> u32 {
            x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
        }

        const fn capital_sigma1(x: u32) -> u32 {
            x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
        }

        #[allow(clippy::too_many_arguments)]
        #[rustfmt::skip]
        const fn round(State { a, b, c, d, e, f, g, h }: State, w: u32, k: u32) -> State {
            let t1 = h.wrapping_add(capital_sigma1(e)).wrapping_add(ch(e, f, g)).wrapping_add(k).wrapping_add(w);
            let t2 = capital_sigma0(a).wrapping_add(maj(a, b, c));
            let h = g;
            let g = f;
            let f = e;
            let e = d.wrapping_add(t1);
            let d = c;
            let c = b;
            let b = a;
            let a = t1.wrapping_add(t2);
            State { a, b, c, d, e, f, g, h }
        }

        let state = round(state, w[0x00], K[0x00]);
        let state = round(state, w[0x01], K[0x01]);
        let state = round(state, w[0x02], K[0x02]);
        let state = round(state, w[0x03], K[0x03]);
        let state = round(state, w[0x04], K[0x04]);
        let state = round(state, w[0x05], K[0x05]);
        let state = round(state, w[0x06], K[0x06]);
        let state = round(state, w[0x07], K[0x07]);
        let state = round(state, w[0x08], K[0x08]);
        let state = round(state, w[0x09], K[0x09]);
        let state = round(state, w[0x0A], K[0x0A]);
        let state = round(state, w[0x0B], K[0x0B]);
        let state = round(state, w[0x0C], K[0x0C]);
        let state = round(state, w[0x0D], K[0x0D]);
        let state = round(state, w[0x0E], K[0x0E]);
        let state = round(state, w[0x0F], K[0x0F]);
        let state = round(state, w[0x10], K[0x10]);
        let state = round(state, w[0x11], K[0x11]);
        let state = round(state, w[0x12], K[0x12]);
        let state = round(state, w[0x13], K[0x13]);
        let state = round(state, w[0x14], K[0x14]);
        let state = round(state, w[0x15], K[0x15]);
        let state = round(state, w[0x16], K[0x16]);
        let state = round(state, w[0x17], K[0x17]);
        let state = round(state, w[0x18], K[0x18]);
        let state = round(state, w[0x19], K[0x19]);
        let state = round(state, w[0x1A], K[0x1A]);
        let state = round(state, w[0x1B], K[0x1B]);
        let state = round(state, w[0x1C], K[0x1C]);
        let state = round(state, w[0x1D], K[0x1D]);
        let state = round(state, w[0x1E], K[0x1E]);
        let state = round(state, w[0x1F], K[0x1F]);
        let state = round(state, w[0x20], K[0x20]);
        let state = round(state, w[0x21], K[0x21]);
        let state = round(state, w[0x22], K[0x22]);
        let state = round(state, w[0x23], K[0x23]);
        let state = round(state, w[0x24], K[0x24]);
        let state = round(state, w[0x25], K[0x25]);
        let state = round(state, w[0x26], K[0x26]);
        let state = round(state, w[0x27], K[0x27]);
        let state = round(state, w[0x28], K[0x28]);
        let state = round(state, w[0x29], K[0x29]);
        let state = round(state, w[0x2A], K[0x2A]);
        let state = round(state, w[0x2B], K[0x2B]);
        let state = round(state, w[0x2C], K[0x2C]);
        let state = round(state, w[0x2D], K[0x2D]);
        let state = round(state, w[0x2E], K[0x2E]);
        let state = round(state, w[0x2F], K[0x2F]);
        let state = round(state, w[0x30], K[0x30]);
        let state = round(state, w[0x31], K[0x31]);
        let state = round(state, w[0x32], K[0x32]);
        let state = round(state, w[0x33], K[0x33]);
        let state = round(state, w[0x34], K[0x34]);
        let state = round(state, w[0x35], K[0x35]);
        let state = round(state, w[0x36], K[0x36]);
        let state = round(state, w[0x37], K[0x37]);
        let state = round(state, w[0x38], K[0x38]);
        let state = round(state, w[0x39], K[0x39]);
        let state = round(state, w[0x3A], K[0x3A]);
        let state = round(state, w[0x3B], K[0x3B]);
        let state = round(state, w[0x3C], K[0x3C]);
        let state = round(state, w[0x3D], K[0x3D]);
        let state = round(state, w[0x3E], K[0x3E]);
        let state = round(state, w[0x3F], K[0x3F]);

        // Update

        let Self { a, b, c, d, e, f, g, h } = state;

        let a = a.wrapping_add(self.a);
        let b = b.wrapping_add(self.b);
        let c = c.wrapping_add(self.c);
        let d = d.wrapping_add(self.d);
        let e = e.wrapping_add(self.e);
        let f = f.wrapping_add(self.f);
        let g = g.wrapping_add(self.g);
        let h = h.wrapping_add(self.h);

        // Return

        Self { a, b, c, d, e, f, g, h }
    }

    /// Returns a new state with initial values.
    #[must_use]
    pub const fn reset(self) -> Self {
        Self::new()
    }

    /// Returns a digest.
    #[must_use]
    pub const fn digest(&self) -> [u32; DIGEST_LENGTH_DWORDS] {
        let Self {
            a, b, c, d, e, f, g, ..
        } = *self;
        [a, b, c, d, e, f, g]
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_empty() {
        let digest = new().digest();
        assert_eq!(
            digest,
            [0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7]
        );
    }

    #[test]
    fn default_empty() {
        let digest = default().digest();
        assert_eq!(
            digest,
            [0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7]
        );
    }

    #[test]
    fn new_zeros() {
        #[rustfmt::skip]
        let block = [
            u32::from_be_bytes([0x80, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
            u32::from_be_bytes([0x00, 0x00, 0x00, 0x00]),
        ];
        let digest = new().update(block).digest();
        assert_eq!(
            digest,
            [0xD14A028C, 0x2A3A2BC9, 0x476102BB, 0x288234C4, 0x15A2B01F, 0x828EA62A, 0xC5B3E42F]
        );
    }
}
