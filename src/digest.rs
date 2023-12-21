//! Module contains items related to the [`Digest`] structure.
//!
//! # Example
//!
//! ```rust
//! use chksum_hash_sha2_224 as sha2_224;
//!
//! // Digest bytes
//! #[rustfmt::skip]
//! let digest = [
//!     0xD1, 0x4A, 0x02, 0x8C,
//!     0x2A, 0x3A, 0x2B, 0xC9,
//!     0x47, 0x61, 0x02, 0xBB,
//!     0x28, 0x82, 0x34, 0xC4,
//!     0x15, 0xA2, 0xB0, 0x1F,
//!     0x82, 0x8E, 0xA6, 0x2A,
//!     0xC5, 0xB3, 0xE4, 0x2F,
//! ];
//!
//! // Create new digest
//! let digest = sha2_224::digest::new(digest);
//!
//! // Print digest (by default it uses hex lowercase format)
//! println!("digest {}", digest);
//!
//! // You can also specify which format you prefer
//! println!("digest {:x}", digest);
//! println!("digest {:X}", digest);
//!
//! // Turn into byte slice
//! let bytes = digest.as_bytes();
//!
//! // Get inner bytes
//! let digest = digest.into_inner();
//!
//! // Should be same
//! assert_eq!(bytes, &digest[..]);
//! ```

use std::fmt::{self, Display, Formatter, LowerHex, UpperHex};
use std::num::ParseIntError;

use chksum_hash_core as core;

/// Digest length in bits.
pub const LENGTH_BITS: usize = 224;
/// Digest length in bytes.
pub const LENGTH_BYTES: usize = LENGTH_BITS / 8;
/// Digest length in words (double bytes).
pub const LENGTH_WORDS: usize = LENGTH_BYTES / 2;
/// Digest length in double words (quadruple bytes).
pub const LENGTH_DWORDS: usize = LENGTH_WORDS / 2;
/// Digest length in hexadecimal format.
pub const LENGTH_HEX: usize = LENGTH_BYTES * 2;

/// Creates a new [`Digest`].
#[must_use]
pub fn new(digest: [u8; LENGTH_BYTES]) -> Digest {
    Digest::new(digest)
}

/// A hash digest.
///
/// Check [`digest`](self) module for usage examples.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest([u8; LENGTH_BYTES]);

impl Digest {
    /// Creates a new digest.
    #[must_use]
    pub const fn new(digest: [u8; LENGTH_BYTES]) -> Self {
        Self(digest)
    }

    /// Returns a byte slice of the digest's contents.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the digest, returning the digest bytes.
    #[must_use]
    pub fn into_inner(self) -> [u8; LENGTH_BYTES] {
        let Self(inner) = self;
        inner
    }

    /// Returns a string in the lowercase hexadecimal representation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_hash_sha2_224 as sha2_224;
    ///
    /// #[rustfmt::skip]
    /// let digest = [
    ///     0xD1, 0x4A, 0x02, 0x8C,
    ///     0x2A, 0x3A, 0x2B, 0xC9,
    ///     0x47, 0x61, 0x02, 0xBB,
    ///     0x28, 0x82, 0x34, 0xC4,
    ///     0x15, 0xA2, 0xB0, 0x1F,
    ///     0x82, 0x8E, 0xA6, 0x2A,
    ///     0xC5, 0xB3, 0xE4, 0x2F,
    /// ];
    /// let digest = sha2_224::Digest::new(digest);
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    /// );
    /// ```
    #[must_use]
    pub fn to_hex_lowercase(&self) -> String {
        format!("{self:x}")
    }

    /// Returns a string in the uppercase hexadecimal representation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_hash_sha2_224 as sha2_224;
    ///
    /// #[rustfmt::skip]
    /// let digest = [
    ///     0xD1, 0x4A, 0x02, 0x8C,
    ///     0x2A, 0x3A, 0x2B, 0xC9,
    ///     0x47, 0x61, 0x02, 0xBB,
    ///     0x28, 0x82, 0x34, 0xC4,
    ///     0x15, 0xA2, 0xB0, 0x1F,
    ///     0x82, 0x8E, 0xA6, 0x2A,
    ///     0xC5, 0xB3, 0xE4, 0x2F,
    /// ];
    /// let digest = sha2_224::Digest::new(digest);
    /// assert_eq!(
    ///     digest.to_hex_uppercase(),
    ///     "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"
    /// );
    /// ```
    #[must_use]
    pub fn to_hex_uppercase(&self) -> String {
        format!("{self:X}")
    }
}

impl core::Digest for Digest {}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<[u8; LENGTH_BYTES]> for Digest {
    fn from(digest: [u8; LENGTH_BYTES]) -> Self {
        Self::new(digest)
    }
}

impl From<Digest> for [u8; LENGTH_BYTES] {
    fn from(digest: Digest) -> Self {
        digest.into_inner()
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        LowerHex::fmt(self, f)
    }
}

impl LowerHex for Digest {
    #[rustfmt::skip]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let digest = format!(
            "{:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}\
             {:02x}{:02x}{:02x}{:02x}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
            self.0[0x14], self.0[0x15], self.0[0x16], self.0[0x17],
            self.0[0x18], self.0[0x19], self.0[0x1A], self.0[0x1B],
        );
        if formatter.alternate() {
            formatter.pad_integral(true, "0x", &digest)
        } else {
            formatter.pad(&digest)
        }
    }
}

impl UpperHex for Digest {
    #[rustfmt::skip]
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let digest = format!(
            "{:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}\
             {:02X}{:02X}{:02X}{:02X}",
            self.0[0x00], self.0[0x01], self.0[0x02], self.0[0x03],
            self.0[0x04], self.0[0x05], self.0[0x06], self.0[0x07],
            self.0[0x08], self.0[0x09], self.0[0x0A], self.0[0x0B],
            self.0[0x0C], self.0[0x0D], self.0[0x0E], self.0[0x0F],
            self.0[0x10], self.0[0x11], self.0[0x12], self.0[0x13],
            self.0[0x14], self.0[0x15], self.0[0x16], self.0[0x17],
            self.0[0x18], self.0[0x19], self.0[0x1A], self.0[0x1B],
        );
        if formatter.alternate() {
            formatter.pad_integral(true, "0X", &digest)
        } else {
            formatter.pad(&digest)
        }
    }
}

impl TryFrom<&str> for Digest {
    type Error = FormatError;

    fn try_from(digest: &str) -> Result<Self, Self::Error> {
        if digest.len() != LENGTH_HEX {
            let error = Self::Error::InvalidLength {
                value: digest.len(),
                proper: LENGTH_HEX,
            };
            return Err(error);
        }
        let digest = [
            u32::from_str_radix(&digest[0x00..0x08], 16)?.to_be_bytes(),
            u32::from_str_radix(&digest[0x08..0x10], 16)?.to_be_bytes(),
            u32::from_str_radix(&digest[0x10..0x18], 16)?.to_be_bytes(),
            u32::from_str_radix(&digest[0x18..0x20], 16)?.to_be_bytes(),
            u32::from_str_radix(&digest[0x20..0x28], 16)?.to_be_bytes(),
            u32::from_str_radix(&digest[0x28..0x30], 16)?.to_be_bytes(),
            u32::from_str_radix(&digest[0x30..0x38], 16)?.to_be_bytes(),
        ];
        #[rustfmt::skip]
        let digest = [
            digest[0][0], digest[0][1], digest[0][2], digest[0][3],
            digest[1][0], digest[1][1], digest[1][2], digest[1][3],
            digest[2][0], digest[2][1], digest[2][2], digest[2][3],
            digest[3][0], digest[3][1], digest[3][2], digest[3][3],
            digest[4][0], digest[4][1], digest[4][2], digest[4][3],
            digest[5][0], digest[5][1], digest[5][2], digest[5][3],
            digest[6][0], digest[6][1], digest[6][2], digest[6][3],
        ];
        let digest = Self::from(digest);
        Ok(digest)
    }
}

/// An error type for the digest conversion.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum FormatError {
    /// Represents an invalid length error with detailed information.
    #[error("Invalid length `{value}`, proper value `{proper}`")]
    InvalidLength { value: usize, proper: usize },
    /// Represents an error that occurs during parsing.
    #[error(transparent)]
    ParseError(#[from] ParseIntError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_bytes() {
        #[rustfmt::skip]
        let digest = [
            0xD1, 0x4A, 0x02, 0x8C,
            0x2A, 0x3A, 0x2B, 0xC9,
            0x47, 0x61, 0x02, 0xBB,
            0x28, 0x82, 0x34, 0xC4,
            0x15, 0xA2, 0xB0, 0x1F,
            0x82, 0x8E, 0xA6, 0x2A,
            0xC5, 0xB3, 0xE4, 0x2F,
        ];
        assert_eq!(Digest::new(digest).as_bytes(), &digest);
    }

    #[test]
    fn as_ref() {
        #[rustfmt::skip]
        let digest = [
            0xD1, 0x4A, 0x02, 0x8C,
            0x2A, 0x3A, 0x2B, 0xC9,
            0x47, 0x61, 0x02, 0xBB,
            0x28, 0x82, 0x34, 0xC4,
            0x15, 0xA2, 0xB0, 0x1F,
            0x82, 0x8E, 0xA6, 0x2A,
            0xC5, 0xB3, 0xE4, 0x2F,
        ];
        assert_eq!(Digest::new(digest).as_ref(), &digest);
    }

    #[test]
    fn format() {
        #[rustfmt::skip]
        let digest = Digest::new([
            0xD1, 0x4A, 0x02, 0x8C,
            0x2A, 0x3A, 0x2B, 0xC9,
            0x47, 0x61, 0x02, 0xBB,
            0x28, 0x82, 0x34, 0xC4,
            0x15, 0xA2, 0xB0, 0x1F,
            0x82, 0x8E, 0xA6, 0x2A,
            0xC5, 0xB3, 0xE4, 0x2F,
        ]);
        assert_eq!(
            format!("{digest:x}"),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            format!("{digest:#x}"),
            "0xd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            format!("{digest:64x}"),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f        "
        );
        assert_eq!(
            format!("{digest:>64x}"),
            "        d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
        assert_eq!(
            format!("{digest:^64x}"),
            "    d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f    "
        );
        assert_eq!(
            format!("{digest:<64x}"),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f        "
        );
        assert_eq!(
            format!("{digest:.^64x}"),
            "....d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f...."
        );
        assert_eq!(format!("{digest:.8x}"), "d14a028c");
        assert_eq!(
            format!("{digest:X}"),
            "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"
        );
        assert_eq!(
            format!("{digest:#X}"),
            "0XD14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"
        );
        assert_eq!(
            format!("{digest:64X}"),
            "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F        "
        );
        assert_eq!(
            format!("{digest:>64X}"),
            "        D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"
        );
        assert_eq!(
            format!("{digest:^64X}"),
            "    D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F    "
        );
        assert_eq!(
            format!("{digest:<64X}"),
            "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F        "
        );
        assert_eq!(
            format!("{digest:.^64X}"),
            "....D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F...."
        );
        assert_eq!(format!("{digest:.8X}"), "D14A028C");
    }

    #[test]
    fn from() {
        #[rustfmt::skip]
        let digest = [
            0xD1, 0x4A, 0x02, 0x8C,
            0x2A, 0x3A, 0x2B, 0xC9,
            0x47, 0x61, 0x02, 0xBB,
            0x28, 0x82, 0x34, 0xC4,
            0x15, 0xA2, 0xB0, 0x1F,
            0x82, 0x8E, 0xA6, 0x2A,
            0xC5, 0xB3, 0xE4, 0x2F,
        ];
        assert_eq!(Digest::from(digest), Digest::new(digest));
        assert_eq!(<[u8; 28]>::from(Digest::new(digest)), digest);
    }

    #[test]
    fn to_hex() {
        #[rustfmt::skip]
        let digest = Digest::new([
            0xD1, 0x4A, 0x02, 0x8C,
            0x2A, 0x3A, 0x2B, 0xC9,
            0x47, 0x61, 0x02, 0xBB,
            0x28, 0x82, 0x34, 0xC4,
            0x15, 0xA2, 0xB0, 0x1F,
            0x82, 0x8E, 0xA6, 0x2A,
            0xC5, 0xB3, 0xE4, 0x2F,
        ]);
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_lowercase(), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
        #[rustfmt::skip]
        assert_eq!(digest.to_hex_uppercase(), "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F");
    }

    #[test]
    fn try_from() {
        assert_eq!(
            Digest::try_from("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
            Digest::try_from("D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F")
        );
        #[rustfmt::skip]
        assert_eq!(
            Digest::try_from("D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"),
            Ok(Digest::new([
                0xD1, 0x4A, 0x02, 0x8C,
                0x2A, 0x3A, 0x2B, 0xC9,
                0x47, 0x61, 0x02, 0xBB,
                0x28, 0x82, 0x34, 0xC4,
                0x15, 0xA2, 0xB0, 0x1F,
                0x82, 0x8E, 0xA6, 0x2A,
                0xC5, 0xB3, 0xE4, 0x2F,
            ]))
        );
        assert!(matches!(Digest::try_from("D1"), Err(FormatError::InvalidLength { .. })));
        assert!(matches!(
            Digest::try_from("D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42FXX"),
            Err(FormatError::InvalidLength { .. })
        ));
        assert!(matches!(
            Digest::try_from("D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E4XX"),
            Err(FormatError::ParseError(_))
        ));
    }
}
