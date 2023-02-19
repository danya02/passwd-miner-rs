use std::fmt::Display;

/// Module implementing creating and checking Unix MD5 hashes.
use md5::{Digest, Md5};

use crate::base64_24::{base64_24bit_decode, base64_24bit_encode};

#[derive(Debug, Clone, PartialEq)]
pub struct HashedMD5Password {
    /// The password's salt. This can be up to 8 characters long.
    pub salt: [u8; 8],

    /// The actual salt's length.
    /// The first bytes from the salt are taken, and the rest are ignored.
    pub salt_len: u8,

    /// The actual password hash.
    pub hash: [u8; 16],
}

const ROUNDS: usize = 1000;

impl HashedMD5Password {
    /// Make a hashed password from an unhashed password and a salt.
    pub fn from_pw(key: &[u8], salt: &[u8]) -> Self {
        // This implementation was rewritten from https://github.com/tredoe/osutil/blob/master/v2/userutil/crypt/md5_crypt/md5_crypt.go

        assert!(salt.len() <= 8);

        // The hashing procedure starts by making a hash of key, then salt, then key.
        let mut hasher = Md5::new();
        hasher.update(key);
        hasher.update(salt);
        hasher.update(key);
        let alternate = hasher.finalize_reset();
        let alternate_b: &[u8] = &alternate.clone()[..];

        // Now we hash key, the magic string "$1$", salt, and then the alternate hash looped with the length that matches the key.
        hasher.update(key);
        hasher.update(b"$1$");
        hasher.update(salt);
        let first_val = &hasher.clone().finalize().clone()[..];
        let infinite_alternate = alternate
            .iter()
            .cloned() // This does nothing because u8 is Copy
            .cycle();
        for (_key_byte, alternate_byte) in key.iter().zip(infinite_alternate) {
            hasher.update([alternate_byte]);
            // TODO: profile to check if this is efficient!
        }
        let second_val = &hasher.clone().finalize().clone()[..];

        // Go source's comment:
        // > The original implementation now does something weird:
        // >   For every 1 bit in the key, the first 0 is added to the buffer
        // >   For every 0 bit, the first character of the key
        // > This does not seem to be what was intended but we have to follow this to
        // > be compatible.
        let mut i = key.len();
        while i > 0 {
            if i & 1 == 0 {
                hasher.update(&key[0..1]);
            } else {
                hasher.update([0]);
            }
            i >>= 1;
        }

        let mut c_sum = hasher.finalize_reset();
        let csum_b: &[u8] = &c_sum.clone()[..];
        // WORKS until here!!!

        // Now is a long loop designed to make cracking more difficult.
        for i in 0..ROUNDS {
            // At every round, add either the key or the last result
            if i & 1 != 0 {
                hasher.update(key);
            } else {
                hasher.update(c_sum);
            }

            // If the number is not divisible by 3, add salt
            if i % 3 != 0 {
                hasher.update(salt);
            }

            // If the number is not divisible by 7, add key
            if i % 7 != 0 {
                hasher.update(key);
            }

            // Finally add either last result or key -- the opposite of what was added before
            if i & 1 == 0 {
                hasher.update(key);
            } else {
                hasher.update(c_sum);
            }
            c_sum = hasher.finalize_reset();
        }

        let mut sized_salt = [0; 8];
        for (i, v) in salt.iter().enumerate() {
            sized_salt[i] = *v;
        }

        let csumfinal_b: &[u8] = &c_sum.clone()[..];

        // The resulting output is the final hash
        HashedMD5Password {
            salt: sized_salt,
            salt_len: salt.len() as u8,
            hash: c_sum.into(),
        }
    }

    /// Parse the Unix password string corresponding to an MD5-password.
    pub fn from_unix(unix_str: &str) -> Option<Self> {
        // The Unix MD5 string has the format "$1${salt}${base64(hash)}"
        let pieces: Vec<&str> = unix_str.split('$').collect();
        // The first piece must be empty because the first dollar is right next to it
        if pieces[0] != "" {
            return None;
        }
        // The second piece must be "1"
        if pieces[1] != "1" {
            return None;
        }
        // The third piece is the salt
        // The fourth piece must be the MD5: a base64 string of 16 bytes
        let salt = pieces[2];
        if salt.len() > 8 {
            return None;
        }
        let salt = salt.as_bytes();
        let md5 = base64_24bit_decode(pieces[3])?;
        if md5.len() != 16 {
            return None;
        }

        let md5: [u8; 16] = md5.try_into().ok()?;

        let mut sized_salt = [0; 8];
        for (i, v) in salt.iter().enumerate() {
            sized_salt[i] = *v;
        }

        Some(HashedMD5Password {
            salt: sized_salt,
            salt_len: salt.len() as u8,
            hash: md5,
        })
    }
}

impl Display for HashedMD5Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let readable_salt = String::from_utf8_lossy(&self.salt[..self.salt_len as usize]);
        write!(
            f,
            "$1${}${}",
            readable_salt,
            base64_24bit_encode(&self.hash)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn display_and_from_unix() {
        // Password is "Hello World!"
        let pw = "$1$hello$xMBKJV00/bbgMFMAincFo0";
        let loaded = HashedMD5Password::from_unix(pw).unwrap();
        assert_eq!(&loaded.salt, b"hello\0\0\0");
        assert_eq!(loaded.salt_len, 5);
        let formatted = format!("{}", loaded);
        assert_eq!(pw, formatted);
    }

    #[test]
    fn hashing() {
        // Password is "Hello World!"
        let pw = "$1$hello$OYK6k6djmHg1dIhMlFMPA/";
        let loaded = HashedMD5Password::from_unix(pw).unwrap();
        let hashed = HashedMD5Password::from_pw(b"hello", b"hello");
        let hash = hashed.hash;
        assert_eq!(hashed, loaded);
    }
}
