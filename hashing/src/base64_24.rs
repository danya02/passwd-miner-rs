use std::{collections::VecDeque, ops::Index};

use base64::{Engine, alphabet::Alphabet, engine::{GeneralPurposeConfig, DecodePaddingMode, GeneralPurpose}};

/// The Base64_24bit encoding scheme. Taken from https://github.com/tredoe/osutil/blob/master/v2/userutil/crypt/common/base64.go#L24.

/// The alphabet used for this base64 encoding.
const BASE64_ALPHABET: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn split_u8_into_bool_array(value: u8) -> [bool; 8] {
    let mut bool_array = [false; 8];
    for i in 0..8 {
        bool_array[i] = value & (1 << i) != 0;
    }
    bool_array
}

fn join_bool_array_into_u6(array: [bool; 6]) -> u8 {
    let mut value: u8 = 0;
    for i in 0..6 {
        if array[i] {
            value |= 1 << i;
        }
    }
    value
}


///   1. Bottom 6 bits of the first byte
///   2. Top 2 bits of the first byte, and bottom 4 bits of the second byte.
///   3. Top 4 bits of the second byte, and bottom 2 bits of the third byte.
///   4. Top 6 bits of the third byte.
fn conv_3u8_to_4u6(a: u8, b: u8, c: u8) -> [u8; 4] {
    let q = split_u8_into_bool_array(a);
    let w = split_u8_into_bool_array(b);
    let e = split_u8_into_bool_array(c);

    let a = [ q[2], q[3], q[4], q[5], q[6], q[7] ];
    let b = [ q[0], q[1], w[4], w[5], w[6], w[7] ];
    let c = [ w[0], w[1], w[2], w[3], e[6], e[7] ];
    let d = [ e[0], e[1], e[2], e[3], e[4], e[5] ];

    let a = join_bool_array_into_u6(a);
    let b = join_bool_array_into_u6(b);
    let c = join_bool_array_into_u6(c);
    let d = join_bool_array_into_u6(d);
    [a,b,c,d]
    
}

fn conv_4u6_to_3u8(parts: [u8; 4]) -> [u8; 3] {
    let [a,b,c,d] = parts;
    let a: [bool; 6] = split_u8_into_bool_array(a)[2..8].try_into().unwrap();
    let b: [bool; 6] = split_u8_into_bool_array(b)[2..8].try_into().unwrap();
    let c: [bool; 6] = split_u8_into_bool_array(c)[2..8].try_into().unwrap();
    let d: [bool; 6] = split_u8_into_bool_array(d)[2..8].try_into().unwrap();

    let q = [ b[0], b[1], a[0], a[1], a[2], a[3], a[4], a[5] ];
}

/// Base64_24Bit is a variant of Base64 encoding, commonly used with password
/// hashing algorithms to encode the result of their checksum output.
///
//// The algorithm operates on up to 3 bytes at a time, encoding the following
/// 6-bit sequences into up to 4 hash64 ASCII bytes.
///
///   1. Bottom 6 bits of the first byte
///   2. Top 2 bits of the first byte, and bottom 4 bits of the second byte.
///   3. Top 4 bits of the second byte, and bottom 2 bits of the third byte.
///   4. Top 6 bits of the third byte.
///
/// This encoding method does not emit padding bytes as Base64 does.
pub fn base64_24bit_encode(mut data: &[u8]) -> String {
    let mut output = Vec::with_capacity(data.len() * 8 / 6);
    // General case: there are 3 bytes or more left
    while data.len() >= 3 {
        let a = data[0];
        let b = data[1];
        let c = data[2];
        let parts = conv_3u8_to_4u6(a, b, c);
        let parts_chars = parts.map(|x| BASE64_ALPHABET[x as usize]);
        output.extend(parts_chars);
        data = &data[3..];
    }
    // Special case: there is two bytes left (makes 3 chars)
    if data.len() == 2 {
        let a = data[0];
        let b = data[1];
        let parts = conv_3u8_to_4u6(a, b, 0);
        let parts_chars = parts.map(|x| BASE64_ALPHABET[x as usize]);
        output.extend(&parts_chars[..3]);
    }
    // Special case: there is one byte left (makes 2 chars)
    if data.len() == 1 {
        let a = data[0];
        let parts = conv_3u8_to_4u6(a, 0, 0);
        let parts_chars = parts.map(|x| BASE64_ALPHABET[x as usize]);
        output.extend(&parts_chars[..2]);
    }


    // This is safe, because at every point we're adding bytes from `BASE64_ALPHABET`,
    // which is guaranteed to be ASCII, and ASCII is valid UTF8.
    unsafe {String::from_utf8_unchecked(output)}
}

pub fn base64_24bit_decode(data_as_str: &str) -> Option<Vec<u8>> {
    let mut data_as_u6s = Vec::with_capacity(data_as_str.len());
    for c in data_as_str.bytes() {
        // Find the index of the alphabet's byte that matches the taken string byte.
        // If it's a byte that's not in the alphabet, it's an invalid byte, so fail decoding.
        let char_index = BASE64_ALPHABET.iter().enumerate().find(|(_index, value)| **value == c)?.0;
        data_as_u6s.push(char_index as u8);
    }

    let mut data = &data_as_u6s[..];

    // General case: there is 4 chars to take
    let mut output = Vec::with_capacity(data.len() * 6 / 8);
    while data.len() >= 4 {
        let parts: [u8;4] = data[..4].try_into().unwrap();
        let result_parts = conv_4u6_to_3u8(parts);
        output.extend(result_parts);
        data = &data[4..];
    }

    // Special case: there is 3 chars to take (18 bits = 2 bytes + 2 extra)
    if data.len() == 3 {
        let a = data[0];
        let b = data[1];
        let c = data[2];
        let [a,b,_c] = conv_4u6_to_3u8([a,b,c,0]);
        output.push(a);
        output.push(b);
    }

    // Special case: there is 2 chars to take (12 bits = 1 byte + 4 extra)
    if data.len() == 2 {
        let a = data[0];
        let b = data[1];
        let [a,_b,_c] = conv_4u6_to_3u8([a,b,0,0]);
        output.push(a);
    }

    // Special case: there is 1 char to take (6 bits -- zero whole bytes, which is an error in encoding)
    if data.len() == 1 { return None; }

    Some(output)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_base64_conv_single() {
        let data = b"\xff";
        let enc = base64_24bit_encode(data);
        let dec = base64_24bit_decode(&enc);
        assert!(dec.is_some());
        let dec = dec.unwrap();
        assert_eq!(data, &dec[..]);
    }

    #[test]
    fn check_base64_conv_double() {
        let data = b"\x00\xff";
        let enc = base64_24bit_encode(data);
        let dec = base64_24bit_decode(&enc);
        assert!(dec.is_some());
        let dec = dec.unwrap();
        assert_eq!(data, &dec[..]);
    }
    #[test]
    fn check_base64_conv_triple() {
        let data = b"\x00\xaa\xff";
        let enc = base64_24bit_encode(data);
        let dec = base64_24bit_decode(&enc);
        assert!(dec.is_some());
        let dec = dec.unwrap();
        assert_eq!(data, &dec[..]);
    }

    #[test]
    fn check_base64_conv_long() {
        let mut data: Vec<u8> = b"Hello World!".iter().cloned().collect();
        for i in 0..=u8::MAX {
            data.push(i);
        }
        let enc = base64_24bit_encode(&data);
        let dec = base64_24bit_decode(&enc);
        assert!(dec.is_some());
        let dec = dec.unwrap();
        assert_eq!(data, &dec[..]);
    }

    #[test]
    fn check_password_hash() {
        // This is the hash part of an MD5 crypt with pw="hello" and salt="hello"
        let data = [
            33, 190, 14, 98, 109, 113, 105, 146, 196, 213, 132, 76, 26, 48, 242, 41,
        ];
        let encoded = "OYK6k6djmHg1dIhMlFMPA/";
        assert_eq!(base64_24bit_decode(encoded).unwrap(), data);
        assert_eq!(base64_24bit_encode(&data), encoded);
    }

    #[test]
    fn check_unpack_3u8(){
        let (a,b,c) = (33, 190, 14);
        let output = b"OYK6";
        let output = output.map(|x| *BASE64_ALPHABET.iter().find(|q| **q == x).unwrap());
        assert_eq!(conv_3u8_to_4u6(a,b,c), output);
    }

    #[test]
    fn check_u8_u6_inverse(){
        let inp = [0x00, 0x55, 0xff];
        let u6s = conv_3u8_to_4u6(inp[0], inp[1], inp[2]);
        let u8s = conv_4u6_to_3u8(u6s);
        assert_eq!(inp, u8s);
    }
}
