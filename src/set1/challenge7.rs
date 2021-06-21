use std::convert::TryInto;

use crate::utils::byte_slice_utils::{ByteUtilsError, XOR};

/// Number of columns (32-bit words) comprising the state (block size)
///
/// Always 4 according to the standard
///
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
const NB: usize = 4;

/// Number of 32-bit words comprising the cipher key
const NK: usize = 4;

/// According to the standard, NR (number of rounds) is 10 if NK = 4 and NB = 4
const NR: usize = 10;

/// S-box hardcoded
const S: [u8; 0x100] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];
const RCON: [u8; 0x100] = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
];

const INV_S: [u8; 256] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
];

#[derive(Default)]
pub struct AES {
    data: Vec<u8>,
    key: [u8; 4 * NK],
}

impl AES {
    pub fn with_key(mut self, key: [u8; 4 * NK]) -> AES {
        self.key = key;
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> AES {
        self.data = data;
        self
    }

    pub fn encrypt_ecb(&self) -> Vec<u8> {
        let expanded_key = self.expand_key();
        let padded_payload = self.data.pkcs7_pad(NB * NB);
        let mut out = Vec::new();
        for i in 0..padded_payload.len() / (NB * NB) {
            let res = self.cipher(
                padded_payload[i * NB * NB..(i + 1) * NB * NB]
                    .try_into()
                    .unwrap(),
                &expanded_key,
            );
            out.extend(res);
        }
        out
    }
    
    pub fn decrypt_ecb(&self) -> Result<Vec<u8>, ByteUtilsError> {
        let expanded_key = self.expand_key();
        //let padded_payload = pkcs7_pad(payload, NB * NB);
        let mut out = Vec::new();
        for i in 0..self.data.len() / (NB * NB) {
            let res = self.inv_cipher(
                self.data[i * NB * NB..(i + 1) * NB * NB]
                    .try_into()
                    .unwrap(),
                &expanded_key,
            );
            out.extend(res);
        }
        out.pkcs7_unpad()
    }


    fn add_round_key(&self, state: &mut [u8; 4 * NB], subkey: &[u8]) {
        for (i, x) in state.iter_mut().enumerate() {
            *x ^= subkey[i];
        }
    }

    /// stolen from the example at:
    /// https://en.wikipedia.org/w/index.php?title=Rijndael_MixColumns&oldid=1009113287
    fn mix_columns(&self, state: &mut [u8; 4 * NB]) {
        let mut ss = *state;

        for c in 0..4 {
            ss[c * 4] = self.galois_mul(0x02, state[c * 4])
                ^ self.galois_mul(0x03, state[4 * c + 1])
                ^ state[4 * c + 2]
                ^ state[4 * c + 3];
            ss[4 * c + 1] = state[c * 4]
                ^ self.galois_mul(0x02, state[4 * c + 1])
                ^ self.galois_mul(0x03, state[4 * c + 2])
                ^ state[4 * c + 3];
            ss[4 * c + 2] = state[4 * c]
                ^ state[4 * c + 1]
                ^ self.galois_mul(0x02, state[4 * c + 2])
                ^ self.galois_mul(0x03, state[4 * c + 3]);
            ss[4 * c + 3] = self.galois_mul(0x03, state[4 * c])
                ^ state[4 * c + 1]
                ^ state[4 * c + 2]
                ^ self.galois_mul(0x02, state[4 * c + 3]);
        }

        *state = ss;
    }

    /// stolen from the example at:
    /// https://en.wikipedia.org/w/index.php?title=Rijndael_MixColumns&oldid=1009113287
    fn inv_mix_columns(&self, state: &mut [u8; 4 * NB]) {
        let mut ss = *state;

        for c in 0..4 {
            ss[c * 4] = self.galois_mul(14, state[c * 4])
                ^ self.galois_mul(11, state[4 * c + 1])
                ^ self.galois_mul(13, state[4 * c + 2])
                ^ self.galois_mul(9, state[4 * c + 3]);
            ss[4 * c + 1] = self.galois_mul(9, state[c * 4])
                ^ self.galois_mul(14, state[4 * c + 1])
                ^ self.galois_mul(11, state[4 * c + 2])
                ^ self.galois_mul(13, state[4 * c + 3]);
            ss[4 * c + 2] = self.galois_mul(13, state[4 * c])
                ^ self.galois_mul(9, state[4 * c + 1])
                ^ self.galois_mul(14, state[4 * c + 2])
                ^ self.galois_mul(11, state[4 * c + 3]);
            ss[4 * c + 3] = self.galois_mul(11, state[4 * c])
                ^ self.galois_mul(13, state[4 * c + 1])
                ^ self.galois_mul(9, state[4 * c + 2])
                ^ self.galois_mul(14, state[4 * c + 3]);
        }

        *state = ss;
    }

    /// stolen from the example at:
    /// https://en.wikipedia.org/w/index.php?title=Rijndael_MixColumns&oldid=1009113287
    fn galois_mul(&self, mut a: u8, mut b: u8) -> u8 {
        // Galois Field (256) Multiplication of two Bytes
        let mut p = 0;
        for _ in 0..8 {
            if (b & 1) != 0 {
                p ^= a;
            }
            let hi_bit_set = (a & 0x80) != 0;
            a <<= 1;
            if hi_bit_set {
                a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
            }
            b >>= 1;
        }
        p
    }

    /// Shift bytes in rows 1-n to the left by n
    ///
    /// CAUTION: the state is ordered column-first!
    fn shift_rows(&self, state: &mut [u8; 4 * NB]) {
        for i in 0..NB {
            let mut row = [0; NB];
            for j in 0..NB {
                row[j] = state[NB * j + i];
            }
            for _ in 0..i {
                self.rotate(&mut row);
            }
            for j in 0..NB {
                state[NB * j + i] = row[j];
            }
        }
    }

    fn inv_shift_rows(&self, state: &mut [u8; 4 * NB]) {
        for i in 0..NB {
            let mut row = [0; NB];
            for j in 0..NB {
                row[j] = state[NB * j + i];
            }
            for _ in 0..i {
                self.inv_rotate(&mut row);
            }
            for j in 0..NB {
                state[NB * j + i] = row[j];
            }
        }
    }

    fn rotate(&self, slice: &mut [u8]) {
        let buf = slice[0];
        for i in 0..slice.len() - 1 {
            slice[i] = slice[i + 1];
        }
        slice[slice.len() - 1] = buf;
    }

    fn inv_rotate(&self, slice: &mut [u8]) {
        let buf = slice[slice.len() - 1];
        for i in 0..slice.len() - 1 {
            slice[slice.len() - 1 - i] = slice[slice.len() - 1 - (i + 1)];
        }
        slice[0] = buf;
    }

    fn sub_bytes(&self, state: &mut [u8]) {
        for i in state.iter_mut() {
            *i = S[*i as usize];
        }
    }

    fn inv_sub_bytes(&self, state: &mut [u8]) {
        for i in state.iter_mut() {
            *i = INV_S[*i as usize];
        }
    }

    fn expand_key(&self) -> [u8; 4 * NB * (NR + 1)] {
        let mut expanded_key: [u8; 4 * NB * (NR + 1)] = [0; 4 * NB * (NR + 1)];
        expanded_key[0..self.key.len()].copy_from_slice(&self.key);
        let mut progress = self.key.len();
        let mut i = 1; // rcon iteration value
        let mut t: [u8; 4] = [0; 4];
        let n = self.key.len();
        while progress < 4 * NB * (NR + 1) {
            // first four bytes:
            t.clone_from_slice(&expanded_key[progress - 4..progress]);
            self.rotate(&mut t);
            for j in 0..t.len() {
                t[j] = S[t[j] as usize];
            }
            t[0] ^= RCON[i];
            i += 1;
            let res = t.xor(&expanded_key[progress - n..progress - n + 4]);
            for item in res.iter().take(4) {
                expanded_key[progress] = *item;
                progress += 1;
            }

            // Next twelve bytes:
            for _ in 0..3 {
                t.clone_from_slice(&expanded_key[progress - 4..progress]);
                let res = t.xor(&expanded_key[progress - n..progress - n + 4]);
                for item in res.iter().take(4) {
                    expanded_key[progress] = *item;
                    progress += 1;
                }
            }
            // Next four bytes if the key is 256 bits long
            if n * 8 == 256 {
                // https://en.wikipedia.org/wiki/Rijndael_key_schedule#Key_schedule_description
                unimplemented!()
            }

            // Next 8 (12) bytes if the key is 192 (256) bits long
            if n * 8 != 128 {
                unimplemented!()
            }
        }
        expanded_key
    }

    // TODO: Use u128 instead of [u8; 16]?
    fn cipher(&self, input: &[u8; 4 * NB], w: &[u8; 4 * 4 * (NR + 1)]) -> [u8; 4 * NB] {
        let mut state: [u8; 4 * NB] = *input;
        self.add_round_key(&mut state, &w[0..NB * 4]);
        for round in 1..NR {
            self.sub_bytes(&mut state);
            self.shift_rows(&mut state);
            self.mix_columns(&mut state);
            self.add_round_key(&mut state, &w[round * NB * 4..(round + 1) * NB * 4]);
        }
        self.sub_bytes(&mut state);
        self.shift_rows(&mut state);
        self.add_round_key(&mut state, &w[NR * NB * 4..(NR + 1) * NB * 4]);
        state
    }

    fn inv_cipher(&self, input: &[u8; 4 * NB], w: &[u8; 4 * 4 * (NR + 1)]) -> [u8; 4 * NB] {
        let mut state: [u8; 4 * NB] = *input;
        self.add_round_key(&mut state, &w[NR * NB * 4..(NR + 1) * NB * 4]);
        for r in 0..NR - 1 {
            let round = NR - 1 - r;
            self.inv_shift_rows(&mut state);
            self.inv_sub_bytes(&mut state);
            self.add_round_key(&mut state, &w[round * NB * 4..(round + 1) * NB * 4]);
            self.inv_mix_columns(&mut state);
        }
        self.inv_shift_rows(&mut state);
        self.inv_sub_bytes(&mut state);
        self.add_round_key(&mut state, &w[0..NB * 4]);
        state
    }
}



#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use crate::utils::to_byte_vec::ToByteVec;

    use super::*;

    #[test]
    fn test_shift() {
        let mut state = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let expected: [u8; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
        let aes = AES::default();
        aes.shift_rows(&mut state);
        assert_eq!(expected, state);
    }

    #[test]
    fn test_encrypt_ecb() {
        let aes = AES::default()
            .with_key("YELLOW SUBMARINE".as_bytes().try_into().unwrap())
            .with_data("YELLOW SUBMARINE".as_bytes().to_vec());
        assert_eq!(
            "0apPZXiSZUL7tt2HbNIFCGD6NnB+RfSZ26DyW5IjAaU=",
            base64::encode(aes.encrypt_ecb())
        )
    }

    #[test]
    fn test_key_expansion() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let aes = AES::default().with_key(key);
        let expanded = aes.expand_key();
        //println!("{:x?}", expanded);
        assert_eq!(
            "a0fafe1788542cb123a339392a6c7605f2c295f27a96b943"
                .to_byte_vec()
                .unwrap(),
            expanded[4 * 4..10 * 4]
        );
        assert_eq!(
            "19fadc2128d12941575c006ed014f9a8c9ee2589e13f0cc8b6630ca6"
                .to_byte_vec()
                .unwrap(),
            expanded[37 * 4..]
        );
    }

    #[test]
    fn test_sub_bytes() {
        let mut input = vec![0x53];
        let aes = AES::default();
        aes.sub_bytes(&mut input);
        assert_eq!(vec![0xed], input);
    }

    #[test]
    fn test_decrypt() {

        let aes = AES::default()
            .with_key("YELLOW SUBMARINE".as_bytes().try_into().unwrap())
            .with_data(base64::decode("0apPZXiSZUL7tt2HbNIFCGD6NnB+RfSZ26DyW5IjAaU=").unwrap().to_vec());
        assert_eq!(
            "YELLOW SUBMARINE".as_bytes(),
            aes.decrypt_ecb().unwrap()
        );
    }

    #[test]
    fn test_challenge_7() {
        let ciphertext = base64::decode(
            std::fs::read_to_string("resources/set1challenge7.txt")
                .unwrap()
                .trim()
                .replace("\n", ""),
        )
        .unwrap();
        let aes = AES::default().with_data(ciphertext).with_key("YELLOW SUBMARINE".as_bytes().try_into().unwrap());
        println!(
            "{}",
            String::from_utf8(aes.decrypt_ecb().unwrap()).unwrap()
        );
    }
}
