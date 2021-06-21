use thiserror::Error;

#[derive(Error, Debug)]
pub enum ByteUtilsError {
    #[error("Empty slice")]
    EmptySlice,
    #[error("Invalid PKCS#7 padding. Padding byte {pad_byte} does not occur {pad_byte} times")]
    InvalidPadding {
        pad_byte: u8
    },
    #[error("Input shorter than padding byte {0}")]
    TooShortInput(u8)
}

pub trait XOR {
    fn xor(&self, other: &[u8]) -> Vec<u8>;
    fn edit_distance(&self, other: &[u8]) -> usize;
    fn pkcs7_pad(&self, blocklength: usize) -> Vec<u8>;
    fn pkcs7_unpad(&self) -> Result<Vec<u8>, ByteUtilsError>;
}

impl XOR for [u8] {
    fn xor(&self, other: &[u8]) -> Vec<u8> {
        self.iter().zip(other.iter().cycle()).map(|(x,y)| x ^ y ).collect()
    }

    fn edit_distance(&self, other: &[u8]) -> usize {
        self.xor(other).iter().map(|x| x.count_ones() as usize).sum()
    }

    fn pkcs7_pad(&self, blocklength: usize) -> Vec<u8> {
       //let mut new_length = blocklength;
        let new_length = match self.len().cmp(&blocklength) {
            std::cmp::Ordering::Equal => 2 * blocklength,
            std::cmp::Ordering::Less => blocklength,
            std::cmp::Ordering::Greater => {
                (self.len() as f64 / blocklength as f64).ceil() as usize * blocklength
            }
        };
        let mut out = self.to_vec();
        let pad = (new_length - self.len()) as u8;
        for _ in self.len()..new_length {
            out.push(pad);
        }
        out
    }

    fn pkcs7_unpad(&self) -> Result<Vec<u8>, ByteUtilsError> {
        match self.last() {
            None => Err(ByteUtilsError::EmptySlice),
            Some(&last) => {
                if last as usize > self.len() {
                    return Err(ByteUtilsError::TooShortInput(last));
                }
               if self.iter().rev().take(last as usize).any(|&x| x != last) {
                    return Err(ByteUtilsError::InvalidPadding{pad_byte: last});
                }
                Ok(self[0..self.len() - last as usize].to_vec())
            }
        }
    }
}



#[cfg(test)]
mod tests {
    use crate::utils::to_byte_vec::ToByteVec;
    use super::*;
    #[test]
    fn test_repeating_key() {
        let byte_vec = "1c0111001f010100061a024b53535009181c".to_byte_vec().unwrap();
        let key = vec![0xff];
        assert_eq!(byte_vec, byte_vec.xor(&key).xor(&key));
    }

    #[test]
    fn test_edit_distance() {
        assert_eq!(37, "this is a test".as_bytes().edit_distance("wokka wokka!!!".as_bytes()));
    }

    #[test]
    fn test_unpad() {
        let mut pad = vec![0x10u8; 16];
        let mut input: Vec<u8> = "YELLOW SUBMARINE".as_bytes().iter().cloned().collect();
        input.append(&mut pad);
        assert_eq!("YELLOW SUBMARINE".as_bytes(), &input.pkcs7_unpad().unwrap());
    }

    #[test]
    fn test_broken_unpad() {
        let mut pad = vec![0x11u8; 16];
        let mut input: Vec<u8> = "YELLOW SUBMARINE".as_bytes().iter().cloned().collect();
        input.append(&mut pad);
        match &input.pkcs7_unpad() {
            Ok(_) => todo!(),
            Err(e) => println!("{}", e),
        }
        assert!(&input.pkcs7_unpad().is_err());
    }

    #[test]
    fn test_pkcs7_pad() {
        let input = "YELLOW SUBMARINE".as_bytes();
        let mut expected = [16; 32];
        expected[0..16].copy_from_slice(input);
        assert_eq!(expected.to_vec(), input.pkcs7_pad(16));
    }
}
