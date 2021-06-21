pub trait ToByteVec {
    /// Converts a string representation of bytes into a byte vec
    fn to_byte_vec(&self) -> Option<Vec<u8>>;
}

impl ToByteVec for &str {
    fn to_byte_vec(&self) -> Option<Vec<u8>> {
        let mut result: Vec<u8> = Vec::with_capacity(self.len() / 2);
        for i in (0..self.len()).step_by(2) {
            result.push(u8::from_str_radix(&self[i..i + 2], 16).ok()?);
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_from_byte_str() {
        assert_eq!("123def".to_byte_vec().unwrap(), &[0x12, 0x3d, 0xef]);
    }
}
