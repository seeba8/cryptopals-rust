pub trait ToHexString {
    /// Converts a string representation of bytes into a byte vec
    fn to_hex_string(&self) -> String;
}

impl ToHexString for [u8] {
    fn to_hex_string(&self) -> String {
        self.iter().map(|x| format!("{:02x}", x)).collect()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_str() {
        let x = vec![0x12u8, 0x3d, 0xef];
        assert_eq!("123def", &x.to_hex_string());
    }
}