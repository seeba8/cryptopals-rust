

#[cfg(test)]
mod tests {
    use crate::utils::{to_byte_vec::ToByteVec, to_hex_string::ToHexString};
    use crate::utils::byte_slice_utils::XOR;

    #[test]
    fn test() {
        let byte_vec = "1c0111001f010100061a024b53535009181c".to_byte_vec().unwrap();
        let key = "686974207468652062756c6c277320657965".to_byte_vec().unwrap();
        assert_eq!("746865206b696420646f6e277420706c6179", byte_vec.xor(&key).to_hex_string());

    }
}