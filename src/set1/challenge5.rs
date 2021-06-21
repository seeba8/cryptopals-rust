#[cfg(test)]
mod tests {
    use crate::utils::{byte_slice_utils::XOR, to_hex_string::ToHexString};
    #[test]
    fn test_repeating_key_xor() {
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        assert_eq!(expected, input.as_bytes().xor("ICE".as_bytes()).to_hex_string()) ;  
    }
}