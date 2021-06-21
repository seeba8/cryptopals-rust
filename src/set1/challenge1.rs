use base64::encode;
use crate::utils::to_byte_vec::{ToByteVec};
fn hex_to_base64(input: &str) -> Option<String> {
    Some(encode(input.to_byte_vec().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_string() {
        println!("{}", String::from_utf8("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_byte_vec().unwrap()).unwrap());
    }

    #[test]
    fn test_hex_to_base64() {
        assert_eq!(hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap(), 
                "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    }
}
