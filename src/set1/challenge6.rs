use std::collections::HashMap;

use crate::utils::byte_slice_utils::XOR;

use super::challenge3;

fn decrypt_caesar_cipher(input: &[u8]) -> Vec<u8> {
    let keylength = get_probable_key_length(&input);
    break_vigenere_cipher(&input, keylength)
}

fn get_probable_key_length(input: &[u8]) -> usize {
    let mut scores: HashMap<usize, f64> = HashMap::new();
    for keysize in 2..=40 {
        let mut distances_in_keysize = Vec::with_capacity(3);
        for i in 1..4 {
            let first = &input[keysize * (i - 1)..keysize * i + 1];
            let other = &input[keysize * i..keysize * (i + 1) + 1];
            distances_in_keysize.push(first.edit_distance(other));
        }
        let avg: f64 =
            distances_in_keysize.iter().sum::<usize>() as f64 / distances_in_keysize.len() as f64;
        scores.insert(keysize, avg / keysize as f64);
    }
    let min = scores
        .iter()
        .min_by(|a, b| a.1.partial_cmp(b.1).unwrap())
        .unwrap();
    *min.0
}

fn break_vigenere_cipher(input: &[u8], keylength: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(keylength);
    for i in 0..keylength {
        let transposed: Vec<u8> = input.iter().skip(i).step_by(keylength).copied().collect();
        key.push(challenge3::find_single_byte_key(&transposed));
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test() {
        let input = std::fs::read_to_string("resources/set1challenge6.txt")
            .unwrap()
            .replace("\n", "");
        let input = base64::decode(input).unwrap();
        let key = decrypt_caesar_cipher(&input);
        println!("{}", std::str::from_utf8(&key).unwrap());
        println!("{}", String::from_utf8(input.xor(&key)).unwrap());
    }
}
