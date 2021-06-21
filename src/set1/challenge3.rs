use crate::utils::byte_slice_utils::XOR;

pub fn find_single_byte_key(input: &[u8]) -> u8 {
    let mut best_key = 0;
    let mut best_score = 0;
    for i in 0..=0xff {
        let cleartext = input.xor(&[i]);
        if std::str::from_utf8(&cleartext).is_ok() {
            let score = score_text(&cleartext);
            if score >= best_score {
                best_score = score;
                best_key = i;
            }
        }
    }
    best_key
}

pub fn score_text(input: &[u8]) -> usize {
    let mut score = 0;
    for &c in input {
        if (65..=90).contains(&c) {
            score += 5;
        }
        if (97..=122).contains(&c) {
            score += 5;
        }
        if c == 32 {
            score += 5;
        }
        if c == 44 || c == 46 || c == 58 || c == 59 || c == 39 {
            score += 2;
        }
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{to_byte_vec::ToByteVec};
    #[test]
    fn test_challenge3() {
        let byte_vec = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
            .to_byte_vec()
            .unwrap();
        let key = find_single_byte_key(&byte_vec);
        println!("{}: {}", key, String::from_utf8(byte_vec.xor(&vec![key])).unwrap());
    }

    #[test]
    fn test_examples() {
        let cleartext = "Imagine there's no people, it's easy if you try.".as_bytes();
        assert_eq!(5, find_single_byte_key(&cleartext.xor(&vec![5])));
        assert_eq!(127, find_single_byte_key(&cleartext.xor(&vec![127])));
        assert_eq!(234, find_single_byte_key(&cleartext.xor(&vec![234])));
    }
}
