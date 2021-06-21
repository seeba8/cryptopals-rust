#[cfg(test)]
mod tests {
    use crate::{
        set1::challenge3,
        utils::{byte_slice_utils::XOR, to_byte_vec::ToByteVec},
    };

    #[test]
    fn find_single_character_xor_cipherstring() {
        let lines = std::fs::read_to_string("resources/set1challenge4.txt").unwrap();
        let mut best_score = 0;
        let mut best_line = None;
        for line in lines.lines() {
            let line = line.to_byte_vec().unwrap();
            let key = challenge3::find_single_byte_key(&line);
            let score = challenge3::score_text(&line.xor(&vec![key]));
            if score > best_score {
                if let Ok(clear) = String::from_utf8(line.xor(&vec![key])) {
                    best_score = score;
                    best_line = Some(clear);
                }
                   
            }
            
        }
        println!("{}", best_line.unwrap_or(String::new()));
    }
}
