pub use eth2_hashing::hash;

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hex::FromHex;

    #[test]
    fn test_hash() {
        let input: Vec<u8> = b"Hello World!!!".as_ref().into();

        let output = hash(&input);
        let expected_hex = "073F7397B078DCA7EFC7F9DC05B528AF1AFBF415D3CAA8A5041D1A4E5369E0B3";
        let expected: Vec<u8> = expected_hex.from_hex().unwrap();
        assert_eq!(expected, output);
    }

    #[test]
    fn test_hash_fail() {
        let input: Vec<u8> = b"Hello World!!".as_ref().into();

        let output = hash(&input);
        let expected_hex = "073F7397B078DCA7EFC7F9DC05B528AF1AFBF415D3CAA8A5041D1A4E5369E0B3";
        let expected: Vec<u8> = expected_hex.from_hex().unwrap();
        assert_ne!(expected, output);
    }
}