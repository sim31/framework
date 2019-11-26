use crate::error::Error;
use std::convert::TryInto;

// inteface has changed
pub fn xor_str(bytes_1: &str, bytes_2: &str) -> String {
    if bytes_1.chars().count() != 32 && bytes_2.chars().count() != 32 {
        panic!("One of the input arguments is too short to be a sha256 hash.");
    }
    if bytes_1.len() != 32 || bytes_2.len() != 32 {
        panic!("Illegal characters in one of the input strings");
    }
    let mut string_to_return = String::new();
    let bytes_1_as_bytes = bytes_1.as_bytes();
    let bytes_2_as_bytes = bytes_2.as_bytes();
    for i in 0..32 {
        if bytes_1_as_bytes[i] == bytes_2_as_bytes[i] {
            string_to_return += "1";
        } else {
            string_to_return += "0";
        }
    }
    string_to_return
}

// [u8; 32] -> Vec<u8>
pub fn xor(bytes_1: &[u8], bytes_2: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes_1.len() != 32 || bytes_2.len() != 32 {
        return Err(Error::NotAHash);
    }
    let mut vec_to_return: Vec<u8> = Vec::new();
    for i in 0..32 {
        if bytes_1[i] == bytes_2[i] {
            vec_to_return.push(0);
        } else {
            vec_to_return.push(1);
        }
    }
    Ok(vec_to_return)
}

pub fn integer_squareroot(n: u64) -> u64 {
    /*
    let sqrt = (n as f64).sqrt();
    let mut sqrt_floor = sqrt as u64;
    if (sqrt_floor + 1) * (sqrt_floor + 1) <= n {
        sqrt_floor += 1;
    }
    sqrt_floor
     */
    let mut x = 1;
    loop {
        if (x + 1) ^ 2 > n {
            return x;
        }
        x += 1;
    }
}

pub fn int_to_bytes(n: u64, length: usize) -> Result<Vec<u8>, Error> {
    let mut capacity = 1;
    for _i in 0..length - 1 {
        capacity *= 256;
    }
    capacity = capacity - 1 + 255 * capacity;
    if n > capacity {
        return Err(Error::NumberExceedsCapacity);
    }
    let mut rez_vec: Vec<u8> = Vec::with_capacity(length);
    let mut num = n;
    for _i in 0..length {
        rez_vec.push((num % 256).try_into().expect(""));
        num /= 256;
    }
    rez_vec.reverse();
    Ok(rez_vec)
}

pub fn bytes_to_int(bytes: &[u8]) -> Result<u64, Error> {
    // TODO: handle error
    let length = bytes.len();
    let mut nums: Vec<u8> = bytes.to_vec();
    nums.reverse();
    let mut result: u64 = 0;
    let mut mult = 1;
    let mut i = 0;
    let iter = nums.iter().take(length);
    for j in iter {
        result += mult * (u64::from(*j));
        if i < length - 1 {
            mult *= 256;
            i += 1;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_str() {
        let test_str_1: &str = "A4x3A4x3A4x3A4x3A4x3A4x3A4x3A4x3";
        let mut test_str_2: &str = "A4x3A4x3A4x3A4x3A4x3A4x3A4x3A4x3";
        assert_eq!(
            xor_str(test_str_1, test_str_2),
            "11111111111111111111111111111111",
        );
        test_str_2 = "AAAABBBBCCCCDDDDAAAABBBBCCCCDDDD";
        assert_eq!(
            xor_str(test_str_1, test_str_2),
            "10000000000000001000000000000000",
        );
        assert_ne!(
            xor_str(test_str_1, test_str_2),
            "11000000000000001000000000000000",
        );
    }
    #[test]
    #[should_panic]
    fn test_too_short_hashes() {
        let test_str_1: &str = "ABC";
        let test_str_2: &str = "ABC";
        assert_eq!(xor_str(test_str_1, test_str_2), "111");
    }
    #[test]
    #[should_panic]
    fn test_invalid_symbols_in_hashes() {
        let test_str_1: &str = "\u{104}\u{104}\u{104}\u{104}\u{118}\u{118}\u{118}\u{118}\u{12e}\u{12e}\u{12e}\u{12e}\u{160}\u{160}\u{160}\u{160}\u{104}\u{104}\u{104}\u{104}\u{118}\u{118}\u{118}\u{118}\u{12e}\u{12e}\u{12e}\u{12e}\u{160}\u{160}\u{160}\u{160}";
        let test_str_2: &str = "\u{104}\u{104}\u{104}\u{104}\u{118}\u{118}\u{118}\u{118}\u{12e}\u{12e}\u{12e}\u{12e}\u{160}\u{160}\u{160}\u{160}\u{104}\u{104}\u{104}\u{104}\u{118}\u{118}\u{118}\u{118}\u{12e}\u{12e}\u{12e}\u{12e}\u{160}\u{160}\u{160}\u{160}";
        assert_eq!(
            xor_str(test_str_1, test_str_2),
            "11111111111111111111111111111111",
        );
    }

    #[test]
    fn test_xor() {
        let expected_vec: Vec<u8> = vec![
            0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0,
            0, 1, 1,
        ];
        let vec_1: Vec<u8> = vec![
            255, 255, 1, 2, 254, 254, 3, 4, 253, 253, 5, 6, 252, 252, 7, 8, 251, 251, 9, 10, 250,
            250, 11, 12, 249, 249, 13, 14, 248, 248, 15, 16,
        ];
        let vec_2: Vec<u8> = vec![
            255, 255, 10, 20, 254, 254, 30, 40, 253, 253, 50, 60, 252, 252, 70, 80, 251, 251, 90,
            100, 250, 250, 110, 120, 249, 249, 130, 140, 248, 248, 150, 160,
        ];
        assert_eq!(
            expected_vec,
            xor(vec_1.as_slice(), vec_2.as_slice()).expect("")
        );
    }

    #[test]
    fn test_int_to_bytes() {
        let test_vec: Vec<u8> = vec![0, 2, 2];
        let vec_from_func: Vec<u8> = int_to_bytes(514, 3).expect("");
        assert_eq!(test_vec, vec_from_func);
    }

    #[test]
    #[should_panic]
    fn test_int_to_bytes_overflow() {
        let _vec_from_func: Vec<u8> = int_to_bytes(256, 1).expect("");
    }

    #[test]
    fn test_bytes_to_int() {
        let num: u64 = bytes_to_int(&[1, 1]).expect("");
        assert_eq!(num, 257);
    }
}
