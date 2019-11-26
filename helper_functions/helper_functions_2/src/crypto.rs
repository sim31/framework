use bls::{
    AggregatePublicKey, AggregateSignature, PublicKey, PublicKeyBytes, Signature, SignatureBytes,
};

use ring::digest::{digest, SHA256};
use ssz::DecodeError;
use std::convert::TryInto;

pub fn hash(input: &[u8]) -> Vec<u8> {
    digest(&SHA256, input).as_ref().into()
}

pub fn bls_verify(
    pubkey: &PublicKeyBytes,
    message: &[u8],
    signature: &SignatureBytes,
    domain: u64,
) -> Result<bool, DecodeError> {
    let pk: PublicKey = pubkey.try_into()?;
    let sg: Signature = signature.try_into()?;

    Ok(sg.verify(message, domain, &pk))
}

pub fn bls_verify_multiple(
    pubkeys: &[&PublicKeyBytes],
    messages: &[&[u8]],
    signature: &SignatureBytes,
    domain: u64,
) -> Result<bool, DecodeError> {
    let sg = AggregateSignature::from_bytes(signature.as_bytes().as_slice())?;

    let mut pks: Vec<AggregatePublicKey> = Vec::new();
    for pk_bytes in pubkeys {
        let pk = AggregatePublicKey::from_bytes(pk_bytes.as_bytes().as_slice())?;
        pks.push(pk);
    }

    Ok(sg.verify_multiple(messages, domain, &pks.iter().collect::<Vec<_>>()))
}

pub fn bls_aggregate_pubkeys(pubkeys: &[PublicKey]) -> AggregatePublicKey {
    let mut aggr_pk = AggregatePublicKey::new();
    for pk in pubkeys {
        aggr_pk.add(pk);
    }
    aggr_pk
}
// ssz funkcijos

#[cfg(test)]
mod tests {
    use super::*;
    use bls::SecretKey;
    use rustc_hex::FromHex;

    #[test]
    fn test_hash() {
        let input: Vec<u8> = b"Hello World!!!".as_ref().into();

        let output = hash(&input);
        let expected_hex = "073F7397B078DCA7EFC7F9DC05B528AF1AFBF415D3CAA8A5041D1A4E5369E0B3";
        let expected: Vec<u8> = expected_hex
            .from_hex()
            .expect("Invalid hex string constant");
        assert_eq!(expected, output);
    }

    #[test]
    fn test_bls_verify_simple() {
        let sk_bytes: [u8; 48] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 252, 122, 126, 32, 0, 75, 89, 252,
            31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194, 233, 117, 181, 75, 96, 238, 79, 100,
            237, 59, 140, 111,
        ];

        // Load some keys from a serialized secret key.
        let sk = SecretKey::from_bytes(&sk_bytes).expect("Expected success");
        let pk = PublicKey::from_secret_key(&sk);
        let domain: u64 = 0;

        // Sign a message
        let message = b"cats";
        let signature = Signature::new(message, domain, &sk);
        assert!(signature.verify(message, domain, &pk));

        let pk_bytes =
            PublicKeyBytes::from_bytes(pk.as_bytes().as_slice()).expect("Expected success");
        let sg_bytes =
            SignatureBytes::from_bytes(signature.as_bytes().as_slice()).expect("Expected sucess");

        assert_eq!(bls_verify(&pk_bytes, message, &sg_bytes, domain), Ok(true));
    }

    #[test]
    fn test_bls_verify_fail() {
        let sk_bytes: [u8; 48] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 252, 122, 126, 32, 0, 75, 89, 252,
            31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194, 233, 117, 181, 75, 96, 238, 79, 100,
            237, 59, 140, 111,
        ];

        // Load some keys from a serialized secret key.
        let sk = SecretKey::from_bytes(&sk_bytes).expect("Expected success");
        let pk = PublicKey::from_secret_key(&sk);
        let domain: u64 = 0;

        // Sign a message
        let message = b"cats";
        let signature = Signature::new(message, domain, &sk);
        // Different domain
        assert!(!signature.verify(message, 1, &pk));

        let pk_bytes =
            PublicKeyBytes::from_bytes(pk.as_bytes().as_slice()).expect("Expected success");
        let sg_bytes =
            SignatureBytes::from_bytes(signature.as_bytes().as_slice()).expect("Expected sucess");

        // Different domain
        assert_eq!(bls_verify(&pk_bytes, message, &sg_bytes, 1), Ok(false));
    }

    #[test]
    fn test_bls_verify_invalid_pubkey() {
        // Create a valid signature first
        let sk_bytes: [u8; 48] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 252, 122, 126, 32, 0, 75, 89, 252,
            31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194, 233, 117, 181, 75, 96, 238, 79, 100,
            237, 59, 140, 111,
        ];
        // Load some keys from a serialized secret key.
        let sk = SecretKey::from_bytes(&sk_bytes).expect("Expected success");
        let domain: u64 = 0;
        // Sign a message
        let message = b"cats";
        let signature = Signature::new(message, domain, &sk);

        let pk_bytes = PublicKeyBytes::from_bytes(&[0; 48]).expect("Expected success");
        let sg_bytes =
            SignatureBytes::from_bytes(signature.as_bytes().as_slice()).expect("Expected success");

        // Different domain
        let err = DecodeError::BytesInvalid(format!("Invalid PublicKey bytes: {:?}", pk_bytes));
        assert_eq!(bls_verify(&pk_bytes, message, &sg_bytes, 1), Err(err));
    }

    #[test]
    fn test_bls_verify_invalid_sig() {
        // Create a valid public key first
        let sk_bytes: [u8; 48] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 78, 252, 122, 126, 32, 0, 75, 89, 252,
            31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194, 233, 117, 181, 75, 96, 238, 79, 100,
            237, 59, 140, 111,
        ];
        // Load some keys from a serialized secret key.
        let sk = SecretKey::from_bytes(&sk_bytes).expect("Expected success");
        let pk = PublicKey::from_secret_key(&sk);

        let pk_bytes =
            PublicKeyBytes::from_bytes(pk.as_bytes().as_slice()).expect("Expected success");
        let sg_bytes = SignatureBytes::from_bytes(&[1; 96]).expect("Expected success");

        // Different domain
        let err = DecodeError::BytesInvalid(format!("Invalid Signature bytes: {:?}", sg_bytes));
        assert_eq!(bls_verify(&pk_bytes, b"aaabbb", &sg_bytes, 1), Err(err));
    }
}
