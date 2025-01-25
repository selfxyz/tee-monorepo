use hmac::Hmac;
use hmac::Mac;
use k256::SecretKey;
use ruint::aliases::U256;
use ruint::uint;
use sha2::Digest;
use sha2::Sha512;
use sha3::Keccak256;

pub fn derive_enclave_seed(
    root: [u8; 64],
    pcr0: &[u8],
    pcr1: &[u8],
    pcr2: &[u8],
    user_data: &[u8],
) -> Option<[u8; 64]> {
    derive_enclave_seed_once(
        derive_enclave_seed_once(root, pcr0, pcr1, pcr2, user_data)?,
        pcr0,
        pcr1,
        pcr2,
        user_data,
    )
}

pub fn derive_path_seed(root: [u8; 64], path: &[u8]) -> Option<[u8; 64]> {
    derive_path_seed_once(derive_path_seed_once(root, path)?, path)
}

pub fn to_secp256k1_secret(derived: [u8; 64]) -> Option<k256::SecretKey> {
    // throw away last 32 bytes, assumes derived is random
    // unlikely to ever matter, but bound it to [1, n)
    // not perfectly random to mod but too negligible to care
    SecretKey::from_slice(
        &U256::from_be_bytes(derived)
            .reduce_mod(uint!(
                // secp256k1 n - 1
                0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140_U256
            ))
            .wrapping_add(U256::from(1))
            .to_be_bytes::<32>(),
    )
    .ok()
}

pub fn to_secp256k1_public(derived: [u8; 64]) -> Option<k256::PublicKey> {
    let secret = to_secp256k1_secret(derived)?;
    Some(secret.public_key())
}

pub fn to_secp256k1_address(derived: [u8; 64]) -> Option<[u8; 20]> {
    let public = to_secp256k1_public(derived)?;
    Keccak256::new_with_prefix(&public.to_sec1_bytes()[1..]).finalize()[12..]
        .try_into()
        .ok()
}

fn derive_enclave_seed_once(
    root: [u8; 64],
    pcr0: &[u8],
    pcr1: &[u8],
    pcr2: &[u8],
    user_data: &[u8],
) -> Option<[u8; 64]> {
    let mut mac = Hmac::<Sha512>::new_from_slice(&root).ok()?;
    mac.update(&pcr0);
    mac.update(&pcr1);
    mac.update(&pcr2);
    mac.update(&(user_data.len() as u16).to_be_bytes());
    mac.update(&user_data);

    Some(mac.finalize().into_bytes().into())
}

fn derive_path_seed_once(root: [u8; 64], path: &[u8]) -> Option<[u8; 64]> {
    let mut mac = Hmac::<Sha512>::new_from_slice(&root).ok()?;
    mac.update(&path);

    Some(mac.finalize().into_bytes().into())
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::{derive_enclave_seed, derive_path_seed};

    #[test]
    fn test_derive_enclave_seed() {
        let root = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdf2031c4c25b95142cf02844a118bfafa2ad41aceda1191be332eee20b4bacd9be5");
        let pcr0 = hex!("107a6d53ba665ae961bb407bccf8b8bc95fa048e1eb59e012caac30e0ba2d58928ab78c18983e44c9660b01a8abadb91");
        let pcr1 = hex!("c4c764a379f18de9633c69d81173f2ef1510bb84926fab60f77b54885b67d1a9e3c3d716c7991f16dd2c4a8bc4c8eca5");
        let pcr2 = hex!("f0abae3d376be84340d12a9a5f6d989c1f5c56c59d04b41a3b5a72187fcb3d4090dd60229261c04281eb1d8d40c4b328");
        let user_data = hex!("0336b1a0838f0bd3");
        // derived from an independent online implementation
        let expected = hex!("07daa9e8e6917e45658f826b68f925e043d54ae4040ef1bbcc54e9aaf29d72a9c8ab133a8a5ca8b6a86eaf355421a4b4d8c6e125a22a827df3c90d78696d07d7");

        let seed = derive_enclave_seed(root, &pcr0, &pcr1, &pcr2, &user_data);

        assert_eq!(seed, Some(expected));
    }

    #[test]
    fn test_derive_path_seed() {
        let root = hex!("4090382ec7b7a00ee999a8da6f5d85e4159964c9f03448b3e3608e877a49cdf2031c4c25b95142cf02844a118bfafa2ad41aceda1191be332eee20b4bacd9be5");
        let path = hex!("0336b1a0838f0bd3");
        // derived from an independent online implementation
        let expected = hex!("77dd95c3ad1c4aec2370d79ad1cbab5399b0f893e203653c3a60a9a63f0c6f6d309cecab1007c4a893bc5e23180d5de25038420d70c309446c99581844f93fa0");

        let seed = derive_path_seed(root, &path);

        assert_eq!(seed, Some(expected));
    }
}
