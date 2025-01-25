use hmac::Hmac;
use hmac::Mac;
use k256::SecretKey;
use ruint::aliases::U256;
use ruint::uint;
use sha2::Sha512;

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
