use hmac::Hmac;
use hmac::Mac;
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
