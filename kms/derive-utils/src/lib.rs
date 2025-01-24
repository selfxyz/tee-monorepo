use hmac::Hmac;
use hmac::Mac;
use sha2::Sha512;

pub fn derive_enclave_seed(
    root: &[u8],
    pcr0: &[u8],
    pcr1: &[u8],
    pcr2: &[u8],
    user_data: &[u8],
) -> Option<[u8; 64]> {
    let mut mac = Hmac::<Sha512>::new_from_slice(root).ok()?;
    mac.update(&pcr0);
    mac.update(&pcr1);
    mac.update(&pcr2);
    mac.update(&(user_data.len() as u16).to_be_bytes());
    mac.update(&user_data);

    Some(mac.finalize().into_bytes().into())
}
