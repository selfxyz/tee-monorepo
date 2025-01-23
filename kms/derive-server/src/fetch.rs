use anyhow::Result;

use crate::scallop::{AuthStore, Auther};

pub async fn fetch_randomness(
    auther: Auther,
    auth_store: AuthStore,
    secret: [u8; 32],
) -> Result<[u8; 64]> {
    todo!()
}
