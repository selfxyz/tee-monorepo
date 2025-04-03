use std::time::{SystemTime, UNIX_EPOCH};

use oyster::{
    attestation::{self, AttestationExpectations, AWS_ROOT_KEY},
    scallop::{Key, ScallopAuthStore},
};

#[derive(Clone, Default)]
pub struct AuthStore {}

pub type AuthStoreState = ([[u8; 48]; 3], Box<[u8]>);

impl ScallopAuthStore for AuthStore {
    type State = AuthStoreState;

    fn verify(&mut self, attestation: &[u8], key: Key) -> Option<Self::State> {
        let Ok(now) = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|x| x.as_millis() as usize)
        else {
            return None;
        };

        let Ok(decoded) = attestation::verify(
            attestation,
            AttestationExpectations {
                // TODO: hardcoded, make it a param
                age: Some((300000, now)),
                root_public_key: Some(&AWS_ROOT_KEY),
                public_key: Some(&key),
                // do not care about PCRs or user data
                // will derive different keys for each set
                ..Default::default()
            },
        ) else {
            return None;
        };

        if decoded.user_data.len() > 65535 {
            return None;
        }

        return Some((decoded.pcrs, decoded.user_data));
    }
}
