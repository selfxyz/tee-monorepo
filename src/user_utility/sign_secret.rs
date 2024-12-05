use std::fs;

use alloy::dyn_abi::DynSolValue;
use alloy::hex;
use alloy::primitives::{keccak256, U256};
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::k256::elliptic_curve::generic_array::sequence::Lengthen;
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ecies::encrypt;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    // Secret ID of the secret to encrpyt and sign
    #[clap(long, value_parser)]
    secret_id: U256,

    // Serialized secret data
    #[clap(long, value_parser)]
    secret_data_hex: String,

    // File location of the enclave public key (used to encrypt the data)
    #[clap(long, value_parser, default_value = "./id.pub")]
    enclave_public_file: String,

    // User's private key to sign the data
    #[clap(long, value_parser)]
    user_private_hex: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let secret_data_bytes = hex::decode(cli.secret_data_hex).context("Failed to hex decode the secret data hex string")?;
    println!("Secret data in bytes: {:?}", secret_data_bytes);

    let enclave_public_key =
        fs::read(cli.enclave_public_file).context("Failed to read the enclave public key")?;

    // Encrypt secret data using the enclave 'secp256k1' public key
    let encrypted_secret_data_bytes = encrypt(&enclave_public_key, secret_data_bytes.as_slice());
    let Ok(encrypted_secret_data_bytes) = encrypted_secret_data_bytes else {
        return Err(anyhow!(
            "Failed to encrypt the secret data using enclave public key: {:?}",
            encrypted_secret_data_bytes.unwrap_err()
        ));
    };

    let user_private_key = SigningKey::from_slice(
        hex::decode(
            cli.user_private_hex
                .strip_prefix("0x")
                .unwrap_or(&cli.user_private_hex),
        )
        .context("Failed to decode the user private key hex")?
        .as_slice(),
    )
    .context("Invalid user signer key")?;

    let token_list = DynSolValue::Tuple(vec![
        DynSolValue::Uint(cli.secret_id, 256),
        DynSolValue::Bytes(encrypted_secret_data_bytes.clone()),
    ]);

    let data_hash = keccak256(token_list.abi_encode());

    // Sign the digest using user private key
    let (rs, v) = user_private_key
        .sign_prehash_recoverable(&data_hash.to_vec())
        .context("Failed to sign the secret data message using user private key")?;
    let signature = rs.to_bytes().append(27 + v.to_byte()).to_vec();

    println!(
        "Secret ID: {}\nEncrypted secret: {}\nSignature: {}",
        cli.secret_id,
        hex::encode(encrypted_secret_data_bytes),
        hex::encode(signature)
    );

    Ok(())
}
