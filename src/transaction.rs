use alloy::primitives::{Address, Bytes, FixedBytes, Token, I8, U256};
use alloy::providers::Provider;
use std::error::Error;

fn convert_params_to_tokens(params: Vec<(&str, &dyn std::any::Any)>) -> Vec<Token> {
    params
        .into_iter()
        .map(|(type_name, value)| match type_name {
            "Address" => Token::Address(*value.downcast_ref::<Address>().unwrap()),
            "FixedBytes" => {
                Token::FixedBytes(value.downcast_ref::<FixedBytes<32>>().unwrap().clone())
            }
            "Bytes" => Token::Bytes(value.downcast_ref::<Bytes>().unwrap().clone()),
            "Int" => Token::Int(*value.downcast_ref::<I8>().unwrap()),
            "Uint" => Token::Uint(*value.downcast_ref::<U256>().unwrap()),
            "Bool" => Token::Bool(*value.downcast_ref::<bool>().unwrap()),
            "String" => Token::String(value.downcast_ref::<String>().unwrap().clone()),
            "FixedArray" => Token::FixedArray(value.downcast_ref::<Vec<Token>>().unwrap().clone()),
            "Array" => Token::Array(value.downcast_ref::<Vec<Token>>().unwrap().clone()),
            "Tuple" => Token::Tuple(value.downcast_ref::<Vec<Token>>().unwrap().clone()),
            _ => panic!("Unsupported type"),
        })
        .collect()
}

pub async fn call_contract_function(
    contract: &Contract<Provider<Http>>,
    function_name: &str,
    params: Vec<(&str, &dyn std::any::Any)>,
) -> Result<(), Box<dyn Error>> {
    // Convert parameters to Token types
    let tokens = convert_params_to_tokens(params);

    // Get the method object for the specified function
    let method = contract.method::<_, ()>(function_name, tokens)?;

    for _ in 0..3 {
        let pending_txn = method.send().await;
        if let Err(err) = pending_txn {
            let err_string = format!("{:#?}", err);
            if err_string.contains("code: -32000") && err_string.contains("nonce") {
                // Handle the specific error case
                continue;
            }
        } else {
            // Handle successful transaction
            break;
        }
    }

    Ok(())
}
