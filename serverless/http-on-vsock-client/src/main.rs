use clap::Parser;
use http_on_vsock_client::vsock_client::vsock_connector;
use hyper::{body::Body, Request, Uri};
use serde_json::json;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// url to query
    #[clap(short, long, value_parser)]
    url: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // WARN: Had to do Box::pin to get it to work, vsock_connector is not Unpin for some reason
    let connector = tower::service_fn(|dst: Uri| Box::pin(vsock_connector(dst)));

    let client = hyper::Client::builder().build::<_, Body>(connector);

    let mut resp = client.get(cli.url.clone().try_into()?).await?;
    println!("{:?}", resp);

    // prepare the post request
    let body = json!({
        "owner_address_hex": "0x35304262b9E87C00c430149f28dD154995d01206"
    }).to_string();
    let request = Request::post(cli.url.clone()+"immutable-config")
        .header("Content-Type", "application/json")
        .body(Body::from(body))?;
    resp = client.request(request).await?;
    println!("{:?}", resp);
    println!("{:?}", String::from_utf8(hyper::body::to_bytes(resp.into_body()).await?.to_vec())?);

    // resp = client.post(cli.url.clone().try_into()?).await?;
    // let response_bytes =
    //     hyper::body::to_bytes(client.get(cli.url.try_into()?).await?.into_body()).await?;

    // let res = String::from_utf8(response_bytes.to_vec())?;

    // println!("{res}");

    Ok(())
}
