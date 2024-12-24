![Marlin Oyster Logo](./logo.svg)

# HTTP Over Vsock Server

A Rust library designed to facilitate secure HTTP communication over vsock connections between an Oyster enclave and
its operator. It is intended for use by Oyster applications as an HTTP server over vsock, with the client residing on
the host of the Oyster.


## Usage

Include following in Cargo.toml of the project:
```
http-on-vsock-server = { git = "https://github.com/marlinprotocol/oyster-monorepo.git", branch = "master" }
```

Build the http server using the `axum`:
```rust
use http_on_vsock_server::VsockServer;

let app = Router::new()
    .route("/", get(|| async { "Hello" }));
axum::Server::builder(VsockServer {
    listener: VsockListener::bind(cid, port)
        .context("failed to create vsock listener")?,
})
.serve(app.into_make_service())
.await
.context("server exited with error")?;
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
