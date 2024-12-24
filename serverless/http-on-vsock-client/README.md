![Marlin Oyster Logo](./logo.svg)

# HTTP Over Vsock Client
This application serves as a client for HTTP over vsock connections with the Oyster enclave, which runs the server. It
enables operators of Oyster to communicate securely over vsock, providing the same functionality as HTTP.

## Build

```bash
cargo build --release
```

### Reproducible builds
Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used
to trigger builds:

```bash
nix build -v .#<flavor>.serverless.http-on-vsock-client.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## Usage

```bash
$ ./http-on-vsock-client --help
Usage: http-on-vsock-client --url <URL> --owner-address <OWNER_ADDRESS> --gas-key <GAS_KEY>

Options:
  -u, --url <URL>                      url to query
  -o, --owner-address <OWNER_ADDRESS>  
  -g, --gas-key <GAS_KEY>              
  -h, --help                           Print help
  -V, --version                        Print version
```

## Example

```bash
$ ./http-on-vsock-client --url vsock://88:6000/ --owner-address <OWNER_ADDRESS> --gas-key <GAS_KEY>
```
## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
