![Marlin Oyster Logo](./logo.svg)

# Attestation Verifier

The attestation verifier verifies attestations provided by the [attestation server](https://github.com/marlinprotocol/oyster-monorepo/tree/master/attestation/server) containing a secp256k1 public key and signs the response using its own secp256k1 key. Intended to be run inside an enclave to provide cheap attestation verification services.

Once the attestation of the verifier is verified on-chain (very expensive), it enables other enclaves, including other verifiers, to get verified by submitting a simple ECDSA signature from the verifier instead (very cheap). The process essentially extends the chain of trust of the attestation verifier enclave instead of trying to verify the full attestation of the other enclave again.

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.attestation.verifier.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## Test

```
cargo test
```

## Usage

```
$ ./target/release/oyster-attestation-verifier --help
Usage: oyster-attestation-verifier --secp256k1-secret <SECP256K1_SECRET> --secp256k1-public <SECP256K1_PUBLIC> --ip <IP> --port <PORT>

Options:
      --secp256k1-secret <SECP256K1_SECRET>
          path to secp256k1 private key file (e.g. /app/secp256k1.sec)
      --secp256k1-public <SECP256K1_PUBLIC>
          path to secp256k1 public key file (e.g. /app/secp256k1.pub)
  -i, --ip <IP>
          server ip (e.g. 127.0.0.1)
  -p, --port <PORT>
          server port (e.g. 1400)
  -h, --help
          Print help
  -V, --version
          Print version
```

## CLI Verification
The attestation verifier also includes a binary to verify an attestation doc locally through the CLI as shown below :- 

```
$ ./target/release/oyster-verify-attestation --help
Usage: oyster-verify-attestation --attestation <ATTESTATION>

Options:
      --attestation <ATTESTATION>  
          path to attestation doc hex string file
  -h, --help                       Print help
  -V, --version                    Print version
```

Above execution will return an error if failing to parse or verify the attestation doc/file. 
If the verification completes successfully, the parsed attestation doc will be printed in below format :- 
```
AttestationDecoded {
    pcrs: [[...], [...], [...]],
    timestamp: '...',
    public_key: [...]
}
```

To generate the attestation hex file, call the corresponding `attestation-server` endpoint inside a running enclave like below:-
```
$ curl <attestation_server_ip:attestation_server_port>/attestation/hex --output attestation.hex
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  8938  100  8938    0     0   126k      0 --:--:-- --:--:-- --:--:--  124k
```

## Endpoints

The attestation verifier exposes two verification endpoints which expect the attestation in one of two formats - raw and hex. The formats match the two endpoints of the [attestation server](https://github.com/marlinprotocol/oyster-attestation-server) and the response of the server can just be sent to the verifier as is.

### Raw

##### Endpoint

`/verify/raw`

##### Example

```
$ curl <attestation_server_ip:attestation_server_port>/attestation/raw -vs | curl -H "Content-Type: application/octet-stream" --data-binary @- <attestation_verifier_ip:attestation_verifier_port>/verify/raw -vs
*   Trying <attestation_server_ip:attestation_server_port>...
* Connected to <attestation_server_ip> (<attestation_server_ip>) port <attestation_server_port> (#0)
> GET /attestation/raw HTTP/1.1
> Host: <attestation_server_ip:attestation_server_port>
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-type: application/octet-stream
< content-length: 4468
< date: Sun, 07 Apr 2024 06:36:44 GMT
< 
{ [2682 bytes data]
* Connection #0 to host <attestation_server_ip> left intact
*   Trying <attestation_verifier_ip:attestation_verifier_port>...
* Connected to <attestation_verifier_ip> (<attestation_verifier_ip>) port <attestation_verifier_port> (#0)
> POST /verify/raw HTTP/1.1
> Host: <attestation_verifier_ip:attestation_verifier_port>
> User-Agent: curl/7.81.0
> Accept: */*
> Content-Type: application/octet-stream
> Content-Length: 4468
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-length: 799
< content-type: application/json
< date: Sun, 07 Apr 2024 06:36:44 GMT
< 
* Connection #0 to host <attestation_verifier_ip> left intact
{"signature":"15383a7af2c33e80eba2637c9e3fb0c246ecedfbb183879f9dc9b18d25635b3871212cfab51db0fd75dded5be870febe19226c92d38425c37689fb7c1e86f74f1c","public_key":"435ed75cf1be0c58b97d372b153ad4e43101895e481e7dd7d27519605e859f34d7b5491586faa887257178bbb6daa1e212f35aa2a60308cd76df5db522abb139","image_id":"3fe8419454c44a36782f2b9a307cad84ee8c226e0351cb0861c50fb6b13a3a3e","timestamp":1738845553218,"verifier_public_key":"60b77877f624b4eaf776a6afef1dd727f969c7557b88b05cc27c51366eafd72a2328b054bd2f6cec47b3b82b61bbfc898b5b32d604446ebf59e50195345a8d98"}
```

### Hex

##### Endpoint

`/attestation/hex`

##### Example

```
$ curl <attestation_server_ip:attestation_server_port>/attestation/hex -vs | curl -H "Content-Type: text/plain" -d @- <attestation_verifier_ip:attestation_verifier_port>/verify/hex -vs
*   Trying <attestation_server_ip:attestation_server_port>...
* Connected to <attestation_server_ip> (<attestation_server_ip>) port <attestation_server_port> (#0)
> GET /attestation/hex HTTP/1.1
> Host: <attestation_server_ip:attestation_server_port>
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-type: text/plain; charset=utf-8
< content-length: 8936
< date: Sun, 07 Apr 2024 06:44:25 GMT
< 
{ [2681 bytes data]
* Connection #0 to host <attestation_server_ip> left intact
*   Trying <attestation_verifier_ip:attestation_verifier_port>...
* Connected to <attestation_verifier_ip> (<attestation_verifier_ip>) port <attestation_verifier_port> (#0)
> POST /verify/hex HTTP/1.1
> Host: <attestation_verifier_ip:attestation_verifier_port>
> User-Agent: curl/7.81.0
> Accept: */*
> Content-Type: text/plain
> Content-Length: 8936
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< content-length: 799
< content-type: application/json
< date: Sun, 07 Apr 2024 06:44:25 GMT
< 
* Connection #0 to host <attestation_verifier_ip> left intact
{"signature":"15383a7af2c33e80eba2637c9e3fb0c246ecedfbb183879f9dc9b18d25635b3871212cfab51db0fd75dded5be870febe19226c92d38425c37689fb7c1e86f74f1c","public_key":"435ed75cf1be0c58b97d372b153ad4e43101895e481e7dd7d27519605e859f34d7b5491586faa887257178bbb6daa1e212f35aa2a60308cd76df5db522abb139","image_id":"3fe8419454c44a36782f2b9a307cad84ee8c226e0351cb0861c50fb6b13a3a3e","timestamp":1738845553218,"verifier_public_key":"60b77877f624b4eaf776a6afef1dd727f969c7557b88b05cc27c51366eafd72a2328b054bd2f6cec47b3b82b61bbfc898b5b32d604446ebf59e50195345a8d98"}
```

## Response format

```json
{
    "signature": "...",
    "public_key": "...",
    "image_id": "...",
    "timestamp": ...,
    "verifier_public_key": "..."
}
```

The verifier responds with JSON with the following fields:
- `signature`: signature provided by the verifier
- `public_key`: public key that was encoded in the attestation
- `image_id`: hash of PCRs and user data encoded in the attestation
- `timestamp`: timestamp that was encoded in the attestation
- `verifier_public_key`: public key of the verifier corresponding to the signature

## Signature format

The verifier creates the signature as per the [EIP-712](https://eips.ethereum.org/EIPS/eip-712) standard.

#### EIP-712 domain

```typescript
struct EIP712Domain {
    string name = "marlin.oyster.AttestationVerifier",
    string version = "1",
}
```

The `chainId`, `verifyingContract` and `salt` fields are omitted because we do not see any significant replay concerns in allowing the signature to be verified on any contract on any chain.

#### Message struct

```typescript
struct Attestation {
    bytes enclavePubKey;
    bytes32 imageId;
    uint256 timestampInMilliseconds;
}
```

## Verification

It is designed to be verified by the following solidity code (taken from the [AttestationVerifier](https://github.com/marlinprotocol/oyster-contracts/blob/master/contracts/AttestationVerifier.sol#L230) contract):

```solidity
bytes32 private constant DOMAIN_SEPARATOR =
    keccak256(
        abi.encode(
            keccak256("EIP712Domain(string name,string version)"),
            keccak256("marlin.oyster.AttestationVerifier"),
            keccak256("1")
        )
    );

bytes32 private constant ATTESTATION_TYPEHASH =
    keccak256("Attestation(bytes enclavePubKey,bytes32 imageId,uint256 timestampInMilliseconds)");

function _verify(bytes memory signature, Attestation memory attestation) internal view {
    bytes32 hashStruct = keccak256(
        abi.encode(
            ATTESTATION_TYPEHASH,
            keccak256(attestation.enclavePubKey),
            attestation.imageId,
            attestation.timestampInMilliseconds
        )
    );
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

    address signer = ECDSA.recover(digest, signature);

    ...
}
```

## License

This project is licensed under the GNU AGPLv3 or any later version. See [LICENSE.txt](./LICENSE.txt).
