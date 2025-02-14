![Marlin Oyster Logo](./logo.svg)

# Init Params Manager

This project provides an encoder and decoder for initialization parameters for enclaves. The encoder is expected to be used by users to encode their initialization parameters before deployment. The decoder is expected to be used inside enclaves to decode the initialization parameters and extract them onto the enclave filesystem.

## Build

```bash
cargo build --release
```

### Reproducible builds

Reproducible builds can be done using Nix. The monorepo provides a Nix flake which includes this project and can be used to trigger builds:

```bash
nix build -v .#<flavor>.initialization.init-params-manager.<output>
```

Supported flavors:
- `gnu`
- `musl`

Supported outputs:
- `default`, same as `compressed`
- `uncompressed`
- `compressed`, using `upx`

## Encoder

Takes raw params either as UTF-8 strings or files and encodes them into an init param string.

### Usage

```bash
$ ./target/release/init-params-encoder --help
Usage: init-params-encoder [OPTIONS] --kms-endpoint <KMS_ENDPOINT> --pcr0 <PCR0> --pcr1 <PCR1> --pcr2 <PCR2>

Options:
      --init-params <INIT_PARAMS>    Init params list, supports the following forms: `<enclave path>:<should attest, 0 or 1>:<should encrypt, 0 or 1>:utf8:<string>` `<enclave path>:<should attest, 0 or 1>:<should encrypt, 0 or 1>:file:<local path>`
      --kms-endpoint <KMS_ENDPOINT>  KMS public endpoint
      --pcr0 <PCR0>                  PCR0
      --pcr1 <PCR1>                  PCR1
      --pcr2 <PCR2>                  PCR2
  -h, --help                         Print help
```

Multiple init params can be specified by simply repeating `--init-params <INIT_PARAMS>`.

### Example

```bash
$ ./target/release/init-params-encoder --kms-endpoint http://v1.kms.box:1101 --pcr0 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 --pcr1 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 --pcr2 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 --init-params 'hello/hello:1:1:utf8:hello' --init-params 'Cargo.toml:1:1:file:./Cargo.toml'
2025-02-02T10:37:43.720731Z  INFO init_params_encoder: digest path="hello/hello" should_attest=true should_encrypt=true
2025-02-02T10:37:43.720780Z  INFO init_params_encoder: digest path="Cargo.toml" should_attest=true should_encrypt=true
2025-02-02T10:37:43.804398Z  INFO init_params_encoder: param path="hello/hello" should_attest=true should_encrypt=true
2025-02-02T10:37:43.804571Z  INFO init_params_encoder: param path="Cargo.toml" should_attest=true should_encrypt=true
2025-02-02T10:37:43.804671Z  INFO init_params_encoder: JSON: {
  "digest": "p9fbHwysAlEuutj8HmMbDyrbXApuLI3xzdVqJR4OOx4=",
  "params": [
    {
      "path": "hello/hello",
      "contents": "khiQXA1Uy0O/wnQ5Wx0X/h3N91eyBdLMlHmiUcTMuB5TCG+efPTF8basFnDc/xYMoO03Wb0=",
      "should_attest": true,
      "should_decrypt": true
    },
    {
      "path": "Cargo.toml",
      "contents": "5xOFcLzmXtdZkP+rU/d1wAEsWpH6VDXAaM0UTgXAblBliUzmDBDVZd/qcxa2293+xPwoNOpeu9ZTDpgVXacM7iBaRBGNonoalIMmUH+5YB6rh+YKigqhbivt/EMcNyYJL+zNmiHgT2Rk76S7A6BvMnHLKJG81zOzPzW2Cp40fTYWoV336n2oExpM5V8zjmEez1qWCHOWp3ByIJyGD7vBGHqoT43fUtQCfawIXwZ0ic+bw99qzfrfUS4bz/rEJtJRWr40TO8FgTETjOuNerG/vSUZ+rnU3PV4k8Z6nQ5GU0Puo0HP1kq0MrLZcIGTpwTcee/Do4xrxhfiKMoOdX5JB+2Kpy4AX0idv2k2MIltJR1HJ2eplv27li6xgeFvZEB4dTgUm78JrsDM2Pp8mlQdrBln6vuzCBtpGWQEUhqyfHXCPKfqfShWg/IY1NrkEdvkx0hOtFxxOZ/q7Xg4pgf4Ekynznyq+XjhZdeX4/0HaOaD8/hfWrOTcKKLcWjVfjSqvNpd8lBVjMGxqcps+cBlXNkFhwu3icXYQmFAQZFnakdbUHn1Obxf0/zabx1L1dAjKu5EsF0sg2SUbq5GaLIYaClFnWBD29dPiJLpbUaR4OZMHHkn/LDOR7eer/nyrw58AR4rh8SlGiE7JIqkzXqDse/DSacpUTAb4TmDPdrbDkxNshx/sXAsVc5wuK7Lt+VJ3xjChJ/PSbNbJit3hstc490YaOlRDpXdWRY4Cq6EnDI2ZHuGOTuEz7aSKPrpjpRdNDztkSXwPcEedJOC+ZCBJIffdaG96DeciahGbK6Po4piam4kh9Vxz4DzOnbupxdpk1haqjEqLznoOttfvcT0439XEww6AVrmr6tvhVAJXaUZRSYe6038A6vmf/352reg8bSnLxRzt95UQw4GO//O+fu2KUzEwX4nAyW5YAEHNM7LLWfgkUbgS+dU2kHCPq/OekZmbmQeWYLL/Rg/2A8=",
      "should_attest": true,
      "should_decrypt": true
    }
  ]
}
2025-02-02T10:37:43.804698Z  INFO init_params_encoder: BASE64: ewogICJkaWdlc3QiOiAicDlmYkh3eXNBbEV1dXRqOEhtTWJEeXJiWEFwdUxJM3h6ZFZxSlI0T094ND0iLAogICJwYXJhbXMiOiBbCiAgICB7CiAgICAgICJwYXRoIjogImhlbGxvL2hlbGxvIiwKICAgICAgImNvbnRlbnRzIjogImtoaVFYQTFVeTBPL3duUTVXeDBYL2gzTjkxZXlCZExNbEhtaVVjVE11QjVUQ0crZWZQVEY4YmFzRm5EYy94WU1vTzAzV2IwPSIsCiAgICAgICJzaG91bGRfYXR0ZXN0IjogdHJ1ZSwKICAgICAgInNob3VsZF9kZWNyeXB0IjogdHJ1ZQogICAgfSwKICAgIHsKICAgICAgInBhdGgiOiAiQ2FyZ28udG9tbCIsCiAgICAgICJjb250ZW50cyI6ICI1eE9GY0x6bVh0ZFprUCtyVS9kMXdBRXNXcEg2VkRYQWFNMFVUZ1hBYmxCbGlVem1EQkRWWmQvcWN4YTIyOTMreFB3b05PcGV1OVpURHBnVlhhY003aUJhUkJHTm9ub2FsSU1tVUgrNVlCNnJoK1lLaWdxaGJpdnQvRU1jTnlZSkwrek5taUhnVDJSazc2UzdBNkJ2TW5ITEtKRzgxek96UHpXMkNwNDBmVFlXb1YzMzZuMm9FeHBNNVY4emptRWV6MXFXQ0hPV3AzQnlJSnlHRDd2QkdIcW9UNDNmVXRRQ2Zhd0lYd1owaWMrYnc5OXF6ZnJmVVM0YnovckVKdEpSV3I0MFRPOEZnVEVUak91TmVyRy92U1VaK3JuVTNQVjRrOFo2blE1R1UwUHVvMEhQMWtxME1yTFpjSUdUcHdUY2VlL0RvNHhyeGhmaUtNb09kWDVKQisyS3B5NEFYMGlkdjJrMk1JbHRKUjFISjJlcGx2MjdsaTZ4Z2VGdlpFQjRkVGdVbTc4SnJzRE0yUHA4bWxRZHJCbG42dnV6Q0J0cEdXUUVVaHF5ZkhYQ1BLZnFmU2hXZy9JWTFOcmtFZHZreDBoT3RGeHhPWi9xN1hnNHBnZjRFa3luem55cStYamhaZGVYNC8wSGFPYUQ4L2hmV3JPVGNLS0xjV2pWZmpTcXZOcGQ4bEJWak1HeHFjcHMrY0JsWE5rRmh3dTNpY1hZUW1GQVFaRm5ha2RiVUhuMU9ieGYwL3phYngxTDFkQWpLdTVFc0Ywc2cyU1VicTVHYUxJWWFDbEZuV0JEMjlkUGlKTHBiVWFSNE9aTUhIa24vTERPUjdlZXIvbnlydzU4QVI0cmg4U2xHaUU3Sklxa3pYcURzZS9EU2FjcFVUQWI0VG1EUGRyYkRreE5zaHgvc1hBc1ZjNXd1SzdMdCtWSjN4akNoSi9QU2JOYkppdDNoc3RjNDkwWWFPbFJEcFhkV1JZNENxNkVuREkyWkh1R09UdUV6N2FTS1BycGpwUmRORHp0a1NYd1BjRWVkSk9DK1pDQkpJZmZkYUc5NkRlY2lhaEdiSzZQbzRwaWFtNGtoOVZ4ejREek9uYnVweGRwazFoYXFqRXFMem5vT3R0ZnZjVDA0MzlYRXd3NkFWcm1yNnR2aFZBSlhhVVpSU1llNjAzOEE2dm1mLzM1MnJlZzhiU25MeFJ6dDk1VVF3NEdPLy9PK2Z1MktVekV3WDRuQXlXNVlBRUhOTTdMTFdmZ2tVYmdTK2RVMmtIQ1BxL09la1ptYm1RZVdZTEwvUmcvMkE4PSIsCiAgICAgICJzaG91bGRfYXR0ZXN0IjogdHJ1ZSwKICAgICAgInNob3VsZF9kZWNyeXB0IjogdHJ1ZQogICAgfQogIF0KfQ==
```

## Decoder

Takes encoded init params and extract them into files inside the `/init-params` directory.

### Usage

```bash
./target/release/init-params-decoder --help
Usage: init-params-decoder [OPTIONS]

Options:
      --init-params-path <INIT_PARAMS_PATH>  Init params file [default: /app/init-params]
      --derive-endpoint <DERIVE_ENDPOINT>    Derive server endpoint [default: http://127.0.0.1:1100]
  -h, --help                                 Print help
```

### Example

Given the same init params as the encoder example, the decoder will create the following files:
- `/init-params/hello/hello` with `hello` as the content
- `/init-params/Cargo.toml` with the content of the `Cargo.toml` file

## Encoder - Contract

Takes raw params either as UTF-8 strings or files and encodes them into an init param string. Unlike the regular encoder, it does not use PCRs or parameter digests. Instead, it expects a verification contract address on a blockchain.

### Usage

```bash
$ ./target/release/init-params-encoder-contract --help
Usage: init-params-encoder-contract [OPTIONS] --kms-endpoint <KMS_ENDPOINT> --address <ADDRESS>

Options:
      --init-params <INIT_PARAMS>    Init params list, supports the following forms: `<enclave path>:<should attest, 0 or 1>:<should encrypt, 0 or 1>:utf8:<string>` `<enclave path>:<should attest, 0 or 1>:<should encrypt, 0 or 1>:file:<local path>`
      --kms-endpoint <KMS_ENDPOINT>  KMS public endpoint
      --address <ADDRESS>            Contract address managing verification
  -h, --help                         Print help
```

Multiple init params can be specified by simply repeating `--init-params <INIT_PARAMS>`.

### Example

```bash
$ ./target/release/init-params-encoder-contract --kms-endpoint http://arbone-v1.kms.box:1101 --address 0x000000000000000000000000000000000000dead --init-params 'hello/hello:1:1:utf8:hello' --init-params 'Cargo.toml:1:1:file:./Cargo.toml'
2025-02-02T10:37:43.720731Z  INFO init_params_encoder_contract: digest path="hello/hello" should_attest=true should_encrypt=true
2025-02-02T10:37:43.720780Z  INFO init_params_encoder_contract: digest path="Cargo.toml" should_attest=true should_encrypt=true
2025-02-02T10:37:43.804398Z  INFO init_params_encoder_contract: param path="hello/hello" should_attest=true should_encrypt=true
2025-02-02T10:37:43.804571Z  INFO init_params_encoder_contract: param path="Cargo.toml" should_attest=true should_encrypt=true
2025-02-02T10:37:43.804671Z  INFO init_params_encoder_contract: JSON: {
  "digest": "p9fbHwysAlEuutj8HmMbDyrbXApuLI3xzdVqJR4OOx4=",
  "params": [
    {
      "path": "hello/hello",
      "contents": "khiQXA1Uy0O/wnQ5Wx0X/h3N91eyBdLMlHmiUcTMuB5TCG+efPTF8basFnDc/xYMoO03Wb0=",
      "should_attest": true,
      "should_decrypt": true
    },
    {
      "path": "Cargo.toml",
      "contents": "5xOFcLzmXtdZkP+rU/d1wAEsWpH6VDXAaM0UTgXAblBliUzmDBDVZd/qcxa2293+xPwoNOpeu9ZTDpgVXacM7iBaRBGNonoalIMmUH+5YB6rh+YKigqhbivt/EMcNyYJL+zNmiHgT2Rk76S7A6BvMnHLKJG81zOzPzW2Cp40fTYWoV336n2oExpM5V8zjmEez1qWCHOWp3ByIJyGD7vBGHqoT43fUtQCfawIXwZ0ic+bw99qzfrfUS4bz/rEJtJRWr40TO8FgTETjOuNerG/vSUZ+rnU3PV4k8Z6nQ5GU0Puo0HP1kq0MrLZcIGTpwTcee/Do4xrxhfiKMoOdX5JB+2Kpy4AX0idv2k2MIltJR1HJ2eplv27li6xgeFvZEB4dTgUm78JrsDM2Pp8mlQdrBln6vuzCBtpGWQEUhqyfHXCPKfqfShWg/IY1NrkEdvkx0hOtFxxOZ/q7Xg4pgf4Ekynznyq+XjhZdeX4/0HaOaD8/hfWrOTcKKLcWjVfjSqvNpd8lBVjMGxqcps+cBlXNkFhwu3icXYQmFAQZFnakdbUHn1Obxf0/zabx1L1dAjKu5EsF0sg2SUbq5GaLIYaClFnWBD29dPiJLpbUaR4OZMHHkn/LDOR7eer/nyrw58AR4rh8SlGiE7JIqkzXqDse/DSacpUTAb4TmDPdrbDkxNshx/sXAsVc5wuK7Lt+VJ3xjChJ/PSbNbJit3hstc490YaOlRDpXdWRY4Cq6EnDI2ZHuGOTuEz7aSKPrpjpRdNDztkSXwPcEedJOC+ZCBJIffdaG96DeciahGbK6Po4piam4kh9Vxz4DzOnbupxdpk1haqjEqLznoOttfvcT0439XEww6AVrmr6tvhVAJXaUZRSYe6038A6vmf/352reg8bSnLxRzt95UQw4GO//O+fu2KUzEwX4nAyW5YAEHNM7LLWfgkUbgS+dU2kHCPq/OekZmbmQeWYLL/Rg/2A8=",
      "should_attest": true,
      "should_decrypt": true
    }
  ]
}
2025-02-02T10:37:43.804698Z  INFO init_params_encoder_contract: BASE64: ewogICJkaWdlc3QiOiAicDlmYkh3eXNBbEV1dXRqOEhtTWJEeXJiWEFwdUxJM3h6ZFZxSlI0T094ND0iLAogICJwYXJhbXMiOiBbCiAgICB7CiAgICAgICJwYXRoIjogImhlbGxvL2hlbGxvIiwKICAgICAgImNvbnRlbnRzIjogImtoaVFYQTFVeTBPL3duUTVXeDBYL2gzTjkxZXlCZExNbEhtaVVjVE11QjVUQ0crZWZQVEY4YmFzRm5EYy94WU1vTzAzV2IwPSIsCiAgICAgICJzaG91bGRfYXR0ZXN0IjogdHJ1ZSwKICAgICAgInNob3VsZF9kZWNyeXB0IjogdHJ1ZQogICAgfSwKICAgIHsKICAgICAgInBhdGgiOiAiQ2FyZ28udG9tbCIsCiAgICAgICJjb250ZW50cyI6ICI1eE9GY0x6bVh0ZFprUCtyVS9kMXdBRXNXcEg2VkRYQWFNMFVUZ1hBYmxCbGlVem1EQkRWWmQvcWN4YTIyOTMreFB3b05PcGV1OVpURHBnVlhhY003aUJhUkJHTm9ub2FsSU1tVUgrNVlCNnJoK1lLaWdxaGJpdnQvRU1jTnlZSkwrek5taUhnVDJSazc2UzdBNkJ2TW5ITEtKRzgxek96UHpXMkNwNDBmVFlXb1YzMzZuMm9FeHBNNVY4emptRWV6MXFXQ0hPV3AzQnlJSnlHRDd2QkdIcW9UNDNmVXRRQ2Zhd0lYd1owaWMrYnc5OXF6ZnJmVVM0YnovckVKdEpSV3I0MFRPOEZnVEVUak91TmVyRy92U1VaK3JuVTNQVjRrOFo2blE1R1UwUHVvMEhQMWtxME1yTFpjSUdUcHdUY2VlL0RvNHhyeGhmaUtNb09kWDVKQisyS3B5NEFYMGlkdjJrMk1JbHRKUjFISjJlcGx2MjdsaTZ4Z2VGdlpFQjRkVGdVbTc4SnJzRE0yUHA4bWxRZHJCbG42dnV6Q0J0cEdXUUVVaHF5ZkhYQ1BLZnFmU2hXZy9JWTFOcmtFZHZreDBoT3RGeHhPWi9xN1hnNHBnZjRFa3luem55cStYamhaZGVYNC8wSGFPYUQ4L2hmV3JPVGNLS0xjV2pWZmpTcXZOcGQ4bEJWak1HeHFjcHMrY0JsWE5rRmh3dTNpY1hZUW1GQVFaRm5ha2RiVUhuMU9ieGYwL3phYngxTDFkQWpLdTVFc0Ywc2cyU1VicTVHYUxJWWFDbEZuV0JEMjlkUGlKTHBiVWFSNE9aTUhIa24vTERPUjdlZXIvbnlydzU4QVI0cmg4U2xHaUU3Sklxa3pYcURzZS9EU2FjcFVUQWI0VG1EUGRyYkRreE5zaHgvc1hBc1ZjNXd1SzdMdCtWSjN4akNoSi9QU2JOYkppdDNoc3RjNDkwWWFPbFJEcFhkV1JZNENxNkVuREkyWkh1R09UdUV6N2FTS1BycGpwUmRORHp0a1NYd1BjRWVkSk9DK1pDQkpJZmZkYUc5NkRlY2lhaEdiSzZQbzRwaWFtNGtoOVZ4ejREek9uYnVweGRwazFoYXFqRXFMem5vT3R0ZnZjVDA0MzlYRXd3NkFWcm1yNnR2aFZBSlhhVVpSU1llNjAzOEE2dm1mLzM1MnJlZzhiU25MeFJ6dDk1VVF3NEdPLy9PK2Z1MktVekV3WDRuQXlXNVlBRUhOTTdMTFdmZ2tVYmdTK2RVMmtIQ1BxL09la1ptYm1RZVdZTEwvUmcvMkE4PSIsCiAgICAgICJzaG91bGRfYXR0ZXN0IjogdHJ1ZSwKICAgICAgInNob3VsZF9kZWNyeXB0IjogdHJ1ZQogICAgfQogIF0KfQ==
```

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE.txt](./LICENSE.txt).
