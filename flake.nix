{
  nixConfig = {
    allow-import-from-derivation = true;
    extra-substituters = ["https://oyster.cachix.org"];
    extra-trusted-public-keys = ["oyster.cachix.org-1:QEXLEQvMA7jPLn4VZWVk9vbtypkXhwZknX+kFgDpYQY="];
  };
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-24.11";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nitro-util = {
      url = "github:monzo/aws-nitro-util";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = {
    self,
    nixpkgs,
    fenix,
    naersk,
    nitro-util,
  }: let
    systemBuilder = systemConfig: rec {
      external.dnsproxy = import ./external/dnsproxy.nix {
        inherit nixpkgs systemConfig;
      };
      external.supervisord = import ./external/supervisord.nix {
        inherit nixpkgs systemConfig;
      };
      attestation-server = import ./attestation-server {
        inherit nixpkgs systemConfig fenix naersk;
      };
      initialization.vet = import ./initialization/vet {
        inherit nixpkgs systemConfig fenix naersk;
      };
      kernels.tuna = import ./kernels/tuna.nix {
        inherit nixpkgs systemConfig;
      };
      networking.raw-proxy = import ./networking/raw-proxy {
        inherit nixpkgs systemConfig fenix naersk;
      };
    };
  in {
    formatter = {
      "x86_64-linux" = nixpkgs.legacyPackages."x86_64-linux".alejandra;
    };
    packages = {
      "x86_64-linux" = let
        gnu = systemBuilder {
          system = "x86_64-linux";
          rust_target = "x86_64-unknown-linux-gnu";
          eif_arch = "x86_64";
          static = false;
        };
        musl = systemBuilder {
          system = "x86_64-linux";
          rust_target = "x86_64-unknown-linux-musl";
          eif_arch = "x86_64";
          static = true;
        };
      in {
        attestation-server = musl.attestation-server.default;
        dnsproxy = musl.external.dnsproxy.default;
        supervisord = musl.external.supervisord.default;
        vet = musl.initialization.vet.default;
        tuna = musl.kernels.tuna.default;
        raw-proxy = musl.networking.raw-proxy.default;
      };
    };
  };
}
