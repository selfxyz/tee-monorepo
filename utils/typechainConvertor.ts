import { Signer } from "ethers";
import {
  Pond__factory,
  Pond,
  MarketV1,
  MarketV1__factory,
  AttestationVerifier__factory,
  AttestationVerifier,
  AttestationAutherUpgradeable__factory,
  AttestationAutherUpgradeable,
  AttestationAutherSample__factory,
  AttestationAutherSample,
} from "../typechain-types";

export function getPond(contractAddress: string, signer: Signer): Pond {
  return new Pond__factory(signer).attach(contractAddress);
}

export function getMarketV1(contractAddress: string, signer: Signer): MarketV1 {
  return new MarketV1__factory(signer).attach(contractAddress);
}

export function getAttestationVerifier(contractAddress: string, signer: Signer): AttestationVerifier {
  return new AttestationVerifier__factory(signer).attach(contractAddress);
}

export function getAttestationAutherUpgradeable(contractAddress: string, signer: Signer): AttestationAutherUpgradeable {
  return new AttestationAutherUpgradeable__factory(signer).attach(contractAddress);
}

export function getAttestationAutherSample(contractAddress: string, signer: Signer): AttestationAutherSample {
  return new AttestationAutherSample__factory(signer).attach(contractAddress);
}
