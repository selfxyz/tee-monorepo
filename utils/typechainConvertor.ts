import { Signer } from "ethers";
import {
  Pond__factory,
  Pond,
  AttestationVerifier__factory,
  AttestationVerifier,
  AttestationAutherUpgradeable__factory,
  AttestationAutherUpgradeable,
  Gateways__factory,
  Gateways,
  Executors__factory,
  Executors,
  Jobs,
  Jobs__factory,
  Relay,
  Relay__factory,
  User,
  User__factory,
} from "../typechain-types";


export function getPond(contractAddress: string, signer: Signer): Pond {
  return new Pond__factory(signer).attach(contractAddress) as Pond;
}

export function getAttestationVerifier(contractAddress: string, signer: Signer): AttestationVerifier {
  return new AttestationVerifier__factory(signer).attach(contractAddress) as AttestationVerifier;
}

export function getAttestationAutherUpgradeable(contractAddress: string, signer: Signer): AttestationAutherUpgradeable {
  return new AttestationAutherUpgradeable__factory(signer).attach(contractAddress) as AttestationAutherUpgradeable;
}

export function getGateways(contractAddress: string, signer: Signer): Gateways {
  return new Gateways__factory(signer).attach(contractAddress) as Gateways;
}

export function getExecutors(contractAddress: string, signer: Signer): Executors {
  return new Executors__factory(signer).attach(contractAddress) as Executors;
}

export function getJobs(contractAddress: string, signer: Signer): Jobs {
  return new Jobs__factory(signer).attach(contractAddress) as Jobs;
}

export function getRelay(contractAddress: string, signer: Signer): Relay {
  return new Relay__factory(signer).attach(contractAddress) as Relay;
}

export function getUser(contractAddress: string, signer: Signer): User {
  return new User__factory(signer).attach(contractAddress) as User;
}