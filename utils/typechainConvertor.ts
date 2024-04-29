import { Signer } from "ethers";
import {
  Pond__factory,
  Pond,
  AttestationVerifier__factory,
  AttestationVerifier,
  AttestationAutherUpgradeable__factory,
  AttestationAutherUpgradeable,
  CommonChainGateways__factory,
  CommonChainGateways,
  CommonChainExecutors__factory,
  CommonChainExecutors,
  CommonChainJobs,
  CommonChainJobs__factory,
  RequestChainContract,
  RequestChainContract__factory,
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

export function getCommonChainGateways(contractAddress: string, signer: Signer): CommonChainGateways {
  return new CommonChainGateways__factory(signer).attach(contractAddress) as CommonChainGateways;
}

export function getCommonChainExecutors(contractAddress: string, signer: Signer): CommonChainExecutors {
  return new CommonChainExecutors__factory(signer).attach(contractAddress) as CommonChainExecutors;
}

export function getCommonChainJobs(contractAddress: string, signer: Signer): CommonChainJobs {
  return new CommonChainJobs__factory(signer).attach(contractAddress) as CommonChainJobs;
}

export function getRequestChainContract(contractAddress: string, signer: Signer): RequestChainContract {
  return new RequestChainContract__factory(signer).attach(contractAddress) as RequestChainContract;
}

export function getUser(contractAddress: string, signer: Signer): User {
  return new User__factory(signer).attach(contractAddress) as User;
}