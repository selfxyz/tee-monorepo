import { decodeHex } from "jsr:@std/encoding@1/hex";
import { decode } from "npm:cbor2@1";
import * as cose from "npm:cose-js@0.9";
import { X509Certificate } from "npm:@peculiar/x509@1";

// Graveyard of x509 libraries that did not work, fuck me I guess
//
// node:crypto - certificate verification not implemented in deno, will not work in a browser anyway
// node-forge - does not support ECC, only RSA
// @fidm/x509 - failed to parse dates
// pkijs - failed certificate chain verification

export const AWS_ROOT_KEY: Uint8Array = decodeHex(
  "fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4",
);

export interface AttestationDecoded {
  timestamp: number;
  pcrs: Uint8Array[];
  rootPublicKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface AttestationExpectations {
  timestamp?: number;
  age?: {
    maxAge: number;
    currentTimestamp: number;
  };
  pcrs?: Uint8Array[];
  rootPublicKey?: Uint8Array;
}

export class AttestationError extends Error {
  constructor(
    type: "ParseFailed" | "VerifyFailed" | "HttpClientError",
    message: string,
  ) {
    super(`${type}: ${message}`);
    this.name = "AttestationError";
  }
}

export async function verify(
  attestationDoc: Uint8Array,
  expectations: AttestationExpectations = {},
): Promise<AttestationDecoded> {
  const result: AttestationDecoded = {
    timestamp: 0,
    pcrs: Array(3).fill(new Uint8Array(48)),
    rootPublicKey: new Uint8Array(),
    publicKey: new Uint8Array(),
  };

  // parse attestation doc
  const [coseSign1, attestationData] = parseAttestationDoc(attestationDoc);

  // parse timestamp
  result.timestamp = parseTimestamp(attestationData);

  // check expected timestamp if exists
  if (
    expectations.timestamp &&
    result.timestamp !== expectations.timestamp
  ) {
    throw new AttestationError("VerifyFailed", "timestamp mismatch");
  }

  // check age if exists
  if (expectations.age) {
    const { maxAge, currentTimestamp } = expectations.age;
    if (
      result.timestamp <= currentTimestamp &&
      currentTimestamp - result.timestamp > maxAge
    ) {
      throw new AttestationError(
        "VerifyFailed",
        "too old",
      );
    }
  }

  // parse pcrs
  result.pcrs = parsePCRs(attestationData);

  // check pcrs if exists
  if (
    expectations.pcrs && !(
      result.pcrs.length === expectations.pcrs.length &&
      result.pcrs.every((pcr, i) =>
        pcr.toString() === expectations.pcrs![i].toString()
      )
    )
  ) {
    throw new AttestationError("VerifyFailed", "pcrs mismatch");
  }

  // verify signature and cert chain
  result.rootPublicKey = await verifyRootOfTrust(attestationData, coseSign1);

  // check root public key if exists
  if (
    expectations.rootPublicKey &&
    result.rootPublicKey.toString() !== expectations.rootPublicKey.toString()
  ) {
    throw new AttestationError("VerifyFailed", "root public key mismatch");
  }

  // return the enclave key
  result.publicKey = parseEnclaveKey(attestationData);

  return result;
}

interface AttestationPayload {
  module_id: string;
  digest: string;
  timestamp: number;
  pcrs: Map<number, Uint8Array>;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
  public_key: Uint8Array;
  user_data: Uint8Array;
  nonce: Uint8Array;
}

// deno-lint-ignore no-explicit-any
function isAttestationPayload(payload: any): payload is AttestationPayload {
  if (
    typeof payload === "object" && typeof payload.module_id === "string" &&
    typeof payload.digest === "string" &&
    typeof payload.timestamp === "number" &&
    payload.pcrs instanceof Map &&
    // deno-lint-ignore no-explicit-any
    payload.pcrs.keys().every((x: any) => typeof x === "number") &&
    // deno-lint-ignore no-explicit-any
    payload.pcrs.values().every((x: any) => x instanceof Uint8Array) &&
    payload.certificate instanceof Uint8Array &&
    Array.isArray(payload.cabundle) &&
    // deno-lint-ignore no-explicit-any
    payload.cabundle.every((x: any) => x instanceof Uint8Array) &&
    (payload.public_key === null || payload.public_key instanceof Uint8Array) &&
    (payload.user_data === null || payload.user_data instanceof Uint8Array) &&
    (payload.nonce === null || payload.nonce instanceof Uint8Array)
  ) {
    return true;
  }

  return false;
}

function parseAttestationDoc(
  attestationDoc: Uint8Array,
): [Uint8Array, AttestationPayload] {
  try {
    const decoded = decode(attestationDoc);
    if (!Array.isArray(decoded)) {
      throw new AttestationError(
        "ParseFailed",
        `Failed to parse attestation document: cose`,
      );
    }

    const payloadBytes = decoded[2];
    if (!(payloadBytes instanceof Uint8Array)) {
      throw new AttestationError(
        "ParseFailed",
        `Failed to parse attestation document: cose payload`,
      );
    }

    const payload = decode(payloadBytes);
    if (!isAttestationPayload(payload)) {
      throw new AttestationError(
        "ParseFailed",
        `Failed to parse attestation document: cbor`,
      );
    }

    return [attestationDoc, payload];
  } catch (error) {
    throw new AttestationError(
      "ParseFailed",
      `Failed to parse attestation document: ${error}`,
    );
  }
}

function parseTimestamp(data: AttestationPayload): number {
  const timestamp = data.timestamp;

  return timestamp;
}

function parsePCRs(data: AttestationPayload): Uint8Array[] {
  const pcrs = data.pcrs;

  const result: Uint8Array[] = [];
  for (let i = 0; i < 3; i++) {
    const pcr = pcrs.get(i);
    if (!pcr || pcr.length !== 48) {
      throw new AttestationError("ParseFailed", `Invalid PCR${i}`);
    }
    result.push(pcr);
  }
  return result;
}

async function verifyRootOfTrust(
  data: AttestationPayload,
  coseSign1: Uint8Array,
): Promise<Uint8Array> {
  // verify attestation doc signature
  const enclaveCert = data.certificate;
  const leafCert = new X509Certificate(enclaveCert);
  const pubkey = new Uint8Array(leafCert.publicKey.rawData.slice(24));

  await cose.sign.verify(coseSign1, {
    key: {
      x: pubkey.slice(0, 48),
      y: pubkey.slice(48),
    },
  }, { defaultType: 18 });

  // verify certificate chain
  const caBundle = data.cabundle;
  const rootKey = verifyCertChain(
    leafCert,
    caBundle.map((x) => new X509Certificate(x)).reverse(),
  );

  return rootKey;
}

async function verifyCertChain(
  leafCert: X509Certificate,
  caBundle: X509Certificate[],
): Promise<Uint8Array> {
  try {
    const certs = [leafCert, ...caBundle];

    for (let i = 0; i < certs.length - 1; i++) {
      const current = certs[i];
      const issuer = certs[i + 1];

      console.log(current, issuer);

      if (
        !(await current.verify({
          publicKey: issuer.publicKey,
          signatureOnly: true,
        }))
      ) {
        throw new AttestationError(
          "VerifyFailed",
          `Invalid signature for certificate ${i}`,
        );
      }

      if (current.issuer !== issuer.subject) {
        throw new AttestationError(
          "VerifyFailed",
          `Invalid issuer for certificate ${i}`,
        );
      }

      const now = new Date();
      if (
        now < current.notBefore || now > current.notAfter
      ) {
        throw new AttestationError(
          "VerifyFailed",
          `Certificate ${i} is not valid at current time`,
        );
      }
    }

    const rootCert = certs[certs.length - 1];

    return new Uint8Array(rootCert.publicKey.rawData.slice(24));
  } catch (error) {
    throw new AttestationError(
      "VerifyFailed",
      `Certificate chain verification failed: ${error}`,
    );
  }
}

function parseEnclaveKey(data: AttestationPayload): Uint8Array {
  const publicKey = data.public_key;

  return publicKey;
}

export async function get(endpoint: string): Promise<Uint8Array> {
  try {
    const response = await fetch(endpoint);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return new Uint8Array(await response.arrayBuffer());
  } catch (error) {
    throw new AttestationError(
      "HttpClientError",
      `Failed to fetch attestation document: ${error}`,
    );
  }
}
