import { assertEquals } from "@std/assert";
import { decodeHex } from "jsr:@std/encoding@1/hex";
import { verify } from "./mod.ts";

// generated using `curl <ip>:<port>/attestation/raw` on the attestation server of a
// real Nitro enclave
Deno.test(async function testVerifyNitro() {
  const attestation = await Deno.readFile(
    new URL("./testcases/aws.bin", import.meta.url),
  );

  const decoded = await verify(attestation);

  assertEquals(decoded.timestamp, 0x00000193bef3f3b0);
  assertEquals(
    decoded.pcrs[0],
    decodeHex(
      "189038eccf28a3a098949e402f3b3d86a876f4915c5b02d546abb5d8c507ceb1755b8192d8cfca66e8f226160ca4c7a6",
    ),
  );
  assertEquals(
    decoded.pcrs[1],
    decodeHex(
      "5d3938eb05288e20a981038b1861062ff4174884968a39aee5982b312894e60561883576cc7381d1a7d05b809936bd16",
    ),
  );
  assertEquals(
    decoded.pcrs[2],
    decodeHex(
      "6c3ef363c488a9a86faa63a44653fd806e645d4540b40540876f3b811fc1bceecf036a4703f07587c501ee45bb56a1aa",
    ),
  );
  assertEquals(
    decoded.rootPublicKey,
    decodeHex(
      "fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4",
    ),
  );
  assertEquals(
    decoded.publicKey,
    decodeHex(
      "e646f8b0071d5ba75931402522cc6a5c42a84a6fea238864e5ac9a0e12d83bd36d0c8109d3ca2b699fce8d082bf313f5d2ae249bb275b6b6e91e0fcd9262f4bb",
    ),
  );
});

// generated using `curl <ip>:<port>/attestation/raw?public_key=12345678&user_data=abcdef`
// on a custom mock attestation server running locally
Deno.test(async function testVerifyCustom() {
  const attestation = await Deno.readFile(
    new URL("./testcases/custom.bin", import.meta.url),
  );

  const decoded = await verify(attestation);

  assertEquals(decoded.timestamp, 0x00000193bf444e30);
  assertEquals(decoded.pcrs[0], new Uint8Array(48).fill(0));
  assertEquals(decoded.pcrs[1], new Uint8Array(48).fill(1));
  assertEquals(decoded.pcrs[2], new Uint8Array(48).fill(2));
  assertEquals(
    decoded.rootPublicKey,
    decodeHex(
      "6c79411ebaae7489a4e8355545c0346784b31df5d08cb1f7c0097836a82f67240f2a7201862880a1d09a0bb326637188fbbafab47a10abe3630fcf8c18d35d96532184985e582c0dce3dace8441f37b9cc9211dff935baae69e4872cc3494410",
    ),
  );
  assertEquals(
    decoded.publicKey,
    decodeHex("12345678"),
  );
});
