// import { assertEquals } from "@std/assert";
import { get, verify } from "./mod.ts";

Deno.test(async function testVerify() {
  // run the mock server
  const attestation = await get(
    "http://127.0.0.1:1350/attestation/raw?public_key=1234",
  );
  const decoded = await verify(attestation);

  console.log(decoded);
});
