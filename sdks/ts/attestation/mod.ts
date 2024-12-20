import { decodeHex } from "jsr:@std/encoding@1/hex";

export const AWS_ROOT_KEY: Uint8Array = decodeHex(
  "fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4",
);
