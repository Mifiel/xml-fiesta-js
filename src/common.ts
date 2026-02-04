import * as forge from "node-forge";

function extend(object, properties) {
  for (let key in properties) {
    const val = properties[key];
    object[key] = val;
  }
  return object;
}

function b64toHex(b64String) {
  return Buffer.from(b64String, "base64").toString("hex");
}

function hextoB64(hexString) {
  return Buffer.from(hexString, "hex").toString("base64");
}

function hextoAscii(hexString) {
  return Buffer.from(hexString, "hex").toString("ascii");
}

function b64toAscii(b64String) {
  return Buffer.from(b64String, "base64").toString("ascii");
}

function parseDate(date) {
  let parsed;
  try {
    parsed = date.match(/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\..*Z/);
    parsed.shift(1);
    return new Date(
      Date.UTC(
        parseInt(parsed[0]),
        parseInt(parsed[1]) - 1,
        parseInt(parsed[2]),
        parseInt(parsed[3]),
        parseInt(parsed[4]),
        parseInt(parsed[5]),
      ),
    );
  } catch (error) {
    parsed = date.match(/(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\..*Z/);
    parsed.shift(1);
    return new Date(
      Date.UTC(
        parseInt(parsed[0]) + 2000,
        parseInt(parsed[1]) - 1,
        parseInt(parsed[2]),
        parseInt(parsed[3]),
        parseInt(parsed[4]),
        parseInt(parsed[5]),
      ),
    );
  }
}

function sha256(string) {
  const md = forge.md.sha256.create();
  md.update(string, "utf8");
  return md.digest().toHex();
}

function sha256hex(hex) {
  const md = forge.md.sha256.create();
  md.update(forge.util.hexToBytes(hex));
  return md.digest().toHex();
}

export {
  extend,
  b64toHex,
  hextoB64,
  hextoAscii,
  b64toAscii,
  parseDate,
  sha256,
  sha256hex,
};
