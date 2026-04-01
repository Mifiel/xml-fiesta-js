import * as forge from "node-forge";

function extend(object, properties) {
  for (let key in properties) {
    const val = properties[key];
    object[key] = val;
  }
  return object;
}

function b64toHex(b64String) {
  return forge.util.bytesToHex(forge.util.decode64(b64String));
}

function hextoB64(hexString) {
  return forge.util.encode64(forge.util.hexToBytes(hexString));
}

function hextoAscii(hexString) {
  return forge.util.hexToBytes(hexString);
}

function b64toAscii(b64String) {
  return forge.util.decode64(b64String);
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
