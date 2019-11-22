/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * DS209: Avoid top-level return
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const jsrsasign = require('jsrsasign');

module.exports = {
  extend(object, properties) {
    for (let key in properties) {
      const val = properties[key];
      object[key] = val;
    }
    return object;
  },

  b64toHex(b64String) {
    return new Buffer(b64String, 'base64').toString('hex');
  },

  hextoB64(hexString) {
    return new Buffer(hexString, 'hex').toString('base64');
  },

  hextoAscii(hexString) {
    return new Buffer(hexString, 'hex').toString('ascii');
  },

  b64toAscii(b64String) {
    return new Buffer(b64String, 'base64').toString('ascii');
  },

  parseDate(date) {
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
          parseInt(parsed[5])
        )
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
          parseInt(parsed[5])
        )
      );
    }
  },


  sha256(string) {
    const digest = new jsrsasign.crypto.MessageDigest({
      alg: 'sha256',
      prov: 'cryptojs'
    });
    return digest.digestString(string);
  },

  sha256hex(hex) {
    const digest = new jsrsasign.crypto.MessageDigest({
      alg: 'sha256',
      prov: 'cryptojs'
    });
    return digest.digestHex(hex);
  }
};
