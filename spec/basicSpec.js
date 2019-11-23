const jsrsasign = require('jsrsasign');
const fs = require('fs');
const expect = require('expect.js');

const intermediate = fs.readFileSync(`${__dirname}/../docs/AC2_Sat.crt`).toString();
const cert = fs.readFileSync(`${__dirname}/fixtures/production-certificate.pem`).toString();

describe('Basic certificate validation', () => it('should be true', function() {
  const certificate = new jsrsasign.X509();
  certificate.readCertPEM(cert);

  const hTbsCert = jsrsasign.ASN1HEX.getDecendantHexTLVByNthList(certificate.hex, 0, [0]);
  const alg = certificate.getSignatureAlgorithmField();
  const signature = jsrsasign.X509.getSignatureValueHex(certificate.hex);

  const sig = new jsrsasign.crypto.Signature({alg});
  sig.init(intermediate);
  sig.updateHex(hTbsCert);
  expect(sig.verify(signature)).to.be(true);
}));
