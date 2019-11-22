/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * DS207: Consider shorter variations of null checks
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const errors    = require('./errors');
const common    = require('./common');
const jsrsasign = require('jsrsasign');

jsrsasign.X509.hex2dnobj = function(e) {
  const f = {};
  const c = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(e, 0);
  let d = 0;

  while (d < c.length) {
    const b = jsrsasign.ASN1HEX.getHexOfTLV_AtObj(e, c[d]);
    try {
      const rdn = jsrsasign.X509.hex2rdnobj(b);
      f[rdn[0]] = rdn[1];
    } catch (err) {
      console.error(err);
    }
    d++;
  }
  return f;
};

jsrsasign.X509.hex2rdnobj = function(a) {
  const f = jsrsasign.ASN1HEX.getDecendantHexTLVByNthList(a, 0, [0, 0]);
  const e = jsrsasign.ASN1HEX.getDecendantHexVByNthList(a, 0, [0, 1]);
  let c = '';
  try {
    c = jsrsasign.X509.DN_ATTRHEX[f];
  } catch (b) {
    c = f;
  }
  const d = jsrsasign.hextorstr(e);
  return [c, d];
};

jsrsasign.X509.prototype.getSubjectObject = function() {
  return jsrsasign.X509.hex2dnobj(
    jsrsasign.ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5])
  );
};

jsrsasign.X509.DN_ATTRHEX = {
  '0603550406': 'C',
  '060355040a': 'O',
  '060355040b': 'OU',
  '0603550403': 'CN',
  '0603550405': 'serialNumber',
  '0603550408': 'ST',
  '0603550407': 'L',
  '060355042d': 'UI',
  '0603550409': 'street',
  '0603550429': 'name',
  '0603550411': 'postalCode',
  '06092a864886f70d010901': 'emailAddress',
  '06092a864886f70d010902': 'unstructuredName'
};

var Certificate = function(binaryString, hexString) {
  let pem;
  let hex = binaryString ? jsrsasign.rstrtohex(binaryString) : hexString;
  const certificate = new jsrsasign.X509();
  let pubKey = null;
  let subject = null;

  if ((binaryString.length === 0) || (!jsrsasign.ASN1HEX.isASN1HEX(hex) && !hex.startsWith('2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494'))) {
    throw new errors.CertificateError('The certificate is not valid.');
    return this;
  }

  if (hex.startsWith('2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494')) {
    pem = jsrsasign.hextorstr(hex);
  } else {
    pem = jsrsasign.asn1.ASN1Util.getPEMStringFromHex(hex, 'CERTIFICATE');
  }

  certificate.readCertPEM(pem);
  ({
    hex
  } = certificate);
  subject = certificate.getSubjectObject();

  this.toBinaryString = () => binaryString;

  this.toHex = () => certificate.hex;
  this.toPem = () => pem;

  this.getX509 = () => certificate;

  this.getSerialNumberHex = () => certificate.getSerialNumberHex();
  this.getSerialNumber = function() {
    return common.hextoAscii(this.getSerialNumberHex());
  };

  this.getSubject = () => subject;
  this.email = () => subject.emailAddress;
  this.owner = () => subject.name;
  this.owner_id = function() {
    const identifier = this.getUniqueIdentifier();
    return identifier[0];
  };

  this.getUniqueIdentifier = function() {
    if (subject.UI) { return subject.UI.split(' / '); } else { return null; }
  };

  this.getRSAPublicKey = () => pubKey = pubKey === null ? certificate.subjectPublicKeyRSA : pubKey;

  this.verifyString = function(string, signedHexString, alg) {
    try {
      if (alg == null) { alg = 'SHA256withRSA'; }
      const sig = new jsrsasign.crypto.Signature({alg});
      sig.init(pem);
      sig.updateString(string);
      return sig.verify(signedHexString);
    } catch (error) {
      return false;
    }
  };

  this.verifyHexString = function(hexString, signedHexString, alg) {
    try {
      if (alg == null) { alg = 'SHA256withRSA'; }
      const sig = new jsrsasign.crypto.Signature({alg});
      sig.init(pem);
      sig.updateHex(hexString);
      return sig.verify(signedHexString);
    } catch (error) {
      return false;
    }
  };

  this.getUniqueIdentifierString = function(joinVal) {
    joinVal = joinVal ? joinVal : ', ';
    const identifiers = this.getUniqueIdentifier();
    return identifiers.join(joinVal);
  };

  const parseDate = function(certDate) {
    const parsed = certDate.match(/(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/);
    parsed.shift(1);
    return new Date(Date.UTC(2000 + parseInt(parsed[0]), parsed[1], parsed[2], parsed[3], parsed[4], parsed[5]));
  };

  this.hasExpired = function() {
    const notAfter = parseDate(certificate.getNotAfter());
    return notAfter.getTime() < new Date().getTime();
  };

  this.isValidOn = function(date){
    const notAfter = parseDate(certificate.getNotAfter());
    const notBefore = parseDate(certificate.getNotBefore());
    return (notAfter.getTime() >= date.getTime()) && (date.getTime() >= notBefore.getTime());
  };

  this.algorithm = () => certificate.getSignatureAlgorithmField();

  this.tbsCertificate = () => // 1st child of SEQ is tbsCert
  jsrsasign.ASN1HEX.getDecendantHexTLVByNthList(hex, 0, [0]);

  this.signature = () => jsrsasign.X509.getSignatureValueHex(hex);

  this.isCa = function(rootCa) {
    try {
      let rootCaCert = new jsrsasign.X509();
      rootCaCert.readCertPEM(rootCa);
      const rootCaIsCa = jsrsasign.X509.getExtBasicConstraints(rootCaCert.hex).cA;
      // root certificate provided is not CA
      if (!rootCaIsCa) { return false; }
      rootCaCert = new Certificate(false, rootCaCert.hex);

      return rootCaCert.verifyHexString(this.tbsCertificate(), this.signature() , this.algorithm());
    } catch (err) {
      return false;
    }
  };
};

module.exports = Certificate;
