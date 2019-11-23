import { CertificateError } from './errors';
import { hextoAscii } from './common';

const parseDate = function(certDate) {
  const parsed = certDate.match(/(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/);
  parsed.shift(1);
  return new Date(Date.UTC(2000 + parseInt(parsed[0]), parsed[1], parsed[2], parsed[3], parsed[4], parsed[5]));
};

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

const certFirstBytes = '2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494';

export default class Certificate {
  constructor(binaryString, hexString) {
    let hex = binaryString ? jsrsasign.rstrtohex(binaryString) : hexString;

    this.binaryString = binaryString;

    if ((binaryString.length === 0) || (!jsrsasign.ASN1HEX.isASN1HEX(hex) && !hex.startsWith(certFirstBytes))) {
      throw new CertificateError('The certificate is not valid.');
    }

    if (hex.startsWith(certFirstBytes)) {
      this.pem = jsrsasign.hextorstr(hex);
    } else {
      this.pem = jsrsasign.asn1.ASN1Util.getPEMStringFromHex(hex, 'CERTIFICATE');
    }

    this.certificate = new jsrsasign.X509();
    this.certificate.readCertPEM(this.pem);
    this.hex = this.certificate.hex;
    this.subject = this.certificate.getSubjectObject();
  }

  toBinaryString() {
    return this.binaryString;
  }

  toHex() {
    return this.certificate.hex;
  }

  toPem() {
    return this.pem;
  }

  getX509() {
    return this.certificate;
  }

  getSerialNumberHex() {
    return this.certificate.getSerialNumberHex();
  }

  getSerialNumber() {
    return hextoAscii(this.getSerialNumberHex());
  }

  getSubject() {
    return this.subject;
  }

  email() {
    return this.subject.emailAddress;
  }

  owner() {
    return this.subject.name;
  }

  owner_id() {
    const identifier = this.getUniqueIdentifier();
    return identifier[0];
  }

  getUniqueIdentifier() {
    if (this.subject.UI) {
      return this.subject.UI.split(' / ');
    } else {
      return null;
    }
  }

  getRSAPublicKey() {
    if (this.pubKey) {
      return this.pubKey;
    }
    return this.pubKey = this.certificate.subjectPublicKeyRSA;
  }

  verifyString(string, signedHexString, alg) {
    try {
      if (alg == null) { alg = 'SHA256withRSA'; }
      const sig = new jsrsasign.crypto.Signature({ alg });
      sig.init(this.pem);
      sig.updateString(string);
      return sig.verify(signedHexString);
    } catch (error) {
      return false;
    }
  }

  verifyHexString(hexString, signedHexString, alg) {
    try {
      if (alg == null) { alg = 'SHA256withRSA'; }
      const sig = new jsrsasign.crypto.Signature({ alg });
      sig.init(this.pem);
      sig.updateHex(hexString);
      return sig.verify(signedHexString);
    } catch (error) {
      return false;
    }
  }

  getUniqueIdentifierString(joinVal) {
    joinVal = joinVal ? joinVal : ', ';
    const identifiers = this.getUniqueIdentifier();
    return identifiers.join(joinVal);
  }

  hasExpired() {
    const notAfter = parseDate(this.certificate.getNotAfter());
    return notAfter.getTime() < new Date().getTime();
  }

  isValidOn(date) {
    const notAfter = parseDate(this.certificate.getNotAfter());
    const notBefore = parseDate(this.certificate.getNotBefore());
    return (notAfter.getTime() >= date.getTime()) && (date.getTime() >= notBefore.getTime());
  }

  algorithm() {
    return this.certificate.getSignatureAlgorithmField();
  }

  tbsCertificate() {
    // 1st child of SEQ is tbsCert
    return jsrsasign.ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0]);
  }

  signature() {
    return jsrsasign.X509.getSignatureValueHex(this.hex);
  }

  isCa(rootCa) {
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
  }
};
