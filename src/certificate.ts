import { CertificateError } from './errors';
import { hextoAscii } from './common';

const parseDate = function(certDate) {
  const parsed = certDate.match(/(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/);
  parsed.shift(1);
  return new Date(Date.UTC(2000 + parseInt(parsed[0]), parseInt(parsed[1]) - 1, parsed[2], parsed[3], parsed[4], parsed[5]));
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
  binaryString: string;
  pem: string;
  certificate: any; // jsrsasign.X509;
  subject: any;
  hex: string;
  pubKey: any;

  constructor(binaryString: string | null, hexString?: string) {
    let hex = binaryString ? jsrsasign.rstrtohex(binaryString) : hexString;

    this.binaryString = binaryString;

    if (
      (!binaryString && !hex) ||
      (binaryString && binaryString.length === 0) ||
      (hex &&
        !jsrsasign.ASN1HEX.isASN1HEX(hex) &&
        !hex.startsWith(certFirstBytes))
    ) {
      throw new CertificateError("The certificate is not valid.");
    }

    if (hex.startsWith(certFirstBytes)) {
      this.pem = jsrsasign.hextorstr(hex);
    } else {
      this.pem = jsrsasign.asn1.ASN1Util.getPEMStringFromHex(
        hex,
        "CERTIFICATE"
      );
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
    return identifier?.[0];
  }

  getUniqueIdentifier() {
    if (this.subject.UI) {
      return this.subject.UI.split(" / ");
    } else {
      return null;
    }
  }

  getRSAPublicKey() {
    if (this.pubKey) {
      return this.pubKey;
    }
    return (this.pubKey = this.certificate.subjectPublicKeyRSA);
  }

  verifyString(string: string, signedHexString: string, alg?: string) {
    try {
      if (alg == null) {
        alg = "SHA256withRSA";
      }
      const sig = new jsrsasign.crypto.Signature({ alg });
      sig.init(this.pem);
      sig.updateString(string);
      const isValid = sig.verify(signedHexString);
      if (!isValid) {
        console.error("Certificate: String verification failed");
      }
      return isValid;
    } catch (error) {
      console.error(error);
      return false;
    }
  }

  verifyHexString(hexString: string, signedHexString: string, alg?: string) {
    try {
      if (alg == null) {
        alg = "SHA256withRSA";
      }
      const sig = new jsrsasign.crypto.Signature({ alg });
      sig.init(this.pem);
      sig.updateHex(hexString);
      const isValid = sig.verify(signedHexString);
      if (!isValid) {
        console.error("Certificate: Hex string verification failed");
      }
      return isValid;
    } catch (error) {
      console.error(error);
      return false;
    }
  }

  getUniqueIdentifierString(joinVal) {
    joinVal = joinVal ? joinVal : ", ";
    const identifiers = this.getUniqueIdentifier();
    return identifiers.join(joinVal);
  }

  hasExpired() {
    const notAfter = parseDate(this.certificate.getNotAfter());
    const isExpired = notAfter.getTime() < new Date().getTime();

    if (isExpired) {
      console.error({
        message: "Certificate: The certificate has expired",
        details: {
          notAfter: notAfter.toISOString(),
          currentTime: new Date().toISOString()
        }
      });
    }

    return isExpired;
  }

  isValidOn(date) {
    const notAfter = parseDate(this.certificate.getNotAfter());
    const notBefore = parseDate(this.certificate.getNotBefore());

    const isValid = (
      notAfter.getTime() >= date.getTime() &&
      date.getTime() >= notBefore.getTime()
    );

    if (!isValid) {
      console.error({
        message: "Certificate: The certificate is not valid on the given date",
        details: {
          notAfter: notAfter.toISOString(),
          notBefore: notBefore.toISOString(),
          givenDate: date.toISOString()
        }
      });
    }

    return isValid;
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

  isCa(rootCaHex) {
  const isCa = this.hex === rootCaHex;

  if (!isCa) {
    console.error({
      message: "Certificate: The certificate is not a CA certificate",
      details: {
        certificateHex: this.hex,
        rootCaHex: rootCaHex
      }
    });
  }

  return isCa;
  }

  validParent(rootCaPem, rootCaHex = null) {
    try {
      let rootCaCert;
      if (rootCaHex) {
        rootCaCert = new Certificate(null, rootCaHex);
      } else {
        rootCaCert = new jsrsasign.X509();
        rootCaCert.readCertPEM(rootCaPem);
        const rootCa = jsrsasign.X509.getExtBasicConstraints(
          rootCaCert.hex
        ).cA;

        if (!rootCa) {
          console.error(
            "Certificate: The certificate is not a child of the provided CA certificate"
          );
          return false;
        }
        rootCaCert = new Certificate(null, rootCaCert.hex);
      }

      const isValid = rootCaCert.verifyHexString(
        this.tbsCertificate(),
        this.signature(),
        this.algorithm()
      );

      if (!isValid) {
        console.error(
          "Certificate: The certificate is not a child of the provided CA certificate"
        );
      }

      return isValid;
    } catch (error) {
      console.error(error);
      return false;
    }
  }
};
