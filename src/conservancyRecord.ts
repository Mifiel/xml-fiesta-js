import { b64toHex, hextoAscii, parseDate } from './common';
import Certificate from './certificate';
import { InvalidRecordError } from './errors';

const jsrsasign = require('jsrsasign');

export default class ConservancyRecord {
  caCert: string;
  userCert: string;
  record: string;
  timestamp: string;
  signedHash: string;
  caCertificate: Certificate;
  userCertificate: Certificate;
  recordHex: string;
  positions: any;

  constructor(
    caCert: string,
    userCert: string,
    record: string,
    timestamp: string,
    signedHash: string
  ) {
    this.caCert = caCert;
    this.userCert = userCert;
    this.record = record;
    this.timestamp = timestamp;
    this.signedHash = signedHash;
    try {
      this.caCertificate = new Certificate(null, b64toHex(this.caCert));
    } catch (err) {
      this.caCertificate = null;
    }

    try {
      this.userCertificate = new Certificate(null, b64toHex(this.userCert));
    } catch (err) {
      this.userCertificate = null;
    }

    this.recordHex = b64toHex(this.record);
    if (!jsrsasign.ASN1HEX.isASN1HEX(this.recordHex)) {
      throw new InvalidRecordError("The record provided is invalid");
    }

    this.positions = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.recordHex,
      0
    );
  }

  caName() {
    if (this.caCertificate) {
      return this.caCertificate.getSubject().O;
    }
  }

  userName() {
    if (this.userCertificate) {
      return this.userCertificate.getSubject().O;
    }
  }

  timestampHex() {
    return jsrsasign.ASN1HEX.getHexOfTLV_AtObj(
      this.recordHex,
      this.positions[2]
    );
  }

  archiveHex() {
    return jsrsasign.ASN1HEX.getHexOfTLV_AtObj(
      this.recordHex,
      this.positions[1]
    );
  }

  archiveSignature() {
    let ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.archiveHex(),
      0
    );
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.archiveHex(),
      ar_pos[3]
    );
    return jsrsasign.ASN1HEX.getHexOfV_AtObj(this.archiveHex(), ar_pos[1]);
  }

  archiveSignedHash() {
    let ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.archiveHex(),
      0
    );
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.archiveHex(),
      ar_pos[1]
    );
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.archiveHex(),
      ar_pos[0]
    );
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.archiveHex(),
      ar_pos[1]
    );
    const signedHashH = jsrsasign.ASN1HEX.getHexOfV_AtObj(
      this.archiveHex(),
      ar_pos[1]
    );
    // remove leading 0
    return hextoAscii(signedHashH.replace(/^[0]+/g, ""));
  }

  validArchiveHash() {
    if (this.signedHash !== this.archiveSignedHash()) {
      console.error("conservancyRecord: Signed hash mismatch", {
        providedSignedHash: this.signedHash,
        archiveSignedHash: this.archiveSignedHash()
      });
      return false;
    }

    const isValid = this.userCertificate.verifyString(
      this.signedHash,
      this.archiveSignature()
    );
    if (!isValid) {
      console.error("conservancyRecord: User certificate failed to verify the signed hash");
    }

    return isValid;
  }

  recordTimestamp() {
    let ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.timestampHex(),
      0
    );
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.timestampHex(),
      ts_pos[0]
    );
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.timestampHex(),
      ts_pos[1]
    );
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.timestampHex(),
      ts_pos[1]
    );
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.timestampHex(),
      ts_pos[0]
    );
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.timestampHex(),
      ts_pos[2]
    );
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.timestampHex(),
      ts_pos[1]
    );
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.timestampHex(),
      ts_pos[0]
    );
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.timestampHex(),
      ts_pos[0]
    );
    const date = jsrsasign.ASN1HEX.getHexOfV_AtObj(
      this.timestampHex(),
      ts_pos[4]
    );
    return parseDate(hextoAscii(date));
  }

  equalTimestamps() {
    const isEqualTime =
      Date.parse(this.timestamp) === this.recordTimestamp().getTime();

    if (!isEqualTime) {
      console.error("conservancyRecord: Timestamps don't match", {
        providedTimestamp: this.timestamp,
        parsedRecordTimestamp: this.recordTimestamp().toISOString()
      });
    }
    return isEqualTime;
  }

  signedData() {
    const nameHex = jsrsasign.ASN1HEX.getHexOfTLV_AtObj(
      this.recordHex,
      this.positions[0]
    );

    return nameHex + this.archiveHex() + this.timestampHex();
  }

  signature() {
    const signature_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(
      this.recordHex,
      this.positions[3]
    );
    return jsrsasign.ASN1HEX.getHexOfV_AtObj(this.recordHex, signature_pos[1]);
  }

  valid() {
    if (!this.caCertificate) {
      console.error("conservancyRecord: CA certificate is missing");
      return false;
    }

    const isValid = this.caCertificate.verifyHexString(
      this.signedData(),
      this.signature()
    );
    if (!isValid) {
      console.error(
        "conservancyRecord: CA certificate failed to verify the signed data"
      );
    }

    return isValid;
  }

  validParent(caPemCert) {
    if (this.caCertificate) {
      return this.caCertificate.validParent(caPemCert);
    } else {
      console.error({
        message: "conservancyRecord: CA certificate is missing",
      });
    }
  }
}
