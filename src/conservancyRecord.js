/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const jsrsasign = require('jsrsasign');
const common = require('./common');
const Certificate = require('./certificate');
const errors = require('./errors');

class ConservancyRecord {

  constructor(caCert, userCert, record, timestamp, signedHash) {
    let error;
    this.caCert = caCert;
    this.userCert = userCert;
    this.record = record;
    this.timestamp = timestamp;
    this.signedHash = signedHash;
    try {
      this.caCertificate = new Certificate(false, common.b64toHex(this.caCert));
    } catch (error1) {
      error = error1;
      this.caCertificate = null;
    }

    try {
      this.userCertificate = new Certificate(false, common.b64toHex(this.userCert));
    } catch (error2) {
      error = error2;
      this.userCertificate = null;
    }

    this.recordHex = common.b64toHex(this.record);

    if (!jsrsasign.ASN1HEX.isASN1HEX(this.recordHex)) {
      throw new errors.InvalidRecordError('The record provided is invalid');
    }

    this.positions = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.recordHex, 0);
  }

  caName() {
    if (this.caCertificate) { return this.caCertificate.getSubject().O; }
  }

  userName() {
    if (this.userCertificate) { return this.userCertificate.getSubject().O; }
  }

  timestampHex() {
    return jsrsasign.ASN1HEX.getHexOfTLV_AtObj(this.recordHex, this.positions[2]);
  }

  archiveHex() {
    return jsrsasign.ASN1HEX.getHexOfTLV_AtObj(this.recordHex, this.positions[1]);
  }

  archiveSignature() {
    let ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), 0);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[3]);
    return jsrsasign.ASN1HEX.getHexOfV_AtObj(this.archiveHex(), ar_pos[1]);
  }

  archiveSignedHash() {
    let ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), 0);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[1]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[0]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[1]);
    const signedHashH = jsrsasign.ASN1HEX.getHexOfV_AtObj(this.archiveHex(), ar_pos[1]);
    // remove leading 0
    return common.hextoAscii(signedHashH.replace(/^[0]+/g, ''));
  }

  validArchiveHash() {
    if (this.signedHash !== this.archiveSignedHash()) { return false; }
    return this.userCertificate.verifyString(this.signedHash, this.archiveSignature());
  }

  recordTimestamp() {
    let ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.timestampHex(), 0);
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.timestampHex(), ts_pos[0]);
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.timestampHex(), ts_pos[1]);
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.timestampHex(), ts_pos[1]);
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.timestampHex(), ts_pos[0]);
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.timestampHex(), ts_pos[2]);
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.timestampHex(), ts_pos[1]);
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.timestampHex(), ts_pos[0]);
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.timestampHex(), ts_pos[0]);
    const date = jsrsasign.ASN1HEX.getHexOfV_AtObj(this.timestampHex(), ts_pos[4]);
    return common.parseDate(common.hextoAscii(date));
  }

  equalTimestamps() {
    return Date.parse(this.timestamp) === this.recordTimestamp().getTime();
  }

  signedData() {
    const nameHex = jsrsasign.ASN1HEX.getHexOfTLV_AtObj(this.recordHex, this.positions[0]);

    return nameHex + this.archiveHex() + this.timestampHex();
  }

  signature() {
    const signature_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.recordHex, this.positions[3]);
    return jsrsasign.ASN1HEX.getHexOfV_AtObj(this.recordHex, signature_pos[1]);
  }

  valid() {
    if (!this.caCertificate) { return false; }
    return this.caCertificate.verifyHexString(this.signedData(), this.signature());
  }

  isCa(caPemCert) {
    if (this.caCertificate) { return this.caCertificate.isCa(caPemCert); }
  }
}


module.exports = ConservancyRecord;
