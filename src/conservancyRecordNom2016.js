/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * DS104: Avoid inline assignments
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const jsrsasign = require('jsrsasign');
const common = require('./common');
const Certificate = require('./certificate');
const errors = require('./errors');

class ConservancyRecordNom2016 {

  constructor(caCert, record, timestamp, signedHash) {
    let error;
    this.caCert = caCert;
    this.record = record;
    this.timestamp = timestamp;
    this.signedHash = signedHash;
    if (!this.record) { throw new errors.ArgumentError(
      'Conservancy must have record'
    ); }

    this.recordHex = common.b64toHex(this.record);

    if (!jsrsasign.ASN1HEX.isASN1HEX(this.recordHex)) {
      throw new errors.InvalidRecordError('The record provided is invalid');
    }

    this.positions = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.recordHex, 0);

    try {
      this.rootCertificate = new Certificate(false,  this.rootCertificateHex());
    } catch (error1) {
      error = error1;
      this.rootCertificate = null;
    }

    try {
      this.tsaCertificate = new Certificate(false, common.b64toHex(this.caCert));
      const inCert = new Certificate(false,  this.caCertificateHex());
      if  (this.tsaCertificate.toHex() !== inCert.toHex()) { throw new errors.ArgumentError('Tsa certificates are not equals' ); }
    } catch (error2) {
      error = error2;
      throw error;
    }

  }

  rootCertificateHex() {
    const ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.certificatesHex(), 0);
    return jsrsasign.ASN1HEX.getHexOfTLV_AtObj(this.certificatesHex(), ar_pos[1]);
  }

  caCertificateHex() {
    const ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.certificatesHex(), 0);
    return jsrsasign.ASN1HEX.getHexOfTLV_AtObj(this.certificatesHex(), ar_pos[0]);
  }

  certificatesHex() {
    let ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), 0);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[1]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[0]);
    return jsrsasign.ASN1HEX.getHexOfTLV_AtObj(this.archiveHex(), ar_pos[3]);
  }

  caName() {
    if (this.tsaCertificate) { return this.tsaCertificate.getSubject().O; }
  }

  rootName() {
    if (this.rootCertificate) { return this.rootCertificate.getSubject().O; }
  }

  messageDigest() {
    const pkcs9 = this.signedAttributesHex();
    let ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, 0);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[2]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[1]);
    return jsrsasign.ASN1HEX.getHexOfV_AtObj(pkcs9, ar_pos[0]);
  }

  signedTimeStamp() {
    const pkcs9 = this.signedAttributesHex();
    let ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, 0);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[1]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[1]);
    const date = jsrsasign.ASN1HEX.getHexOfV_AtObj(pkcs9, ar_pos[0]);
    return common.parseDate(common.hextoAscii(date));
  }

  signingCertificateV2() {
    const pkcs9 = this.signedAttributesHex();
    let ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, 0);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[3]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[1]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[0]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[0]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[0]);
    return jsrsasign.ASN1HEX.getHexOfV_AtObj(pkcs9, ar_pos[1]);
  }

  tSTInfoHex() {
    let ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), 0);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[1]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[0]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[2]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[1]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[0]);
    return jsrsasign.ASN1HEX.getHexOfTLV_AtObj(this.archiveHex(), ar_pos[0]);
  }

  contentAttributesHex() {
    let ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), 0);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[1]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[0]);
    return jsrsasign.ASN1HEX.getHexOfTLV_AtObj(this.archiveHex(), ar_pos[4]);
  }


  signedAttributesHex() {
    let ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), 0);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[1]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[0]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[4]);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.archiveHex(), ar_pos[0]);
    let hex = jsrsasign.ASN1HEX.getHexOfTLV_AtObj(this.archiveHex(), ar_pos[3]);
    if (!hex.startsWith('31')) { return hex = '31' + hex.slice(2, hex.length); }
  }

  archiveHex() {
    return jsrsasign.ASN1HEX.getHexOfTLV_AtObj(this.recordHex, this.positions[1]);
  }

  archiveSignature() {
    const info = this.contentAttributesHex();
    let ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(info, 0);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(info, ar_pos[0]);
    return jsrsasign.ASN1HEX.getHexOfV_AtObj(info, ar_pos[5]);
  }

  archiveSignedHash() {
    const tSTInfo = this.tSTInfoHex();
    let ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(tSTInfo, 0);
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(tSTInfo, ar_pos[2]);
    return jsrsasign.ASN1HEX.getHexOfV_AtObj(tSTInfo, ar_pos[1]);
  }

  validArchiveHash() {
    if (this.signedHash !== this.archiveSignedHash()) { return false; }
    if (!this.tsaCertificate.isValidOn(this.signedTimeStamp())) { return false; }
    if (this.messageDigest() !== common.sha256hex(this.tSTInfoHex())) { return false; }
    if (!this.equalTimestamps()) { return false; }
    if (!this.signingCertificateV2()) { return false; }
    return this.tsaCertificate.verifyHexString(this.signedAttributesHex(), this.archiveSignature());
  }

  recordTimestamp() {
    const ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.tSTInfoHex(), 0);
    const date = jsrsasign.ASN1HEX.getHexOfV_AtObj(this.tSTInfoHex(), ts_pos[4]);
    return common.parseDate(common.hextoAscii(date));
  }

  equalTimestamps() {
    let middle;
    return Date.parse(this.timestamp) === (middle = this.recordTimestamp().getTime()) && middle ===  this.signedTimeStamp().getTime();
  }

  valid() {
    if (!this.rootCertificate) { return false; }
    return this.tsaCertificate.isCa(this.rootCertificate.toPem());
  }

  isCa(caPemCert) {
    if (this.rootCertificate) { return this.rootCertificate.isCa(caPemCert); }
  }
}

module.exports = ConservancyRecordNom2016;
