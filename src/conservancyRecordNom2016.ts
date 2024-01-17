const jsrsasign = require('jsrsasign');

import {
  b64toHex,
  parseDate,
  hextoAscii,
  sha256hex,
} from './common';
import Certificate from './certificate';
import { ArgumentError, InvalidRecordError } from './errors';

export default class ConservancyRecordNom2016 {
  caCert: string;
  record: string;
  timestamp: any;
  signedHash: string;
  recordHex: string;
  rootCertificate: Certificate;
  tsaCertificate: Certificate;
  private positions: any;

  constructor(caCert: string, record: string, timestamp?: any, signedHash?: string) {
    this.caCert = caCert;
    this.record = record;
    this.timestamp = timestamp;
    this.signedHash = signedHash;
    if (!this.record) { throw new ArgumentError('Conservancy must have record'); }

    this.recordHex = b64toHex(this.record);
    if (!jsrsasign.ASN1HEX.isASN1HEX(this.recordHex)) {
      throw new InvalidRecordError('The record provided is invalid');
    }

    this.positions = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.recordHex, 0);

    try {
      this.rootCertificate = new Certificate(null,  this.rootCertificateHex());
    } catch (err) {
      this.rootCertificate = null;
    }

    this.tsaCertificate = new Certificate(null, b64toHex(this.caCert));
    const inCert = new Certificate(null,  this.caCertificateHex());
    if  (this.tsaCertificate.toHex() !== inCert.toHex()) {
      throw new ArgumentError('Tsa certificates are not equals' );
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
    return parseDate(hextoAscii(date));
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
    if (this.messageDigest() !== sha256hex(this.tSTInfoHex())) { return false; }
    if (!this.equalTimestamps()) { return false; }
    if (!this.signingCertificateV2()) { return false; }
    return this.tsaCertificate.verifyHexString(this.signedAttributesHex(), this.archiveSignature());
  }

  recordTimestamp() {
    const ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(this.tSTInfoHex(), 0);
    const date = jsrsasign.ASN1HEX.getHexOfV_AtObj(this.tSTInfoHex(), ts_pos[4]);
    return parseDate(hextoAscii(date));
  }

  equalTimestamps() {
    let middle;
    return Date.parse(this.timestamp) === (middle = this.recordTimestamp().getTime()) && middle ===  this.signedTimeStamp().getTime();
  }

  valid() {
    if (!this.rootCertificate) { return false; }
    return this.tsaCertificate.validParent(this.rootCertificate.toPem());
  }

  validParent(caPemCert) {
    if (this.rootCertificate) { return this.rootCertificate.validParent(caPemCert); }
  }
}
