const Promise = require('promise');
const jsrsasign = require('jsrsasign');

import Signature from './signature';
import ConservancyRecord from './conservancyRecord';
import ConservancyRecordNom2016 from './conservancyRecordNom2016';
import { extend, b64toAscii, b64toHex } from './common';
import {
  ArgumentError,
  InvalidSignerError,
  DuplicateSignersError,
  InvalidRecordError
} from './errors';
import XML from './xml';

const VERSION = '0.0.1';
export default class Document {
  constructor(file, options) {
    if (!file) { throw new Error('file is required'); }
    this.pdf_content = file;
    this.signers = [];
    const defaultOpts = {
      version: VERSION,
      signers: []
    };

    this.errors = {};
    options = extend(defaultOpts, options);
    this.conservancyRecord = null;
    this.recordPresent = false;
    if (options.conservancyRecord) {
      this.setConservancyRecord(options.conservancyRecord)
    }

    this.contentType = options.contentType;
    this.name = options.name;
    this.version = options.version;
    const digest = new jsrsasign.crypto.MessageDigest({
      alg: 'sha256',
      prov: 'cryptojs'
    });
    this.originalHash = digest.digestHex(this.file('hex'));

    if (options.signers.length > 0) {
      options.signers.forEach(el => this.add_signer(el));
    }
  }

  setConservancyRecord(data) {
    this.originalXmlHash = data.originalXmlHash;
    this.recordPresent = true;

    try {
      if (!data.version) {
        this.conservancyRecord = new ConservancyRecord(
          data.caCert,
          data.userCert,
          data.record,
          data.timestamp,
          data.originalXmlHash
        );
      } else {
        this.conservancyRecord = new ConservancyRecordNom2016(
          data.caCert,
          data.record,
          data.timestamp,
          data.originalXmlHash
        );
      }
    } catch (e) {
      throw new InvalidRecordError(`The conservancy record is not valid: ${e.message}`);
    }
  }

  fileBuffer() {
    if (!this.pdf_content) { return null; }
    return new Buffer(this.pdf_content, 'base64');
  }

  // @deprecated
  pdfBuffer() { return this.fileBuffer(); }

  file(format) {
    if (!this.pdf_content) { return null; }
    if (!format) { return b64toAscii(this.pdf_content); }
    if (format === 'hex') { return b64toHex(this.pdf_content); }
    if (format === 'base64') { return this.pdf_content; }
    throw new ArgumentError(`unknown format ${format}`);
  }

  // @deprecated
  pdf(format) { return this.file(format); }

  add_signer(signer) {
    if (!signer.cer || !signer.signature || !signer.signedAt) {
      throw new InvalidSignerError(
        'signer must contain cer, signature and signedAt'
      );
    }
    if (this.signer_exist(signer)) {
      throw new DuplicateSignersError(
        'signer already exists'
      );
    }
    return this.signers.push(signer);
  }

  signatures() {
    return this.signers.map(signer => new Signature(
      signer.cer,
      signer.signature,
      signer.signedAt
    ));
  }

  validSignatures() {
    if (!this.originalHash) { return false; }
    let valid = true;
    const oHash = this.originalHash;
    this.signatures().forEach(function(signature) {
      if (valid && !signature.valid(oHash)) { return valid = false; }
    });
    return valid;
  }

  signer_exist(signer) {
    const selected = this.signers.filter(s => (s.email === signer.email) ||
      (s.cer === signer.cer) ||
      (s.signature === signer.signature));
    return selected.length > 0;
  }

  static fromXml(xmlString, validate) {
    if (!xmlString) { throw new Error('xml is required'); }
    const xml = new XML;
    return new Promise((resolve, reject) => xml.parse(xmlString).then(function() {
      const opts = {
        signers: xml.xmlSigners(),
        version: xml.version,
        name: xml.name,
        contentType: xml.contentType,
        conservancyRecord: xml.getConservancyRecord()
      };
      const doc = new Document(xml.file(), opts);
      resolve({
        document: doc,
        // hash as attribute in the xml
        xmlOriginalHash: xml.originalHash
      });
    }).catch(error => reject(error)));
  }
};
