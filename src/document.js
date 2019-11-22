/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * DS206: Consider reworking classes to avoid initClass
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const Promise = require('promise');
const jsrsasign = require('jsrsasign');

const Signature = require('./signature');
const ConservancyRecord = require('./conservancyRecord');
const ConservancyRecordNom2016 = require('./conservancyRecordNom2016');
const common = require('./common');
const errors = require('./errors');
const XML = require('./xml');

var Document = (function() {
  let VERSION = undefined;
  Document = class Document {
    static initClass() {
      VERSION = '0.0.1';
    }

    constructor(file, options) {
      if (!file) { throw new Error('file is required'); }
      this.pdf_content = file;
      this.signers = [];
      const defaultOpts = {
        version: VERSION,
        signers: []
      };

      this.errors = {};
      options = common.extend(defaultOpts, options);
      this.conservancyRecord = null;
      this.recordPresent = false;
      if (options.conservancyRecord) {
        this.recordPresent = true;
        try {
          if (!options.conservancyRecord.version) {
            this.conservancyRecord = new ConservancyRecord(
              options.conservancyRecord.caCert,
              options.conservancyRecord.userCert,
              options.conservancyRecord.record,
              options.conservancyRecord.timestamp,
              options.conservancyRecord.originalXmlHash
            );
          } else {
            this.conservancyRecord = new ConservancyRecordNom2016(
              options.conservancyRecord.caCert,
              options.conservancyRecord.record,
              options.conservancyRecord.timestamp,
              options.conservancyRecord.originalXmlHash
            );
          }

        } catch (e) {
          this.errors.recordInvalid = `The conservancy record is not valid: ${e.message}`;
        }
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
        const doc = this;
        options.signers.forEach(el => doc.add_signer(el));
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
      if (!format) { return common.b64toAscii(this.pdf_content); }
      if (format === 'hex') { return common.b64toHex(this.pdf_content); }
      if (format === 'base64') { return this.pdf_content; }
      throw new errors.ArgumentError(`unknown format ${format}`);
    }

    // @deprecated
    pdf(format) { return this.file(format); }

    add_signer(signer) {
      if (!signer.cer || !signer.signature || !signer.signedAt) {
        throw new errors.InvalidSignerError(
          'signer must contain cer, signature and signedAt'
        );
      }
      if (this.signer_exist(signer)) {
        throw new errors.DuplicateSignersError(
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
        return resolve({
          document: doc,
          // hash as attribute in the xml
          xmlOriginalHash: xml.originalHash
        });}).catch(error => reject(error)));
    }
  };
  Document.initClass();
  return Document;
})();

module.exports = Document;
