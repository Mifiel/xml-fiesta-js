// const Promise = require('promise');
const jsrsasign = require('jsrsasign');

import Signature from './signature';
import ConservancyRecord from './conservancyRecord';
import ConservancyRecordNom2016 from './conservancyRecordNom2016';
import { extend, b64toAscii, b64toHex } from './common';
import {
  ArgumentError,
  InvalidSignerError,
  InvalidRecordError
} from './errors';
import XML from './xml';

export interface FromXMLResponse {
  document: Document;
  xmljs: any;
  xmlOriginalHash: string;
  xmlHash: string;
  xml: XML;
}

const VERSION = '0.0.1';
export default class Document {
  pdf_content: string;
  signers: any;
  errors: any;
  conservancyRecord: ConservancyRecord | ConservancyRecordNom2016;
  recordPresent: boolean;
  contentType: string;
  name: string;
  version: string;
  encrypted: boolean;
  transfer: boolean;
  originalHash: string;
  originalXmlHash: string;

  constructor(file, options) {
    if (!file) { throw new ArgumentError('file is required'); }
    this.pdf_content = file;
    this.signers = [];
    const defaultOpts = {
      version: VERSION,
      signers: [],
      encrypted: false,
      transfer: false,
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
    this.encrypted = options.encrypted === 'true' || options.encrypted === true;
    this.transfer = options.transfer === "true" || options.transfer === true;
    const digest = new jsrsasign.crypto.MessageDigest({
      alg: 'sha256',
      prov: 'cryptojs'
    });
    this.originalHash = digest.digestHex(this.file('hex'));

    if (options.signers.length > 0) {
      options.signers.forEach(el => this.addSigner(el));
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
    return Buffer.from(this.pdf_content, 'base64');
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

  setFile(file: string) {
    this.pdf_content = file;
  }

  toXML(eDocument) {
    if (!eDocument) throw new ArgumentError('eDocument is required')
    return XML.toXML(eDocument, this.file('base64'));
  }

  // @deprecated
  pdf(format) { return this.file(format); }

  addSigner(signer) {
    if (!signer.cer || !signer.signature || !signer.signedAt) {
      throw new InvalidSignerError(
        'signer must contain cer, signature and signedAt'
      );
    }
    return this.signers.push(signer);
  }

  signatures() {
    return this.signers.map(signer => new Signature(
      signer.cer,
      signer.signature,
      signer.signedAt,
      signer.email,
      signer.ePass,
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

  static async fromXml(xmlString): Promise<FromXMLResponse> {
    return new Promise((resolve, reject) => XML.parse(xmlString).then((xml) => {
        const opts = {
          signers: xml.xmlSigners(),
          version: xml.version,
          name: xml.name,
          encrypted: xml.encrypted,
          contentType: xml.contentType,
          conservancyRecord: xml.getConservancyRecord(),
          transfer: xml.isTransfer,
        };
      const doc = new Document(xml.file(), opts);
      resolve({
        xml,
        document: doc,
        xmljs: xml.eDocument,
        xmlHash: xml.getConservancyRecord() && xml.getConservancyRecord().originalXmlHash,
        // hash as attribute in the xml
        xmlOriginalHash: xml.originalHash,
      });
    }).catch(error => reject(error)));
  }
};
