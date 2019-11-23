const Promise = require('promise');
const xml2js = require('xml2js');
const xmlCrypto = require('xml-crypto');
const select = require('xpath.js');
const Dom = require('xmldom').DOMParser;

import { b64toHex, sha256 } from './common';

const ExclusiveCanonicalization = xmlCrypto.
                            SignedXml.
                            CanonicalizationAlgorithms['http://www.w3.org/2001/10/xml-exc-c14n#'];

export default class XML {
  parse(xml) {
    const el = this;
    return new Promise((resolve, reject) => xml2js.parseString(xml, function(err, result) {
      if (err) { return reject(err); }
      el.eDocument = result.electronicDocument;
      const eDocumentAttrs = el.eDocument.$;
      el.version = eDocumentAttrs.version;
      el.signed = eDocumentAttrs.signed;
      const v = el.version.split(/\./).map(v => parseInt(v));
      el.version_int = (v[0] * 100) + (v[1] * 10) + v[2];

      if (el.version_int < 100) {
        el.fileElementName = 'pdf';
      } else {
        el.fileElementName = 'file';
      }

      const pdfAttrs = el.eDocument[el.fileElementName][0].$;
      el.name = pdfAttrs.name;
      el.contentType = pdfAttrs.contentType;
      el.originalHash = pdfAttrs.originalHash;
      return resolve(el);
    }));
  }

  canonical() {
    const edoc = JSON.parse(JSON.stringify(this.eDocument));
    if (edoc.conservancyRecord) {
      delete edoc.conservancyRecord;
    }
    if (this.version_int >= 100) {
      edoc[this.fileElementName][0]._ = '';
    }

    const builder = new xml2js.Builder({
      rootName: 'electronicDocument',
      renderOpts: {
        pretty: false
      }
    });
    const originalXml = builder.buildObject(edoc);

    const doc = new Dom().parseFromString(originalXml);
    const elem = select(doc, "//*")[0];
    const can = new ExclusiveCanonicalization();
    return can.process(elem).toString();
  }

  file() {
    return this.eDocument[this.fileElementName][0]._;
  }

  pdf() { return this.file(); }

  xmlSigners() {
    const parsedSigners = [];
    const {
      signers
    } = this.eDocument;
    signers[0].signer.forEach(function(signer) {
      const attrs = signer.$;
      return parsedSigners.push({
        email: attrs.email,
        cer: b64toHex(signer.certificate[0]._),
        signature: b64toHex(signer.signature[0]._),
        signedAt: signer.signature[0].$.signedAt
      });
    });
    return parsedSigners;
  }

  getConservancyRecord() {
    let crVersion, userCertificate;
    if (!this.eDocument.conservancyRecord) { return null; }
    const cr = this.eDocument.conservancyRecord[0];
    if (!cr.$.version) {
      userCertificate = cr.userCertificate[0]._;
    } else {
      crVersion = cr.$.version;
    }

    return {
      caCert: cr.caCertificate[0]._,
      userCert: userCertificate,
      record: cr.record[0],
      timestamp: cr.$.timestamp,
      originalXmlHash: sha256(this.canonical()),
      version: crVersion
    };
  }
}
