const Promise = require("promise");
const xmlCrypto = require("xml-crypto");
const select = require("xpath.js");
const Dom = require("xmldom").DOMParser;

import { parseString, Builder, processors } from "xml2js";
import { b64toHex, sha256 } from "./common";
import Certificate from "./certificate";
import PatchedXML from "./patches/xmlPatch";

const ExclusiveCanonicalization =
  xmlCrypto.SignedXml.CanonicalizationAlgorithms[
    "http://www.w3.org/2001/10/xml-exc-c14n#"
  ];

const versionToNumber = (version: string) => {
  // splits the version string using the dots in an array of 3 numbers
  // example: '2.4.1' -> [2, 4, 1]
  const [firstNumber, secondNumber, thirdNumber] = version
    .split(/\./)
    .map((v) => parseInt(v));
  // converts the previous in a number
  // example: [2, 4, 1] -> 241
  return firstNumber * 100 + secondNumber * 10 + thirdNumber;
};

const START_VERSION_WITHOUT_SINGERS_CER = versionToNumber("2.5.0");

export default class XML {
  eDocument: any;
  signed: boolean;
  version: any;
  version_int: any;
  fileElementName: any;
  encrypted: any;
  name: any;
  contentType: any;
  originalHash: any;
  tracked = false;
  destroyed = false;
  nameSpaces = null;

  static parse(string) {
    const xml = new PatchedXML();
    return xml.parse(string);
  }

  static parseByElectronicDocument(electronicDocument) {
    const xml = new PatchedXML();
    return xml.parseByElectronicDocument(electronicDocument);
  }

  static toXML(eDocument: any, file: string) {
    const edoc = JSON.parse(JSON.stringify(eDocument));
    this.removeEncrypedData(edoc);
    edoc.file[0]._ = file;

    const builder = new Builder({
      rootName: "electronicDocument",
      renderOpts: {
        pretty: false,
      },
    });
    return builder.buildObject(edoc);
  }

  static removeEncrypedData(xmljs: any) {
    if (xmljs.file && xmljs.file[0]) {
      delete xmljs.file[0].$.encrypted;
      xmljs.file[0].$.name = xmljs.file[0].$.name.replace(".enc", "");
    }
    xmljs.signers?.[0]?.signer?.forEach(function (signer) {
      delete signer.ePass;
    });
  }

  static removeGeolocation(xmljs: any) {
    xmljs.signers?.[0]?.signer?.forEach(function (signer) {
      if (signer.auditTrail) {
        signer.auditTrail[0].event.forEach(function (event, index) {
          if (event.$.name === "geolocation") {
            delete signer.auditTrail[0].event[index];
          }
        });
      }
    });
  }

  static removeBlockchain(xmljs: any) {
    delete xmljs.blockchain;
  }

  static removeTransfer(xmljs: any) {
    delete xmljs.transfers;
  }

  static detectNamespacePrefix(xmlString: string): string | null {
    // Find the prefix used in the electronicDocument element
    const prefixMatch = xmlString.match(
      /<\s*([A-Za-z_][\w.-]*):electronicDocument\b/
    );
    return prefixMatch ? prefixMatch[1] : null;
  }

  static createAttrNameStripper(xmlString: string) {
    const detectedPrefix = XML.detectNamespacePrefix(xmlString);

    return (name: string) => {
      if (detectedPrefix && name) {
        return name
          .replace(new RegExp(`${detectedPrefix}:`, "g"), "")
          .replace(new RegExp(`:${detectedPrefix}`, "g"), "");
      }
      return name;
    };
  }

  static removeSignersCertificate(xmljs: any) {
    xmljs.signers?.[0]?.signer?.forEach((signer) => {
      delete signer.$.name;
      delete signer.certificate[0]._;
    });
  }

  parseByElectronicDocument(electronicDocument) {
    const el = this;
    if (electronicDocument.blockchain) {
      el.tracked = true;
    }

    el.eDocument = electronicDocument;
    const eDocumentAttrs = el.eDocument.$;
    el.version = eDocumentAttrs.version;
    el.signed = eDocumentAttrs.signed;
    el.version_int = versionToNumber(el.version);

    el.destroyed = eDocumentAttrs.cancel || false;

    if (el.version_int < 100) {
      el.fileElementName = "pdf";
    } else {
      el.fileElementName = "file";
    }

    const pdfAttrs = el.eDocument[el.fileElementName][0].$;
    el.encrypted = pdfAttrs.encrypted;
    el.name = pdfAttrs.name;
    el.contentType = pdfAttrs.contentType;
    el.originalHash = pdfAttrs.originalHash;
    return el;
  }

  parse(xml) {
    const el = this;

    return new Promise((resolve, reject) =>
      parseString(
        xml,
        {
          tagNameProcessors: [processors.stripPrefix],
          attrNameProcessors: [XML.createAttrNameStripper(xml)],
        },
        function (err, { electronicDocument }) {
          if (err) {
            return reject(err);
          }
          // Remove only the xmlns:<detectedPrefix> declarations after parsing
          el.parseByElectronicDocument(electronicDocument);
          return resolve(el);
        }
      )
    );
  }

  canonical(electronicDocumentAttributes = {}) {
    let edoc = JSON.parse(JSON.stringify(this.eDocument));

    if (
      electronicDocumentAttributes &&
      Object.keys(electronicDocumentAttributes).length
    ) {
      Object.entries(electronicDocumentAttributes).map(([key, value]) => {
        if (key.includes("xmlns")) {
          edoc.$[key] = value;
        }
      });
    }

    delete edoc.$.cancel;
    delete edoc.conservancyRecord;

    const xml = this.constructor as typeof XML;
    xml.removeEncrypedData(edoc);
    xml.removeGeolocation(edoc);
    xml.removeBlockchain(edoc);
    xml.removeTransfer(edoc);

    if (this.version_int >= START_VERSION_WITHOUT_SINGERS_CER) {
      xml.removeSignersCertificate(edoc);
    }

    if (this.version_int >= 100) {
      edoc[this.fileElementName][0]._ = "";
    }

    const builder = new Builder({
      rootName: "electronicDocument",
      renderOpts: {
        pretty: false,
      },
    });
    const originalXml = builder.buildObject(edoc);

    const doc = new Dom().parseFromString(originalXml);
    const elem = select(doc, "//*")[0];
    const can = new ExclusiveCanonicalization();
    const canonicalString = can.process(elem).toString();
    // remove windows line-endings
    // fixes an issue when users save the XML in windows
    return canonicalString.replace(/&#xD;/g, "");
  }

  getCanonicalBuffer(electronicDocumentAttributes) {
    return Buffer.from(this.canonical(electronicDocumentAttributes), "utf-8");
  }

  file() {
    return this.eDocument[this.fileElementName][0]._;
  }

  pdf() {
    return this.file();
  }

  xmlSigners() {
    const parsedSigners = [];
    const signers = this.eDocument.signers;
    if (!signers) return;

    signers[0].signer.forEach(function (signer) {
      const attrs = signer.$;
      const cerHex = b64toHex(signer.certificate[0]._);
      const certificate = new Certificate(null, cerHex);

      const xmlSigner: any = {
        name: attrs.name,
        taxId: attrs.id,
        email: attrs.email,
        cer: cerHex,
        signature: b64toHex(signer.signature[0]._),
        signedAt: signer.signature[0].$.signedAt,
        legalEntity: certificate.getUniqueIdentifier().length > 1,
      };
      if (signer.ePass) {
        xmlSigner.ePass = {
          content: b64toHex(signer.ePass[0]._),
          algorithm: signer.ePass[0].$.algorithm,
          iterations: signer.ePass[0].$.iterations,
          keySize: signer.ePass[0].$.keySize,
        };
      }
      return parsedSigners.push(xmlSigner);
    });
    return parsedSigners;
  }

  getConservancyRecord() {
    let crVersion, userCertificate;
    if (!this.eDocument.conservancyRecord) {
      return null;
    }
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
      version: crVersion,
    };
  }
}
