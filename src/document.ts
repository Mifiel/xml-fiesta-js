// const Promise = require('promise');
const jsrsasign = require("jsrsasign");

import Signature from "./signature";
import ConservancyRecord from "./conservancyRecord";
import ConservancyRecordNom2016 from "./conservancyRecordNom2016";
import { extend, b64toAscii, b64toHex } from "./common";
import {
  ArgumentError,
  InvalidSignerError,
  InvalidRecordError,
} from "./errors";
import XML from "./patches/xmlPatch";
import { Blockchain, Network } from "./services/blockchain";
import { GetBlockchainTrackResult } from "./services/blockchain/liquid";
import Certificate from "./certificate";

export interface FromXMLResponse {
  document: Document;
  xmljs: any;
  xmlOriginalHash: string;
  xmlHash: string;
  xml: XML;
}

const VERSION = "0.0.1";
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
  transfersXml: any;
  originalHash: string;
  originalXmlHash: string;
  tracked: boolean;
  destroyed: boolean;
  blockchainTrack: GetBlockchainTrackResult;
  blockchainBinding: any;
  currentHolder: any;
  prevHolder: any;
  assetId: string;
  network: Network;
  electronicDocument: any;

  constructor(file, options) {
    if (!file) {
      throw new ArgumentError("file is required");
    }
    this.pdf_content = file;
    this.signers = [];
    const defaultOpts = {
      version: VERSION,
      signers: [],
      encrypted: false,
    };

    this.errors = {};
    options = extend(defaultOpts, options);
    this.conservancyRecord = null;
    this.recordPresent = false;
    if (options.conservancyRecord) {
      this.setConservancyRecord(options.conservancyRecord);
    } else console.error("The conservancy record was not found");

    this.contentType = options.contentType;
    this.name = options.name;
    this.version = options.version;
    this.encrypted = options.encrypted === "true" || options.encrypted === true;
    this.tracked = options.tracked;
    this.destroyed = options.destroyed;
    this.blockchainTrack = options.blockchainTrack;
    this.blockchainBinding = options.blockchainBinding;
    this.transfersXml = options.transfersXml || [];
    this.currentHolder = options.currentHolder;
    this.prevHolder = options.prevHolder;
    this.assetId = options.assetId;
    this.network = options.network;
    this.electronicDocument = options.electronicDocument;
    const digest = new jsrsasign.crypto.MessageDigest({
      alg: "sha256",
      prov: "cryptojs",
    });
    this.originalHash = digest.digestHex(this.file("hex"));

    if (options.signers?.length > 0) {
      options.signers.forEach((el) => this.addSigner(el));
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
      throw new InvalidRecordError(
        `The conservancy record is not valid: ${e.message}`
      );
    }
  }

  fileBuffer() {
    if (!this.pdf_content) {
      return null;
    }
    return Buffer.from(this.pdf_content, "base64");
  }

  // @deprecated
  pdfBuffer() {
    return this.fileBuffer();
  }

  file(format) {
    if (!this.pdf_content) {
      return null;
    }
    if (!format) {
      return b64toAscii(this.pdf_content);
    }
    if (format === "hex") {
      return b64toHex(this.pdf_content);
    }
    if (format === "base64") {
      return this.pdf_content;
    }
    throw new ArgumentError(`unknown format ${format}`);
  }

  setFile(file: string) {
    this.pdf_content = file;
  }

  toXML(eDocument) {
    if (!eDocument) throw new ArgumentError("eDocument is required");
    return XML.toXML(eDocument, this.file("base64"));
  }

  // @deprecated
  pdf(format) {
    return this.file(format);
  }

  addSigner(signer) {
    if (!signer.cer || !signer.signature || !signer.signedAt) {
      throw new InvalidSignerError(
        "signer must contain cer, signature and signedAt"
      );
    }
    return this.signers.push(signer);
  }

  signatures() {
    return this.signers.map(
      (signer) =>
        new Signature(
          signer.cer,
          signer.signature,
          signer.signedAt,
          signer.email,
          signer.ePass,
          signer.name
        )
    );
  }

  validSignatures() {
    if (!this.originalHash) {
      return false;
    }
    let valid = true;
    const oHash = this.originalHash;
    this.signatures().forEach(function (signature) {
      if (valid && !signature.valid(oHash)) {
        return (valid = false);
      }
    });
    return valid;
  }

  async transfers() {
    return await Promise.all(
      this.transfersXml.map(async (transfer, index) => {
        Object.entries(this.electronicDocument.$).map(([key, value]) => {
          if (key.includes("xmlns")) {
            transfer.$[key] = value;
          }
        });

        const xml = XML.parseByElectronicDocument(transfer);
        const prevHolder =
          index === 0
            ? this.currentHolder
            : this.electronicDocument?.transfers?.[0].electronicDocument?.[
                index - 1
              ].blockchain?.[0]?.holder?.[0];

        const opts = await Document.getOptsToInitializeDocument({
          xml,
          prevHolder,
        });

        const prevAddress =
          index === 0
            ? this.currentHolder.binding[0].signature[0].$.plaintext.split(
                "|"
              )[0]
            : this.transfersXml[
                index - 1
              ].blockchain[0].holder[0].binding[0].signature[0].$.plaintext.split(
                "|"
              )[0];

        const currentAddress =
          xml.eDocument.blockchain?.[0]?.holder?.[0]?.binding[0].signature[0].$.plaintext.split(
            "|"
          )[0];

        const transferData = {
          dataBlockchain: this.blockchainTrack?.transfers?.[index] || {},
          prevAddress,
          currentAddress,
        };

        const Transfer = require("./transfer").default;
        return new Transfer(xml, opts, transferData);
      })
    );
  }

  isSimpleTrackedDocument(rootCertificates) {
    if (!this.tracked) throw new Error("Document is not tracked");

    const certificateB64 = this.blockchainBinding.certificate[0]._;
    const certificateHex = b64toHex(certificateB64);
    const certificate = new Certificate(null, certificateHex);
    const isCa = rootCertificates.some((rootCer) =>
      certificate.isCa(rootCer.cer_hex)
    );
    // isCa=true, its a simple tracked document
    return isCa;
  }

  isValidHashInTrackedDocument(rootCertificates) {
    if (!this.tracked) throw new Error("Document is not tracked");

    // platintext positions hash | asset | address
    const plaintext = this.blockchainBinding.signature[0].$.plaintext;
    const originalHashPlaintext = plaintext.split("|")[0];

    const originalHashInBlockchainBindingIsValid =
      this.validHashInBlockchainBinding(rootCertificates, plaintext);

    if (
      !originalHashInBlockchainBindingIsValid ||
      this.originalHash !== originalHashPlaintext
    ) {
      console.error(
        "Document(validate hash in tracked document): invalid hash",
        {
          originalHashInBlockchainBindingIsValid:
            originalHashInBlockchainBindingIsValid,
          providedOriginalHash: this.originalHash,
          originalHashInPlaintext: originalHashPlaintext,
        }
      );
      return {
        isValid: false,
        error_code: "integrity",
      };
    }

    return {
      isValid: true,
    };
  }

  validHashInBlockchainBinding(rootCertificates, hash: string) {
    if (!this.tracked) throw new Error("Document is not tracked");

    // litecoin is not supported, we return true to omit the validation
    if (this.network === "LTC") return true;

    const trackedDocumentIsSimple =
      this.isSimpleTrackedDocument(rootCertificates);

    const cerHex = b64toHex(this.blockchainBinding.certificate[0]._);
    const nodeSignature = this.blockchainBinding.signature[0];
    const signatureData = {
      signedAt: nodeSignature.$.signedAt,
      signatureHex: b64toHex(nodeSignature._),
    };

    if (!trackedDocumentIsSimple) {
      const certificate = new Certificate(null, cerHex);
      const certificateNumberIsValid = rootCertificates.some((rootCer) =>
        certificate.validParent(null, rootCer.cer_hex)
      );

      const certificateIsFromSigner = this.signers.some(
        (signer) => signer.cer === cerHex
      );

      if (!certificateNumberIsValid || !certificateIsFromSigner) {
        console.error(
          "Document(validate hash in blockchain binding): certificate validation failed",
          {
            certificateNumberIsValid: certificateNumberIsValid,
            certificateIsFromSigner: certificateIsFromSigner,
          }
        );
        return false;
      }
    }

    // validate signature
    const signatureInstance = new Signature(
      cerHex,
      signatureData.signatureHex,
      signatureData.signedAt,
      null,
      null
    );

    const isValidSignature = signatureInstance.valid(hash);

    if (!isValidSignature) {
      console.error(
        "Document(validate hash in blockchain binding): signature validation failed"
      );
      return false;
    }

    return true;
  }

  getStatusTrackedDocument(rootCertificates) {
    if (!this.tracked) throw new Error("Document is not tracked");
    if (!this.isValidAssetId(rootCertificates).isValid) return "error";

    let transfersLengthXml = this.transfersXml?.length || 0;
    const transfersLengthBlockchain = this.blockchainTrack.transfers.length;

    if (this.destroyed) {
      transfersLengthXml += 1;
    }

    if (transfersLengthXml === transfersLengthBlockchain) return "updated";
    if (transfersLengthXml < transfersLengthBlockchain) return "not_updated";
  }

  isValidAssetId(rootCertificates) {
    if (!this.tracked) throw new Error("Document is not tracked");

    // plaintext positions hash | asset | address
    const plaintext = this.blockchainBinding.signature[0].$.plaintext;
    const assetPlaintext = plaintext.split("|")[1];

    const assetInBlockchainBindingIsValid = this.validHashInBlockchainBinding(
      rootCertificates,
      plaintext
    );

    if (!assetInBlockchainBindingIsValid || this.assetId !== assetPlaintext) {
      console.error("Asset ID validation failed", {
        assetInBlockchainBindingIsValid,
        providedAssetId: this.assetId,
        assetInPlaintext: assetPlaintext,
      });
      return {
        isValid: false,
        error_code: "integrity",
      };
    }

    if (!this.blockchainTrack) {
      console.error("Blockchain track not found");
      return {
        isValid: false,
        error_code: "not_found",
      };
    }

    return {
      isValid: true,
    };
  }

  static getOptsToInitializeDocument = async ({
    xml,
    prevHolder = null,
    useTestnet = false,
    isOriginalDocument = false,
  }) => {
    const parseStringToBoolean = (string) => string === "true";

    const opts = {
      electronicDocument: xml.eDocument,
      signers: xml.xmlSigners(),
      version: xml.version,
      name: xml.name,
      encrypted: xml.encrypted,
      contentType: xml.contentType,
      conservancyRecord: xml.getConservancyRecord(),
      blockchainTrack: null,
      tracked: xml.tracked,
      destroyed: parseStringToBoolean(xml.destroyed),
      transfersXml: xml.eDocument?.transfers?.[0]?.electronicDocument || null,
      blockchainBinding: xml.eDocument?.blockchain?.[0]?.binding?.[0],
      currentHolder: xml.eDocument?.blockchain?.[0]?.holder?.[0],
      prevHolder: prevHolder,
      assetId: null,
      network: null,
    };

    if (xml.tracked && isOriginalDocument) {
      const assetIdPlaintext =
        xml.eDocument.blockchain[0].binding[0].signature[0].$.plaintext.split(
          "|"
        )[1];

      const network = xml.eDocument.blockchain[0].$.name;

      opts.assetId = assetIdPlaintext;
      opts.network = network;
      try {
        const blockchainInstance = Blockchain.init(network);
        if (useTestnet) blockchainInstance.useTestnet();
        const blockchainTrack = await blockchainInstance.getBlockchainTrack(
          assetIdPlaintext
        );
        opts.blockchainTrack = blockchainTrack;
      } catch (error) {
        console.error(error);
      }
    }

    // litecoin is not supported, we mock a blockchain track so it doesn't fail, this mock will be removed when we no longer support litecoin
    if (opts.network === "LTC") {
      opts.blockchainTrack = {
        transfers: [],
        asset: opts.assetId,
      };
    }

    return opts;
  };

  static async fromXml(
    xmlString,
    useTestnet = false
  ): Promise<FromXMLResponse> {
    return new Promise((resolve, reject) =>
      XML.parse(xmlString)
        .then(async (xml) => {
          const opts = await this.getOptsToInitializeDocument({
            xml,
            useTestnet,
            isOriginalDocument: true,
          });

          const doc = new Document(xml.file(), opts);
          resolve({
            xml,
            document: doc,
            xmljs: xml.eDocument,
            xmlHash:
              xml.getConservancyRecord() &&
              xml.getConservancyRecord().originalXmlHash,
            xmlOriginalHash: xml.originalHash,
          });
        })
        .catch((error) => reject(error))
    );
  }
}
