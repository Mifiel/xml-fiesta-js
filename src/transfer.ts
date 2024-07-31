import Certificate from "./certificate";
import { b64toHex } from "./common";
import Document from "./document";
import { GetTransfersByTxIdResult } from "./services/blockchain/liquid";
import Signature from "./signature";

export default class Transfer extends Document {
  prevAddress: string;
  currentAddress: string;
  dataBlockchain: GetTransfersByTxIdResult;

  constructor(file, options, transferData) {
    super(file, options);

    this.prevAddress = transferData.prevAddress;
    this.currentAddress = transferData.currentAddress;
    this.dataBlockchain = transferData.dataBlockchain;
  }

  validEndorser(rootCertificates) {
    const isValidHolder = this.validateHolderBinding(
      this.prevHolder,
      rootCertificates
    );

    if (!isValidHolder) {
      console.error("Transfer(validate endorser): holder is not valid");
      return {
        isValid: false,
        error_code: "integrity",
      };
    }

    const isConsistentWithBlockchain =
      this.prevAddress === this.dataBlockchain.prevAddress;

    if (!isConsistentWithBlockchain) {
      console.error("Transfer(validate endorser): Endorser address inconsistent with blockchain", {
        prevAddress: this.prevAddress,
        blockchainPrevAddress: this.dataBlockchain.prevAddress
      });
      return {
        isValid: false,
        error_code: "inconsistent_with_blockchain",
      };
    }

    return {
      isValid: true,
    };
  }

  validEndorsee(rootCertificates) {
    const isValidHolder = this.validateHolderBinding(
      this.currentHolder,
      rootCertificates
    );

    if (!isValidHolder) {
      console.error("Transfer(validate endorsee): holder is not valid");
      return {
        isValid: false,
        error_code: "integrity",
      };
    }

    const isConsistentWithBlockchain =
      this.currentAddress === this.dataBlockchain.currentAddress;

    if (!isConsistentWithBlockchain) {
      console.error("Transfer(validate endorsee): Endorsee address inconsistent with blockchain", {
        currentAddress: this.currentAddress,
        blockchainCurrentAddress: this.dataBlockchain.currentAddress
      });
      return {
        isValid: false,
        error_code: "inconsistent_with_blockchain",
      };
    }

    return {
      isValid: true
    };
  }

  validateHolderBinding(holder, rootCertificates) {
    // validate certificate
    // the signature corresponds to one of the certificates
    const certificate = new Certificate(
      null,
      b64toHex(holder.binding[0].certificate[0]._)
    );
    const isCa = rootCertificates.some((rootCer) =>
      certificate.isCa(rootCer.cer_hex)
    );

    // validate signature
    const nodeSignature = holder.binding[0].signature[0];
    const signatureData = {
      signedAt: nodeSignature.$.signedAt,
      signatureHex: b64toHex(nodeSignature._),
    };

    const signatureInstance = new Signature(
      certificate.hex,
      signatureData.signatureHex,
      signatureData.signedAt,
      null,
      null
    );

    const isValidSignature = signatureInstance.valid(nodeSignature.$.plaintext);

    if (!isCa) {
      console.error("Transfer(validate holder binding): Certificate is not a CA");
    }

    if (!isValidSignature) {
      console.error("Transfer(validate holder binding): Signature validation failed");
    }

    return isCa && isValidSignature;
  }
}