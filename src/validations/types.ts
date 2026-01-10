import Transfer from "../transfer";
import Document from "../document";
import Signature from "../signature";
import { AssetValidation } from "../document";

export type RootCertificate = { cer_hex: string };

export type SignatureValidationResult = {
  certificateNumber: string;
  certificateNumberIsValid: boolean;
  fielIsValid: boolean;
  isValid: boolean;
  metadata: Signature;
};

export type DocumentValidationResult = {
  isValid: boolean;
  /**
   * `xmlOriginalHash` (from the XML attribute) must match the actual file hash.
   */
  oHashValid: boolean;
  conservancyRecordPresent: boolean;
  timestampsMatch: boolean;
  archiveHashValid: boolean;
  metadata: Document;
};

export type StandardValidationResult = {
  isValid: boolean;
  document: DocumentValidationResult;
  signatures: SignatureValidationResult[];
};

export type TransferValidationResult = {
  transferIsValid: boolean;
  transfer: Transfer;
  endorser: AssetValidation;
  endorsee: AssetValidation;
  document: DocumentValidationResult;
  signatures: SignatureValidationResult[];
};

export type TrackedValidationResult = {
  isValid: boolean;
  showLimitData: boolean;
  oHashValid: boolean;
  asset: AssetValidation;
  document: DocumentValidationResult;
  signatures: SignatureValidationResult[];
  transfers?: TransferValidationResult[];
};

export type ValidateOptions = {
  rootCertificates: RootCertificate[];
};

export type ValidateResult =
  | {
      mode: "standard";
      isValid: boolean;
      standard: StandardValidationResult;
    }
  | {
      mode: "tracked";
      isValid: boolean;
      tracked: TrackedValidationResult;
    };
