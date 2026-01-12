import { RootCertificate, SignatureValidationResult } from "../types";
import Document from "../../document";
import Signature from "../../signature";

export const validateSignatures = (
  document: Document,
  rootCertificates: RootCertificate[]
): SignatureValidationResult[] => {
  const signatures: Signature[] = document.signatures();

  return signatures.map((signature) => {
    const serialNumberHex =
      signature.certificate.getSerialNumberHex() as string;
    const certificateNumber =
      serialNumberHex.length > 20
        ? signature.certificate.getSerialNumber()
        : serialNumberHex;

    const certificateNumberIsValid = rootCertificates.some((rootCer) =>
      signature.certificate.validParent(null, rootCer.cer_hex)
    );
    const fielIsValid = signature.valid(document.originalHash) as boolean;

    return {
      certificateNumber,
      certificateNumberIsValid,
      fielIsValid,
      isValid: certificateNumberIsValid && fielIsValid,
      metadata: signature,
    };
  });
};
