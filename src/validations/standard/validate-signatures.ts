import { RootCertificate, SignatureValidationResult } from "../types";
import Document from "../../document";
import Signature from "../../signature";
import { validateOcspTimes } from "../../ocsp";

export const validateSignatures = (
  document: Document,
  rootCertificates: RootCertificate[]
): SignatureValidationResult[] => {
  const signatures: Signature[] = document.signatures();
  const signerRecords: any[] = document.signers || [];

  return signatures.map((signature, index) => {
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

    const ocspProducedAt: string | undefined = signerRecords[index]?.ocspProducedAt;
    const ocsp = validateOcspTimes({
      signerCertHex: signature.certificate.toHex(),
      producedAt: ocspProducedAt,
      signedAt: signature.signedAt,
    });

    return {
      certificateNumber,
      certificateNumberIsValid,
      fielIsValid,
      isValid: certificateNumberIsValid && fielIsValid,
      ocsp,
      metadata: signature,
    };
  });
};
