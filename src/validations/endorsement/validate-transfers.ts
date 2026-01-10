import {
  RootCertificate,
  TransferValidationResult,
  TrackedValidationResult,
} from "../types";
import { validateDocument } from "../standard/validate-document";
import { validateSignatures } from "../standard/validate-signatures";
import { ParsedInstanceLike } from "../validate";
import Transfer from "../../transfer";

export const validateTransfers = async (
  instance: ParsedInstanceLike,
  rootCertificates: RootCertificate[]
): Promise<NonNullable<TrackedValidationResult["transfers"]>> => {
  const transfers: Transfer[] = await instance.document.transfers();

  const results: TransferValidationResult[] = [];

  for (const transfer of transfers) {
    const endorserValidation = transfer.validEndorser(rootCertificates);
    const endorseeValidation = transfer.validEndorsee(rootCertificates);

    const signaturesValidation = validateSignatures(transfer, rootCertificates);
    const signaturesAreValid = signaturesValidation.every(
      ({ isValid }) => isValid
    );

    const documentValidation = await validateDocument({
      document: transfer,
      xmlOriginalHash: transfer.xml.originalHash,
    });

    const transferIsValid =
      endorserValidation.isValid &&
      endorseeValidation.isValid &&
      documentValidation.isValid &&
      signaturesAreValid;

    results.push({
      transferIsValid,
      endorser: endorserValidation,
      endorsee: endorseeValidation,
      document: documentValidation,
      signatures: signaturesValidation,
      transfer,
    });
  }

  return results;
};
