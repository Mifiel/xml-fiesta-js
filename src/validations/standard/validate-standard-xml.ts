import { RootCertificate, StandardValidationResult } from "../types";
import { validateDocument } from "./validate-document";
import { validateSignatures } from "./validate-signatures";
import { ParsedInstanceLike } from "../validate";

export const validateStandardXml = async (
  instance: ParsedInstanceLike,
  rootCertificates: RootCertificate[]
): Promise<StandardValidationResult> => {
  const documentValidation = await validateDocument(instance);
  const signaturesValidation = validateSignatures(
    instance.document,
    rootCertificates
  );

  const signaturesAreValid = signaturesValidation.every(
    ({ isValid }) => isValid
  );

  const isValid =
    !documentValidation.metadata.encrypted &&
    documentValidation.isValid &&
    signaturesAreValid;

  return {
    isValid,
    document: documentValidation,
    signatures: signaturesValidation,
  };
};
