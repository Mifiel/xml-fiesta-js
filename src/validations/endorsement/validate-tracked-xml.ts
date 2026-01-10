import { RootCertificate, TrackedValidationResult } from "../types";
import { validateDocument } from "../standard/validate-document";
import { validateSignatures } from "../standard/validate-signatures";
import { ParsedInstanceLike } from "../validate";

export const validateTrackedXml = async (
  instance: ParsedInstanceLike,
  rootCertificates: RootCertificate[]
): Promise<TrackedValidationResult> => {
  const { document } = instance;

  const signaturesValidation = validateSignatures(document, rootCertificates);
  const assetValidation = document.isValidAssetId(rootCertificates);
  const showLimitData =
    document.isSimpleTrackedDocument(rootCertificates) &&
    signaturesValidation.length === 0;

  const documentValidation = await validateDocument({
    document,
    xmlOriginalHash: instance.xmlOriginalHash,
  });

  if (showLimitData) {
    const oHashValid = instance.xmlOriginalHash === document.originalHash;
    const isValid =
      !documentValidation.metadata.encrypted && assetValidation.isValid;

    return {
      isValid,
      showLimitData: true,
      oHashValid,
      asset: assetValidation,
      document: documentValidation,
      signatures: [],
    };
  }

  const hashInTracked = document.isValidHashInTrackedDocument(rootCertificates);
  const oHashValid =
    instance.xmlOriginalHash === document.originalHash && hashInTracked.isValid;

  const signaturesAreValid = signaturesValidation.every(
    ({ isValid }) => isValid
  );

  const isValid =
    !documentValidation.metadata.encrypted &&
    oHashValid &&
    documentValidation.isValid &&
    assetValidation.isValid &&
    signaturesAreValid;

  return {
    isValid,
    showLimitData: false,
    oHashValid,
    asset: assetValidation,
    document: documentValidation,
    signatures: signaturesValidation,
  };
};
