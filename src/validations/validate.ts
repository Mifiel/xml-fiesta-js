import { ValidateOptions, ValidateResult } from "./types";
import { validateStandardXml } from "./standard/validate-standard-xml";
import { validateTrackedXml } from "./endorsement/validate-tracked-xml";
import { validateTransfers } from "./endorsement/validate-transfers";
import Document from "../document";
import XML from "../xml";

export type ParsedInstanceLike = {
  xml?: XML;
  document: Document;
  xmlOriginalHash?: string;
};

export const validateParsedXml = async (
  parsed: ParsedInstanceLike,
  options: ValidateOptions
): Promise<ValidateResult> => {
  const { document, xml, xmlOriginalHash } = parsed;

  if (document?.tracked) {
    const tracked = await validateTrackedXml(
      {
        xml,
        document,
        xmlOriginalHash,
      },
      options.rootCertificates
    );

    const shouldValidateTransfers =
      !tracked.showLimitData && document?.network !== "LTC";

    if (shouldValidateTransfers) {
      const transfers = await validateTransfers(
        { document: parsed.document },
        options.rootCertificates
      );
      const transfersAreValid = transfers.every((t) => t.transferIsValid);
      const isValid = tracked.isValid && transfersAreValid;
      return {
        mode: "tracked",
        isValid,
        tracked: {
          ...tracked,
          transfers,
        },
      };
    }

    return {
      mode: "tracked",
      isValid: tracked.isValid,
      tracked,
    };
  }

  const standard = await validateStandardXml(
    {
      document,
      xmlOriginalHash,
    },
    options.rootCertificates
  );

  return {
    mode: "standard",
    isValid: standard.isValid,
    standard,
  };
};
