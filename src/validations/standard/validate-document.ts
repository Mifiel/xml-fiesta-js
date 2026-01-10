import ConservancyRecord from "../../conservancyRecord";
import { DocumentValidationResult } from "../types";
import { ParsedInstanceLike } from "../validate";
import ConservancyRecordNom2016 from "../../conservancyRecordNom2016";

const getIsConservancyRecordInstance = (conservancyRecord: any): boolean => {
  return (
    conservancyRecord instanceof ConservancyRecord ||
    conservancyRecord instanceof ConservancyRecordNom2016
  );
};

export const validateDocument = async (
  instance: ParsedInstanceLike
): Promise<DocumentValidationResult> => {
  const { document, xmlOriginalHash } = instance;
  const { conservancyRecord } = document;

  const { originalHash } = document;
  const oHashValid = xmlOriginalHash === originalHash;

  let conservancyRecordPresent = false;
  let timestampsMatch = false;
  let archiveHashValid = false;

  if (
    document.recordPresent &&
    getIsConservancyRecordInstance(conservancyRecord)
  ) {
    conservancyRecordPresent = true;
    timestampsMatch = conservancyRecord.equalTimestamps();
    archiveHashValid = oHashValid && conservancyRecord.validArchiveHash();
  }

  return {
    isValid:
      oHashValid &&
      conservancyRecordPresent &&
      timestampsMatch &&
      archiveHashValid,
    oHashValid,
    conservancyRecordPresent,
    timestampsMatch,
    archiveHashValid,
    metadata: document,
  };
};
