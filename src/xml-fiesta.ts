import Certificate from "./certificate";
import Document from "./document";
import Signature from "./signature";
import ConservancyRecord from "./conservancyRecord";
import ConservancyRecordNom2016 from "./conservancyRecordNom2016";
import XML from "./xml";
import * as validations from "./validations";
import { parseVersion, compareVersions, gteVersion, ltVersion } from "./version";
import {
  extractOcspB64FromSigner,
  extractOcspProducedAt,
  validateOcspTimes,
} from "./ocsp";
import {
  InvalidSignerError,
  CertificateError,
  ArgumentError,
  InvalidRecordError,
} from "./errors";

const version = require("../package.json").version;

const errors = {
  InvalidSignerError,
  CertificateError,
  ArgumentError,
  InvalidRecordError,
};

export {
  Certificate,
  Document,
  Signature,
  ConservancyRecord,
  ConservancyRecordNom2016,
  XML,
  validations,
  parseVersion,
  compareVersions,
  gteVersion,
  ltVersion,
  extractOcspB64FromSigner,
  extractOcspProducedAt,
  validateOcspTimes,
  errors,
  version,
};
