import Certificate from "./certificate";
import Document from "./document";
import Signature from "./signature";
import ConservancyRecord from "./conservancyRecord";
import ConservancyRecordNom2016 from "./conservancyRecordNom2016";
import XML from "./xml";
import * as validations from "./validations";
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
  errors,
  version,
};
