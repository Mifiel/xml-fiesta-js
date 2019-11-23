import Certificate from './certificate'
import Document from './document'
import Signature from './signature'
import ConservancyRecord from './conservancyRecord'
import ConservancyRecordNom2016 from './conservancyRecordNom2016'
import XML from './xml'
import {
  InvalidSignerError,
  DuplicateSignersError,
  CertificateError,
  ArgumentError,
  InvalidRecordError,
} from './errors'

const errors = {
  InvalidSignerError,
  DuplicateSignersError,
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
  errors,
}
