export class InvalidSignerError extends Error {
  constructor(...args) {
    super(...args);
    this.name = 'InvalidSignerError';
  }
};

export class CertificateError extends Error {
  constructor(...args) {
    super(...args);
    this.name = 'CertificateError';
  }
};

export class ArgumentError extends Error {
  constructor(...args) {
    super(...args);
    this.name = 'ArgumentError';
  }
};

export class InvalidRecordError extends Error {
  constructor(...args) {
    super(...args);
    this.name = 'InvalidRecordError';
  }
};
