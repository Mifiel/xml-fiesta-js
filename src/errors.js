class CustomError extends Error {
  constructor(...args) {
    super(...args);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

export class InvalidSignerError extends CustomError {};

export class DuplicateSignersError extends CustomError {};

export class CertificateError extends CustomError {};

export class ArgumentError extends CustomError {};

export class InvalidRecordError extends CustomError {};
