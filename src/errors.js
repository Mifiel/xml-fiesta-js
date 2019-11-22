const InvalidSignerError = function(message) {
  this.message = message;
  this.stack = (new Error()).stack;
  this.name = 'InvalidSignerError';
};

InvalidSignerError.prototype = Object.create(Error.prototype);

const DuplicateSignersError = function(message) {
  this.message = message;
  this.stack = (new Error()).stack;
  this.name = 'DuplicateSignersError';
};

DuplicateSignersError.prototype = Object.create(Error.prototype);

const CertificateError = function(message) {
  this.message = message;
  this.stack = (new Error()).stack;
  this.name = 'CertificateError';
};

CertificateError.prototype = Object.create(Error.prototype);

const ArgumentError = function(message) {
  this.message = message;
  this.stack = (new Error()).stack;
  this.name = 'ArgumentError';
};

ArgumentError.prototype = Object.create(Error.prototype);

const InvalidRecordError = function(message) {
  this.message = message;
  this.stack = (new Error()).stack;
  this.name = 'InvalidRecordError';
};

InvalidRecordError.prototype = Object.create(Error.prototype);

module.exports = {
  InvalidSignerError,
  DuplicateSignersError,
  CertificateError,
  ArgumentError
};
