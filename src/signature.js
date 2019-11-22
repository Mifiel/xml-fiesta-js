/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * DS207: Consider shorter variations of null checks
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const Certificate = require('./certificate');
const errors = require('./errors');
const common = require('./common');

class Signature {
  constructor(cer, signature, signedAt, email) {
    this.signature = signature;
    this.signedAt = signedAt;
    this.email = email;
    if (!this.signedAt) { throw new errors.ArgumentError(
      'Signature must have signedAt'
    ); }
    if (!cer) { throw new errors.ArgumentError(
      'Signature must have cer'
    ); }

    this.certificate = new Certificate(false, cer);
    if (this.email == null) { this.email = this.certificate.email(); }

    this.signer = {
      id: this.certificate.owner_id(),
      name: this.certificate.owner(),
      email: this.email
    };
  }

  sig(format) {
    if ((format === 'hex') || !format) { return this.signature; }
    if (format === 'base64') { return common.hextoB64(this.signature); }
    throw new errors.ArgumentError(`unknown format ${format}`);
  }

  valid(hash) {
    if (!hash) { throw new errors.ArgumentError('hash is required'); }
    return this.certificate.verifyString(hash, this.signature);
  }
}

module.exports = Signature;
