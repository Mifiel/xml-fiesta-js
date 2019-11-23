import Certificate from './certificate';
import { ArgumentError } from './errors';
import { hextoB64 } from './common';

export default class Signature {
  constructor(cer, signature, signedAt, email) {
    this.signature = signature;
    this.signedAt = signedAt;
    this.email = email;
    if (!this.signedAt) { throw new ArgumentError(
      'Signature must have signedAt'
    ); }
    if (!cer) { throw new ArgumentError(
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
    if (format === 'base64') { return hextoB64(this.signature); }
    throw new ArgumentError(`unknown format ${format}`);
  }

  valid(hash) {
    if (!hash) { throw new ArgumentError('hash is required'); }
    return this.certificate.verifyString(hash, this.signature);
  }
}
