import Certificate from './certificate';
import { ArgumentError } from './errors';
import { hextoB64 } from './common';

export default class Signature {
  signature: string;
  ePassInfo: any;
  ePassContent: string;
  signedAt: string;
  email: string;
  certificate: Certificate;
  signer: any;

  constructor(cer, signature, signedAt, email, ePassInfo) {
    this.signature = signature;
    if (!ePassInfo) { ePassInfo = {} }
    const { content, algorithm, iterations, keySize } = ePassInfo;
    this.ePassInfo = { algorithm, iterations, keySize };
    this.ePassContent = content;
    this.signedAt = signedAt;
    this.email = email;
    if (!this.signedAt) { throw new ArgumentError('Signature must have signedAt'); }
    if (!cer) { throw new ArgumentError('Signature must have cer'); }

    this.certificate = new Certificate(null, cer);
    if (this.email == null) { this.email = this.certificate.email(); }

    this.signer = {
      id: this.certificate.owner_id(),
      name: this.certificate.owner(),
      email: this.email,
    };
  }

  ePass(format) {
    if ((format === 'hex') || !format) { return this.ePassContent; }
    if (format === 'base64') { return hextoB64(this.ePassContent); }
    throw new ArgumentError(`unknown format ${format}`);
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
