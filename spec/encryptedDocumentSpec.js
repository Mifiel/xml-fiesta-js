import 'babel-polyfill';

import Signature from '../src/signature';
import Document from '../src/document';
import XML from '../src/xml';
import { InvalidSignerError, ArgumenError } from '../src/errors';
import { b64toHex } from '../src/common';

const fs = require('fs');
const expect = require('expect.js');

describe('Encrypted Document', () => {
  describe('when everything is ok', () => {
    let doc;
    before(async () => {
      const xml = fs.readFileSync(`${__dirname}/fixtures/example_signed.enc.xml`).toString();
      const result = await Document.fromXml(xml);
      doc = result.document;
    });

    it('should be encrypted', () => {
      expect(doc.encrypted).to.be(true);
    });

    it('should have signers with ePass', () => {
      expect(doc.signers[0].ePass.content).not.to.be(null);
      expect(doc.signers[1].ePass.content).not.to.be(null);
    });
  });
})
