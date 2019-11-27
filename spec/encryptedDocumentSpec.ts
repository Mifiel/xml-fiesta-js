import Document from '../src/document';
import { FromXMLResponse } from '../src/document';
import { hextoB64 } from '../src/common'
import { expect } from 'chai';

const fs = require('fs');

describe('Encrypted Document', () => {
  describe('when everything is ok', () => {
    let doc;
    let result: FromXMLResponse;
    beforeEach(async () => {
      const xml = fs.readFileSync(`${__dirname}/fixtures/example_signed.enc.xml`).toString();
      result = await Document.fromXml(xml);
      doc = result.document;
    });

    it('should be encrypted', () => {
      expect(doc.encrypted).to.be.true;
    });

    it('should have signers with ePass', () => {
      expect(doc.signers[0].ePass.content).not.to.be.null;
      expect(doc.signers[1].ePass.content).not.to.be.null;
    });

    describe('signers ePass()', () => {
      let sig;
      before(() => {
        const signatures = doc.signatures();
        sig = signatures[0];
      })

      it('should be defined', () => {
        expect(sig.ePass()).not.to.be.null;
        expect(sig.ePass('base64')).not.to.be.null;
      });

      it('breaks when bad format', () => {
        expect(() => {
          sig.ePass('bad format')
        }).to.throw('unknown format bad format');
      });
    });

    describe('toXML', () => {
      it('should be fine', () => {
        doc.setFile(hextoB64('1234567890ABCDF'));
        const xml = doc.toXML(result.xmljs);
        expect(xml).not.to.include('encrypted');
      })
    })
  });
})
