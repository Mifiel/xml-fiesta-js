import { expect } from 'chai';
import Document from '../src/document';
import { FromXMLResponse } from '../src/document';
import { hextoB64, sha256 } from '../src/common'
import XML from '../src/xml';

const fs = require('fs');

describe('Encrypted Document', () => {
  describe('when everything is ok', () => {
    let doc;
    let result: FromXMLResponse;
    let xml: XML;

    beforeEach(async () => {
      const xmlEnc = `${__dirname}/fixtures/example_signed.enc.xml`;
      const xmlString = fs.readFileSync(xmlEnc);
      xml = new XML();
      await xml.parse(xmlString);
      
      result = await Document.fromXml(xmlString);
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
        expect(xml).not.to.include('.enc');
        expect(xml).not.to.include('encrypted');
      })
    })

    describe('original xml hash', () => {
      const originalXmlHash = '52d36a70e4d9a0fa1464d19bbd4b2e4d936ec0c680d6f677c9b58d1b5c883551';

      it('should be the sha256 of the XML without geolocation', () => {
        const calculated = sha256(xml.canonical());
        expect(calculated).to.eq(originalXmlHash);
      });
    });
  });
})
