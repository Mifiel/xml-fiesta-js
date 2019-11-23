const fs = require('fs');
const expect = require('expect.js');

import XML from '../src/xml';
import { sha256 } from '../src/common';

describe('XML', function() {
  describe('v0', function() {
    beforeEach(function(done) {
      const xmlExample = `${__dirname}/fixtures/example_signed_cr.xml`;
      const xmlString = fs.readFileSync(xmlExample);
      this.xml = new XML();
      this.xml.parse(xmlString).then(() => done());
    });

    describe('original xml hash', function(done) {
      const originalXmlHash = '3e585f9cc5397f4f3295d6a4' +
                        'd650762e009b5db606e70417e5fb342f0ab07b7c';

      it('should be the sha256 of the XML', function() {
        const calculated = sha256(this.xml.canonical());
        expect(calculated).to.be(originalXmlHash);
      });
    });
  });

  describe('v1', function() {
    beforeEach(function(done) {
      const xmlExample = `${__dirname}/fixtures/example_signed_cr-v1.0.0.xml`;
      const xmlString = fs.readFileSync(xmlExample);
      this.xml = new XML();
      this.xml.parse(xmlString).then(() => done());
    });

    describe('original xml hash', function(done) {
      const originalXmlHash = '5e67870434d6cf3006fd87c6' +
                        '0f58b493e505eac18d4ac48ad671dbb3396b5ca4';

      it('should be the sha256 of the XML', function() {
        const calculated = sha256(this.xml.canonical());
        expect(calculated).to.be(originalXmlHash);
      });
    });
  });
});
