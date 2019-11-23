import Signature from '../src/signature';
import Document from '../src/document';
import { InvalidSignerError, DuplicateSignersError, ArgumenError } from '../src/errors';
import { b64toHex } from '../src/common';

const fs = require('fs');
const expect = require('expect.js');

describe('Document', function() {
  const sig = b64toHex(
    'Ia+HMpJt1SGe0fZ1PQmxUO96slPPnbilb94vB/' +
    'FDZl1iJ/68yeHa4ooftn/HuYqGbAHzCxnCGEYo' +
    'E16yyLMB2U9TKKBpGzEipHkD1AyRF8L07ykH+e' +
    'EuHLgdIcMtSP/2lyoWX5x7Au6JTBdQb5qk8cZM' +
    'Nu43DO2SEnszEouNIiU='
  );
  const signers = [
    {
      email: 'some@gmail.com',
      signature: sig,
      cer: null,
      signedAt: new Date()
    }
  ];

  beforeEach(done => fs.readFile(`${__dirname}/fixtures/FIEL_AAA010101AAA.cer`, function(err, data) {
    if (err) { throw err; }
    signers[0].cer = data.toString('hex');
    const doneCer = true;
    done();
  }));

  describe('initialize', function() {
    describe('without pdf', () => it('should throw and error', () => expect(() => new Document()).to.throwError()));

    describe('without signers', () => it('should be OK', function() {
      const doc = new Document('cGRmLWJhc2U2NC1jb250ZW50');
      expect(doc.signers).to.be.empty();
    }));

    describe('without cer', () => it('should raise error', done => expect(() => new Document(
      'cGRmLWJhc2U2NC1jb250ZW50', {
      signers: [{
        email: signers[0].email,
        signature: signers[0].signature
      }]
    }
    )).to.throwException(function(e) {
      expect(e).to.be.a(InvalidSignerError);
      done();
    })));

    describe('with duplicated signers', () => it('should raise error', () => expect(() => new Document(
      'cGRmLWJhc2U2NC1jb250ZW50',
      {signers: [signers[0], signers[0]]}
    )).to.throwException(e => expect(e).to.be.a(DuplicateSignersError))));
  });

  describe('methods', function() {
    let doc = null;
    beforeEach(() => doc = new Document(
      'cGRmLWJhc2U2NC1jb250ZW50',
      {signers}
    ));

    describe('.pdf', function() {
      it('should be defined', () => expect(doc.pdf).to.be.a('function'));

      it('should be an ascci string', function() {
        const pdf = doc.pdf();
        expect(pdf).to.be('pdf-base64-content');
      });

      describe('with unkown format', () => it('should throw Exception', () => expect(() => doc.pdf('blah')).to.throwException(ArgumenError)));

      describe('with base64 format', () => it('should throw Exception', () => expect(doc.pdf('base64')).to.be('cGRmLWJhc2U2NC1jb250ZW50')));
    });

    describe('.signers', function() {
      it('should be defined', () => expect(doc.signers).to.be.an('array'));

      it('should have signers', () => expect(doc.signers[0].email).to.be(signers[0].email));
    });

    describe('.signatures', function() {
      it('should be defined', () => expect(doc.signatures).to.be.a('function'));

      it('should have Signature objects', () => expect(doc.signatures()[0]).to.be.a(Signature));

      it('should have 1 Signature', () => expect(doc.signatures().length).to.be(1));
    });

    describe('.validSignatures', () => it('should be defined', () => expect(doc.validSignatures).to.be.a('function')));
  });

  describe('fromXml v0.0.1+', function() {
    describe('with valid xml', function() {
      const originalHash = '73c818b60eea60e6c1a1e5688a37' +
                     '3c6b8376ca4ea2ff269695fe6eeef134b3c8';
      let doc = null;
      let parsedOHash = null;
      beforeEach(function(done) {
        const xmlExample = `${__dirname}/fixtures/example_signed_cr.xml`;
        const xml = fs.readFileSync(xmlExample);
        const parsedP = Document.fromXml(xml);
        parsedP.then(function(parsed) {
          doc = parsed.document;
          parsedOHash = parsed.xmlOriginalHash;
          done();
        }
        , function(err) {
          console.log('Error', err.stack);
          done();
        });
      });

      it('should parse the xml', function() {
        const xmlSigners = doc.signers;
        const signer = xmlSigners[0];

        expect(doc).to.be.a(Document);
        expect(doc.pdfBuffer()).not.to.be(null);
        expect(doc.pdf()).not.to.be(null);
        expect(doc.originalHash).to.be(originalHash);
        expect(parsedOHash).to.be(originalHash);
        expect(xmlSigners).not.to.be.empty();
        expect(signer.email).to.be('genmadrid@gmail.com');
      });

      describe('.signatures', function() {
        it('should have Signature objects', () => expect(doc.signatures()[0]).to.be.a(Signature));

        it('should have 1 Signature', () => expect(doc.signatures().length).to.be(1));
      });

      describe('.validSignatures', () => it('should be true', () => expect(doc.validSignatures()).to.be(true)));

      describe('.conservancyRecord.validArchiveHash', () => it('should be true', () => expect(doc.conservancyRecord.validArchiveHash()).to.be(true)));
    });

    describe('without xml', () => it('should throw an error', () => expect(() => Document.fromXml()).to.throwError()));
  });

  describe('fromXml v1.0.0+', function() {
    describe('with valid xml', function() {
      const originalHash = '73c818b60eea60e6c1a1e5688a37' +
                     '3c6b8376ca4ea2ff269695fe6eeef134b3c8';
      let doc = null;
      let parsedOHash = null;
      beforeEach(function(done) {
        const xmlExample = `${__dirname}/fixtures/example_signed_cr-v1.0.0.xml`;
        const xml = fs.readFileSync(xmlExample);
        const parsedP = Document.fromXml(xml);
        parsedP.then(function(parsed) {
          doc = parsed.document;
          parsedOHash = parsed.xmlOriginalHash;
          done();
        }
        , function(err) {
          console.log('Error', err.stack);
          done();
        });
      });

      it('should parse the xml', function() {
        const xmlSigners = doc.signers;
        const signer = xmlSigners[0];

        expect(doc).to.be.a(Document);
        expect(doc.pdfBuffer()).not.to.be(null);
        expect(doc.pdf()).not.to.be(null);
        expect(doc.originalHash).to.be(originalHash);
        expect(parsedOHash).to.be(originalHash);
        expect(xmlSigners).not.to.be.empty();
        expect(signer.email).to.be('genmadrid@gmail.com');
      });

      describe('.signatures', function() {
        it('should have Signature objects', () => expect(doc.signatures()[0]).to.be.a(Signature));

        it('should have 1 Signature', () => expect(doc.signatures().length).to.be(1));
      });

      describe('.validSignatures', () => it('should be true', () => expect(doc.validSignatures()).to.be(true)));

      describe('.conservancyRecord.validArchiveHash', () => it('should be true', () => expect(doc.conservancyRecord.validArchiveHash()).to.be(true)));
    });

    describe('without xml', () => it('should throw an error', () => expect(() => Document.fromXml()).to.throwError()));
  });

  describe('fromXml NOM151-2016', function() {
    describe('with valid xml', function() {
      const originalHash = 'e1899493f5cea98b4aadece50fb0e' +
                     '08f5523a342cb2925dc50ef604c6d9d7357';
      let doc = null;
      let parsedOHash = null;
      beforeEach(function(done) {
        const xmlExample = `${__dirname}/fixtures/NOM151-2016.xml`;
        const xml = fs.readFileSync(xmlExample);
        const parsedP = Document.fromXml(xml);
        parsedP.then(function(parsed) {
          doc = parsed.document;
          parsedOHash = parsed.xmlOriginalHash;
          done();
        }
        , function(err) {
          console.log('Error', err.stack);
          done();
        });
      });

      it('should parse the xml', function() {
        const xmlSigners = doc.signers;
        const signer = xmlSigners[0];

        expect(doc).to.be.a(Document);
        expect(doc.pdfBuffer()).not.to.be(null);
        expect(doc.pdf()).not.to.be(null);
        expect(doc.originalHash).to.be(originalHash);
        expect(parsedOHash).to.be(originalHash);
        expect(xmlSigners).not.to.be.empty();
        expect(signer.email).to.be('genmadrid@gmail.com');
      });

      describe('.signatures', function() {
        it('should have Signature objects', () => expect(doc.signatures()[0]).to.be.a(Signature));

        it('should have 1 Signature', () => expect(doc.signatures().length).to.be(1));
      });

      describe('.validSignatures', () => {
        it('should be true', () => expect(doc.validSignatures()).to.be(true))
      });

      describe('.conservancyRecord.validArchiveHash', () => {
        it('should be true', () => {
          expect(doc.conservancyRecord.validArchiveHash()).to.be(true);
        });
      });
    });

    describe('without xml', () => it('should throw an error', () => expect(() => Document.fromXml()).to.throwError()));
  });
});
