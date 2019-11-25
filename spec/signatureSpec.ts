import Signature from '../src/signature';
import { ArgumentError } from '../src/errors';
import { b64toHex } from '../src/common';

const fs = require('fs');
const expect = require('expect.js');

describe('Signature', function() {
  let cer = null;
  let doneCer = false;
  const sigB64 = 'Ia+HMpJt1SGe0fZ1PQmxUO96slPPnbilb94vB/' +
           'FDZl1iJ/68yeHa4ooftn/HuYqGbAHzCxnCGEYo' +
           'E16yyLMB2U9TKKBpGzEipHkD1AyRF8L07ykH+e' +
           'EuHLgdIcMtSP/2lyoWX5x7Au6JTBdQb5qk8cZM' +
           'Nu43DO2SEnszEouNIiU=';

  const sig = b64toHex(sigB64);

  beforeEach(done => fs.readFile(`${__dirname}/fixtures/FIEL_AAA010101AAA.cer`, function(err, data) {
    if (err) { throw err; }
    cer = data.toString('hex');
    doneCer = true;
    done();
  }));

  describe('cer', () => it('should be defined', function() {
    expect(cer).not.to.be(null);
    expect(cer).not.to.be(undefined);
  }));

  describe('initialize', function() {
    describe('without cer', () => {
      it('should throw error', () => {
        expect(() => new Signature(null, sig, new Date(), null, null)).to.throwException(ArgumentError)
      })
    });

    describe('without signedAt', () => {
      it('should throw error', () => {
        expect(() => new Signature(cer, sig, null, null, null)).to.throwException(ArgumentError)
      })
    });
  });

  describe('without email', () => describe('.email', () => it('should be the email of the certificate', function() {
    const signature = new Signature(cer, sig, new Date(), null, null);
    expect(signature.email).to.be('pruebas@sat.gob.mx');
  })));

  describe('with everything OK', function() {
    let signature = null;
    const date = new Date();
    beforeEach(() => signature = new Signature(cer, sig, date, 'other@email.com', null));

    describe('.sig', function() {
      describe('without params', () => it('should be the same as passed', () => expect(signature.sig()).to.be(sig)));

      describe('with hex', () => it('should be the same as passed', () => expect(signature.sig('hex')).to.be(sig)));

      describe('with base64', () => it('should be the same as passed', () => expect(signature.sig('base64')).to.be(sigB64)));

      describe('with unknwon format', () => it('should throw exception', () => expect(() => signature.sig('blah')).to.throwException(ArgumentError)));
    });

    describe('.certificate', () => it('should not be null', () => expect(signature.certificate).not.to.be(null)));

    describe('.signedAt', () => it('should be the same as passed', () => expect(signature.signedAt).to.be(date)));

    describe('.email', () => it('should be the email provided', () => expect(signature.email).to.be('other@email.com')));

    describe('.signer', () => it('should be valid', function() {
      const {
        signer
      } = signature;
      expect(signer.id).to.be('AAA010101AAA');
      expect(signer.name).to.be('ACCEM SERVICIOS EMPRESARIALES SC');
      expect(signer.email).to.be('other@email.com');
    }));

    describe('.valid', function() {
      describe('with valid hash', () => it('should be true', function() {
        const originalHash = '73c818b60eea60e6c1a1e5688a373c6b8376ca4ea2ff269695fe6eeef134b3c8';
        expect(signature.valid(originalHash)).to.be(true);
      }));

      describe('with invalid hash', () => it('should be true', function() {
        const originalHash = 'some invalid';
        expect(signature.valid(originalHash)).to.be(false);
      }));

      describe('without hash', () => {
        it('should throw exception', () => {
          expect(() => signature.valid()).to.throwException(ArgumentError)
        });
      });
    });
  });
});
