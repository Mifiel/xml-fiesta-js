const fs = require('fs');
const jsrsasign = require('jsrsasign');
const expect = require('expect.js');
const sinon = require('sinon');
const certificatesAndKeys = require('./certificatesAndKeys');

import { CertificateError } from '../src/errors'
import Certificate from '../src/certificate';

describe('Certificate', function() {
  const fielCertificate = new Certificate(null, certificatesAndKeys.FIELCer);
  const csdCertificate = new Certificate(null, certificatesAndKeys.CSDCer);

  describe('instance', function() {
    describe('when the provided string is not a certificate', function() {
      it('should have an error', () => {
        expect(() => new Certificate('') ).to.throwException(CertificateError);
      });

      it('should have an error', () => {
        expect(() => new Certificate('not a valid certificate string') ).to.throwException(CertificateError);
      });
    });

    describe('when provide a hex string', () => {
      it('should have no errors', () => {
        expect(() => new Certificate(null, certificatesAndKeys.FIELCer)).not.to.throwError;
      });
    });

    describe('toBinaryString', () => it('should be defined', function() {
      expect(csdCertificate.toBinaryString).to.be.a('function');
      // This is because the first parameter was a hex
      // TODO: Test with binary strings as a browser file
      expect(csdCertificate.toBinaryString()).to.be(null);
    }));

    describe('toHex', () => it('should be defined', function() {
      expect(fielCertificate.toHex).to.be.a('function');
      expect(fielCertificate.toHex()).to.be(certificatesAndKeys.FIELCer);
    }));

    describe('getX509', function() {
      it('should be defined', () => expect(fielCertificate.getX509).to.be.a('function'));

      it('should have valid properties', function() {
        expect(fielCertificate.getX509()).to.have.property('subjectPublicKeyRSA');
        expect(fielCertificate.getX509()).to.have.property('hex');
        expect(fielCertificate.getX509()).to.have.property('getIssuerHex');
        expect(fielCertificate.getX509()).to.have.property('getNotAfter');
      });
    });

    describe('getSerialNumberHex', () => it('should not be null', function() {
      const serialHex = '3230303031303030303030323030303031343130';
      expect(fielCertificate.getSerialNumberHex()).to.be(serialHex);
    }));

    describe('getSerialNumberHex', () => it('should not be null', () => expect(fielCertificate.getSerialNumber()).to.be('20001000000200001410')));

    describe('getSubject', function() {
      it('should be defined', () => expect(fielCertificate.getSubject).to.be.a('function'));

      it('should have valid values', function() {
        const subject = fielCertificate.getSubject();
        expect(subject).to.be.a('object');
        expect(subject.CN).to.be('ACCEM SERVICIOS EMPRESARIALES SC');
        expect(subject.name).to.be('ACCEM SERVICIOS EMPRESARIALES SC');
        expect(subject.O).to.be('ACCEM SERVICIOS EMPRESARIALES SC');
        expect(subject.UI).to.be('AAA010101AAA / HEGT7610034S2');
        expect(subject.serialNumber).to.be(' / HEGT761003MDFNSR08');
        expect(subject.emailAddress).to.be('pruebas@sat.gob.mx');
      });
    });

    // TODO: Mock the current date,
    // when the cert actually expires this will break
    describe('hasExpired', function() {
      it('should be defined', () => expect(fielCertificate.hasExpired).to.be.a('function'));

      it('should be true', () => expect(fielCertificate.hasExpired()).to.be(true));
    });

    describe('isCa', function() {
      const rootCa = null;
      let intermediate = null;
      let cert = null;
      let certificate = null;
      beforeEach(function() {
        intermediate = fs.readFileSync(`${__dirname}/../docs/AC2_Sat.crt`).toString();
        cert = fs.readFileSync(`${__dirname}/fixtures/production-certificate.cer`);
        certificate = new Certificate(null, cert.toString('hex'));
      });

      describe('when a CA', () => it('should be true', function() {
        const valid = certificate.isCa(intermediate);
        expect(valid).to.be(true);
      }));

      describe('when no a CA', () => it('should be false', function() {
        intermediate = fs.readFileSync(`${__dirname}/../docs/AC1_Sat.crt`).toString();
        expect(certificate.isCa(intermediate)).to.be(false);
      }));

      describe('when CA is not CA', () => it('should be false', function() {
        cert = fs.readFileSync(`${__dirname}/fixtures/production-certificate.pem`);
        expect(certificate.isCa(cert.toString())).to.be(false);
      }));

      describe('when CA is not even a certificate', () => it('should be false', () => expect(certificate.isCa('blahblahpem')).to.be(false)));
    });
  });
});
