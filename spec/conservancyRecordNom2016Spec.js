const crData = require('./fixtures/conservancy_record_nom_2016.js');
const expect = require('expect.js');
const fs = require('fs');

import ConservancyRecordNom2016 from '../src/conservancyRecordNom2016';
import { ArgumentError, CertificateError } from '../src/errors';

describe('ConservancyRecordNom2016', function() {
  describe('when valid', function() {
    let conservancyRecordNom2016 = null;
    beforeEach(() => conservancyRecordNom2016 = new ConservancyRecordNom2016(
      crData.caCert,
      crData.record,
      crData.timestamp,
      crData.hash
    ));

    it('should be valid certificates', () => expect(conservancyRecordNom2016.valid()).to.be(true));

    describe('recordTimestamp', () => it('should be a date', function() {
      const date = conservancyRecordNom2016.recordTimestamp();
      expect(date instanceof Date).to.be(true);
    }));

    describe('validArchiveHash', function() {
      it('should be true', () => expect(conservancyRecordNom2016.validArchiveHash()).to.be(true));

      describe('when the passed hash is incorrect', () => it('should be false', function() {
        conservancyRecordNom2016 = new ConservancyRecordNom2016(
          crData.caCert,
          crData.record,
          crData.timestamp,
          'crData.hash' // bad hash
        );
        expect(conservancyRecordNom2016.validArchiveHash()).to.be(false);
      }));
    });

    describe('archiveSignedHash', () => it('should be the same as the hash', function() {
      const hash = conservancyRecordNom2016.archiveSignedHash();
      expect(hash).to.be(crData.hash);
    }));

    describe('equalTimestamps', function() {
      it('should be true when valid', () => expect(conservancyRecordNom2016.equalTimestamps()).to.be(true));

      it('should be true when invalid', function() {
        conservancyRecordNom2016.timestamp = Date.now();
        expect(conservancyRecordNom2016.equalTimestamps()).to.be(false);
      });
    });

    describe('caName', () => it('should be valid', () => expect(conservancyRecordNom2016.caName()).to.be('Advantage Security, S. de R.L. de C.V.')));

    describe('rootName', () => it('should be valid', () => expect(conservancyRecordNom2016.rootName()).to.be('Secretaria de Economia')));
  });

  describe('when caCert is invalid', () => {
    it('should throw an error', () => {
      try {
        new ConservancyRecordNom2016('InvalidCaData', crData.record)
        expect.fail();
      } catch (err) {
        expect(err.name).to.be('CertificateError');
      }
    })
  });

  describe('when caCert is not equal', () => {
    it('should throw an error', () => {
      try {
        new ConservancyRecordNom2016(crData.badCaCert, crData.record)
        expect.fail();
      } catch (err) {
        expect(err.name).to.be('ArgumentError');
      }
    })
  });

  describe('when record is invalid', () => {
    it('should throw an error', () => {
      try {
        new ConservancyRecordNom2016(crData.caCert, 'InvaldRecord')
        expect.fail();
      } catch (err) {
        expect(err.name).to.be('InvalidRecordError');
      }
    })
  });
});

