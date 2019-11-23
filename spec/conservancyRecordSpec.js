import crData from './fixtures/conservancy_record.js';
import ConservancyRecord from '../src/conservancyRecord';
import { ArgumentError, InvalidRecordError } from '../src/errors';

const expect = require('expect.js');
const fs = require('fs');

describe('ConservancyRecord', function() {
  describe('when valid', function() {
    let conservancyRecord = null;
    beforeEach(() => conservancyRecord = new ConservancyRecord(
      crData.caCert,
      crData.userCert,
      crData.record,
      crData.timestamp,
      crData.hash
    ));

    it('should be valid', () => expect(conservancyRecord.valid()).to.be(true));

    it('should be invalid when ca is not passed or incorrect', function() {
      conservancyRecord = new ConservancyRecord(
        'crData.caCert',
        crData.userCert,
        crData.record,
        crData.timestamp,
        crData.hash
      );
      expect(conservancyRecord.valid()).to.be(false);
    });

    describe('recordTimestamp', () => it('should be a date', function() {
      const date = conservancyRecord.recordTimestamp();
      expect(date instanceof Date).to.be(true);
    }));

    describe('validArchiveHash', function() {
      it('should be true', () => expect(conservancyRecord.validArchiveHash()).to.be(true));

      describe('when the passed hash is incorrect', () => it('should be false', function() {
        conservancyRecord = new ConservancyRecord(
          crData.caCert,
          crData.userCert,
          crData.record,
          crData.timestamp,
          'crData.hash' // bad hash
        );
        expect(conservancyRecord.validArchiveHash()).to.be(false);
      }));
    });

    describe('archiveSignedHash', () => it('should be the same as the hash', function() {
      const hash = conservancyRecord.archiveSignedHash();
      expect(hash).to.be(crData.hash);
    }));

    describe('equalTimestamps', function() {
      it('should be true when valid', () => expect(conservancyRecord.equalTimestamps()).to.be(true));

      it('should be true when invalid', function() {
        conservancyRecord.timestamp = Date.now();
        expect(conservancyRecord.equalTimestamps()).to.be(false);
      });
    });

    describe('caName', () => it('should be valid', () => expect(conservancyRecord.caName()).to.be('Advantage Security, S. de R.L. de C.V.')));

    describe('userName', () => it('should be valid', () => expect(conservancyRecord.userName()).to.be('prueba')));
  });

  describe('when caCert is invalid', () => {
    it('should be invalid', () => {
      const cr = new ConservancyRecord('InvalidCaData', crData.userCert, crData.record);
      expect(cr.valid()).to.be(false);
    });
  });

  describe.skip('when userCert is invalid', () => {
    it('should be invalid', () => {
      const cr = new ConservancyRecord(crData.caCert, 'InvalidUserData', crData.record);
      expect(cr.valid()).to.be(false);
    });
  });

  describe('when record is invalid', () => {
    it('should throw an error', () => {
      try {
        new ConservancyRecord(crData.caCert, crData.userCert, 'InvaldRecord');
        expect.fail();
      } catch (err) {
        expect(err.name).to.be('InvalidRecordError');
      }
    });
  });
});
