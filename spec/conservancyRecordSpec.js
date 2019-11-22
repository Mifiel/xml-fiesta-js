/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const crData = require('./fixtures/conservancy_record.js');
const ConservancyRecord = require('../src/conservancyRecord');
const errors = require('../src/errors');
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
      return expect(conservancyRecord.valid()).to.be(false);
    });

    describe('recordTimestamp', () => it('should be a date', function() {
      const date = conservancyRecord.recordTimestamp();
      return expect(date instanceof Date).to.be(true);
    }));

    describe('validArchiveHash', function() {
      it('should be true', () => expect(conservancyRecord.validArchiveHash()).to.be(true));

      return describe('when the passed hash is incorrect', () => it('should be false', function() {
        conservancyRecord = new ConservancyRecord(
          crData.caCert,
          crData.userCert,
          crData.record,
          crData.timestamp,
          'crData.hash' // bad hash
        );
        return expect(conservancyRecord.validArchiveHash()).to.be(false);
      }));
    });

    describe('archiveSignedHash', () => it('should be the same as the hash', function() {
      const hash = conservancyRecord.archiveSignedHash();
      return expect(hash).to.be(crData.hash);
    }));

    describe('equalTimestamps', function() {
      it('should be true when valid', () => expect(conservancyRecord.equalTimestamps()).to.be(true));

      return it('should be true when invalid', function() {
        conservancyRecord.timestamp = Date.now();
        return expect(conservancyRecord.equalTimestamps()).to.be(false);
      });
    });

    describe('caName', () => it('should be valid', () => expect(conservancyRecord.caName()).to.be('Advantage Security, S. de R.L. de C.V.')));

    return describe('userName', () => it('should be valid', () => expect(conservancyRecord.userName()).to.be('prueba')));
  });

  describe('when caCert is invalid', () => it('should throw an error', () => expect(() => new ConservancyRecord('InvalidCaData', crData.userCert)).to.throwError(errors.ArgumentError)));

  describe('when userCert is invalid', () => it('should throw an error', () => expect(() => new ConservancyRecord(crData.caCert, 'InvalidUserData')).to.throwError(errors.ArgumentError)));

  return describe('when record is invalid', () => it('should throw an error', () => expect(() => new ConservancyRecord(crData.caCert, crData.userCert, 'InvaldRecord')).to.throwError(errors.InvalidRecordError)));
});
