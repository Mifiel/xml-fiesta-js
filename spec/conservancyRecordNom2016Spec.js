/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const crData = require('./fixtures/conservancy_record_nom_2016.js');
const ConservancyRecordNom2016 = require('../src/conservancyRecordNom2016');
const errors = require('../src/errors');
const expect = require('expect.js');
const fs = require('fs');

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
      return expect(date instanceof Date).to.be(true);
    }));

    describe('validArchiveHash', function() {
      it('should be true', () => expect(conservancyRecordNom2016.validArchiveHash()).to.be(true));

      return describe('when the passed hash is incorrect', () => it('should be false', function() {
        conservancyRecordNom2016 = new ConservancyRecordNom2016(
          crData.caCert,
          crData.record,
          crData.timestamp,
          'crData.hash' // bad hash
        );
        return expect(conservancyRecordNom2016.validArchiveHash()).to.be(false);
      }));
    });

    describe('archiveSignedHash', () => it('should be the same as the hash', function() {
      const hash = conservancyRecordNom2016.archiveSignedHash();
      return expect(hash).to.be(crData.hash);
    }));

    describe('equalTimestamps', function() {
      it('should be true when valid', () => expect(conservancyRecordNom2016.equalTimestamps()).to.be(true));

      return it('should be true when invalid', function() {
        conservancyRecordNom2016.timestamp = Date.now();
        return expect(conservancyRecordNom2016.equalTimestamps()).to.be(false);
      });
    });

    describe('caName', () => it('should be valid', () => expect(conservancyRecordNom2016.caName()).to.be('Advantage Security, S. de R.L. de C.V.')));

    return describe('rootName', () => it('should be valid', () => expect(conservancyRecordNom2016.rootName()).to.be('Secretaria de Economia')));
  });

  describe('when caCert is invalid', () => it('should throw an error', () => expect(() => new ConservancyRecordNom2016('InvalidCaData', crData.record)).to.throwError(errors.ArgumentError)));

  describe('when caCert is not equal', () => it('should throw an error', () => expect(() => new ConservancyRecordNom2016(crData.badCaCert, crData.record)).to.throwError(errors.ArgumentError)));

  return describe('when record is invalid', () => it('should throw an error', () => expect(() => new ConservancyRecordNom2016(crData.caCert, 'InvaldRecord')).to.throwError(errors.ArgumentError)));
});

