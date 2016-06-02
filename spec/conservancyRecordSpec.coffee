crData = require('./fixtures/conservancy_record.js')
ConservancyRecord = require('../src/conservancyRecord')
errors = require('../src/errors')
expect = require('expect.js')
fs = require 'fs'

describe 'ConservancyRecord', ->
  describe 'when valid', ->
    conservancyRecord = null
    beforeEach ->
      conservancyRecord = new ConservancyRecord(
        crData.caCert,
        crData.userCert,
        crData.record,
        crData.timestamp,
        crData.hash
      )

    it 'should be valid', ->
      expect(conservancyRecord.valid()).to.be true

    it 'should be invalid when ca is not passed or incorrect', ->
      conservancyRecord = new ConservancyRecord(
        'crData.caCert',
        crData.userCert,
        crData.record,
        crData.timestamp,
        crData.hash
      )
      expect(conservancyRecord.valid()).to.be false

    describe 'recordTimestamp', ->
      it 'should be a date', ->
        date = conservancyRecord.recordTimestamp()
        expect(date instanceof Date).to.be true

    describe 'validArchiveHash', ->
      it 'should be true', ->
        expect(conservancyRecord.validArchiveHash()).to.be true

      describe 'when the passed hash is incorrect', ->
        it 'should be false', ->
          conservancyRecord = new ConservancyRecord(
            crData.caCert,
            crData.userCert,
            crData.record,
            crData.timestamp,
            'crData.hash' # bad hash
          )
          expect(conservancyRecord.validArchiveHash()).to.be false

    describe 'archiveSignedHash', ->
      it 'should be the same as the hash', ->
        hash = conservancyRecord.archiveSignedHash()
        expect(hash).to.be crData.hash

    describe 'equalTimestamps', ->
      it 'should be true when valid', ->
        expect(conservancyRecord.equalTimestamps()).to.be true

      it 'should be true when invalid', ->
        conservancyRecord.timestamp = Date.now()
        expect(conservancyRecord.equalTimestamps()).to.be false

    describe 'caName', ->
      it 'should be valid', ->
        expect(conservancyRecord.caName()).to.be 'Advantage Security, S. de R.L. de C.V.'

    describe 'userName', ->
      it 'should be valid', ->
        expect(conservancyRecord.userName()).to.be 'prueba'

  describe 'when caCert is invalid', ->
    it 'should throw an error', ->
      expect ->
        new ConservancyRecord('InvalidCaData', crData.userCert)
      .to.throwError(errors.ArgumentError)

  describe 'when userCert is invalid', ->
    it 'should throw an error', ->
      expect ->
        new ConservancyRecord(crData.caCert, 'InvalidUserData')
      .to.throwError(errors.ArgumentError)

  describe 'when record is invalid', ->
    it 'should throw an error', ->
      expect ->
        new ConservancyRecord(crData.caCert, crData.userCert, 'InvaldRecord')
      .to.throwError(errors.InvalidRecordError)
