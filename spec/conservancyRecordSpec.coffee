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
        crData.timestamp
      )

    it 'should be valid', ->
      expect(conservancyRecord.valid()).to.be true

    describe 'recordTimestamp', ->
      it 'should be a date', ->
        date = conservancyRecord.recordTimestamp()
        expect(date instanceof Date).to.be true

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
