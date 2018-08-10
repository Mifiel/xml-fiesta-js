crData = require('./fixtures/conservancy_record_nom_2016.js')
ConservancyRecordNom2016 = require('../src/conservancyRecordNom2016')
errors = require('../src/errors')
expect = require('expect.js')
fs = require 'fs'

describe 'ConservancyRecordNom2016', ->
  describe 'when valid', ->
    conservancyRecordNom2016 = null
    beforeEach ->
      conservancyRecordNom2016 = new ConservancyRecordNom2016(
        crData.caCert,
        crData.record,
        crData.timestamp,
        crData.hash
      )

    it 'should be valid certificates', ->
      expect(conservancyRecordNom2016.valid()).to.be true

    describe 'recordTimestamp', ->
      it 'should be a date', ->
        date = conservancyRecordNom2016.recordTimestamp()
        expect(date instanceof Date).to.be true

    describe 'validArchiveHash', ->
      it 'should be true', ->
        expect(conservancyRecordNom2016.validArchiveHash()).to.be true

      describe 'when the passed hash is incorrect', ->
        it 'should be false', ->
          conservancyRecordNom2016 = new ConservancyRecordNom2016(
            crData.caCert,
            crData.record,
            crData.timestamp,
            'crData.hash' # bad hash
          )
          expect(conservancyRecordNom2016.validArchiveHash()).to.be false

    describe 'archiveSignedHash', ->
      it 'should be the same as the hash', ->
        hash = conservancyRecordNom2016.archiveSignedHash()
        expect(hash).to.be crData.hash

    describe 'equalTimestamps', ->
      it 'should be true when valid', ->
        expect(conservancyRecordNom2016.equalTimestamps()).to.be true

      it 'should be true when invalid', ->
        conservancyRecordNom2016.timestamp = Date.now()
        expect(conservancyRecordNom2016.equalTimestamps()).to.be false

    describe 'caName', ->
      it 'should be valid', ->
        expect(conservancyRecordNom2016.caName()).to.be 'Advantage Security, S. de R.L. de C.V.'

    describe 'rootName', ->
      it 'should be valid', ->
        expect(conservancyRecordNom2016.rootName()).to.be 'Secretaria de Economia'

  describe 'when caCert is invalid', ->
    it 'should throw an error', ->
      expect ->
        new ConservancyRecordNom2016('InvalidCaData', crData.record)
      .to.throwError(errors.ArgumentError)
  
  describe 'when caCert is not equal', ->
    it 'should throw an error', ->
      expect ->
        new ConservancyRecordNom2016(crData.badCaCert, crData.record)
      .to.throwError(errors.ArgumentError)

  describe 'when record is invalid', ->
    it 'should throw an error', ->
      expect ->
        new ConservancyRecordNom2016(crData.caCert, 'InvaldRecord')
      .to.throwError(errors.ArgumentError)

