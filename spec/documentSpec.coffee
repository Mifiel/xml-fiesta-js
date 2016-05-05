Document = require '../src/document'
Signature = require '../src/signature'
errors = require '../src/errors'
common = require '../src/common'
fs = require 'fs'
crypto = require 'crypto'

expect = require('expect.js')

describe 'Document', ->
  sig = common.b64toHex(
          'Ia+HMpJt1SGe0fZ1PQmxUO96slPPnbilb94vB/' +
          'FDZl1iJ/68yeHa4ooftn/HuYqGbAHzCxnCGEYo' +
          'E16yyLMB2U9TKKBpGzEipHkD1AyRF8L07ykH+e' +
          'EuHLgdIcMtSP/2lyoWX5x7Au6JTBdQb5qk8cZM' +
          'Nu43DO2SEnszEouNIiU='
        )
  signers = [
    {
      email: 'some@gmail.com'
      signature: sig
      cer: null
      signedAt: new Date()
    }
  ]

  beforeEach (done) ->
    fs.readFile "#{__dirname}/fixtures/FIEL_AAA010101AAA.cer", (err, data) ->
      throw err if err
      signers[0].cer = data.toString 'hex'
      doneCer = true
      done()

  describe 'initialize', ->
    describe 'without pdf', ->
      it 'should throw and error', ->
        expect ->
          new Document()
        .to.throwError()

    describe 'without signers', ->
      it 'should be OK', ->
        doc = new Document('cGRmLWJhc2U2NC1jb250ZW50')
        expect(doc.signers()).to.be.empty()

    describe 'without cer', ->
      it 'should raise error', (done) ->
        expect ->
          new Document(
            'cGRmLWJhc2U2NC1jb250ZW50',
            signers: [{
              email: signers[0].email
              signature: signers[0].signature
            }]
          )
        .to.throwException (e) ->
          expect(e).to.be.a(errors.InvalidSignerError)
          done()

    describe 'with duplicated signers', ->
      it 'should raise error', ->
        expect ->
          new Document(
            'cGRmLWJhc2U2NC1jb250ZW50',
            signers: [signers[0], signers[0]]
          )
        .to.throwException (e) ->
          expect(e).to.be.a(errors.DuplicateSignersError)

  describe 'methods', ->
    doc = null
    beforeEach ->
      doc = new Document(
        'cGRmLWJhc2U2NC1jb250ZW50',
        signers: signers
      )

    describe '.pdf', ->
      it 'should be defined', ->
        expect(doc.pdf).to.be.a('function')

      it 'should be an ascci string', ->
        pdf = doc.pdf()
        expect(pdf).to.be 'pdf-base64-content'

    describe '.signers', ->
      it 'should be defined', ->
        expect(doc.signers).to.be.a('function')

      it 'should have signers', ->
        expect(doc.signers()[0].email).to.be signers[0].email

    describe '.signatures', ->
      it 'should be defined', ->
        expect(doc.signatures).to.be.a('function')

      it 'should have Signature objects', ->
        expect(doc.signatures()[0]).to.be.a Signature

      it 'should have 1 Signature', ->
        expect(doc.signatures().length).to.be 1

    describe '.validSignatures', ->
      it 'should be defined', ->
        expect(doc.validSignatures).to.be.a('function')

  describe 'fromXml', ->
    describe 'with valid xml', ->
      originalHash = '73c818b60eea60e6c1a1e5688a373c6b8376ca4ea2ff269695fe6eeef134b3c8'
      doc = null
      beforeEach (done) ->
        fs.readFile "#{__dirname}/fixtures/example_signed.xml", (err, data) ->
          doc = Document.fromXml(data)
          done()

      it 'should parse the xml', ->
        xmlSigners = doc.signers()
        signer = xmlSigners[0]

        expect(doc).to.be.a Document
        expect(doc.pdfBuffer()).not.to.be null
        expect(doc.pdf()).not.to.be null
        expect(doc.originalHash).to.be originalHash
        expect(xmlSigners).not.to.be.empty()
        expect(signer.email).to.be 'some@email.com'

      describe '.signatures', ->
        it 'should have Signature objects', ->
          expect(doc.signatures()[0]).to.be.a Signature

        it 'should have 1 Signature', ->
          expect(doc.signatures().length).to.be 1

      describe '.validSignatures', ->
        it 'should be true', ->
          expect(doc.validSignatures()).to.be true

    describe 'without xml', ->
      it 'should throw an error', ->
        expect ->
          Document.fromXml()
        .to.throwError()
