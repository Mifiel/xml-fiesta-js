Document = require '../src/document'
errors = require '../src/errors'
fs = require 'fs'

expect = require('expect.js')

describe 'Document', ->
  signers = [
    {
      email: 'some@gmail.com'
      signature: 'asd'
      cer: 'some-cer'
    }
  ]

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

  describe 'fromXml', ->
    it 'should parse the xml', (done)->
      fs.readFile "#{__dirname}/fixtures/example_signed.xml", (err, xml) ->
        doc = Document.fromXml(xml)
        xmlSigners = doc.signers()
        signer = xmlSigners[0]

        expect(doc).to.be.a Document
        expect(doc.pdf()).not.to.be null
        expect(xmlSigners).not.to.be.empty()
        expect(signer.email).to.be 'some@email.com'
        done()

    describe 'without xml', ->
      it 'should throw an error', ->
        expect ->
          Document.fromXml()
        .to.throwError()
