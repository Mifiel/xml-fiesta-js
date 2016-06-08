Promise = require('promise')
jsrsasign = require 'jsrsasign'

Signature = require './signature'
ConservancyRecord = require './conservancyRecord'
common = require './common'
errors = require './errors'
XML = require './xml'

class Document
  VERSION = '0.0.1'

  constructor: (file, options) ->
    throw new Error('file is required') unless file
    @pdf_content = file
    @signers = []
    defaultOpts =
      version: VERSION
      signers: []

    @errors = {}
    options = common.extend(defaultOpts, options)
    @conservancyRecord = null
    @recordPresent = false
    if options.conservancyRecord
      @recordPresent = true
      try
        @conservancyRecord = new ConservancyRecord(
          options.conservancyRecord.caCert,
          options.conservancyRecord.userCert,
          options.conservancyRecord.record,
          options.conservancyRecord.timestamp,
          options.conservancyRecord.originalXmlHash
        )
      catch e
        @errors.recordInvalid = "The conservancy record is not valid: #{e.message}"

    @contentType = options.contentType
    @name = options.name
    @version = options.version
    digest = new jsrsasign.crypto.MessageDigest({
      alg: 'sha256',
      prov: 'cryptojs'
    })
    @originalHash = digest.digestHex(@file('hex'))

    if options.signers.length > 0
      doc = this
      options.signers.forEach (el) ->
        doc.add_signer(el)

  fileBuffer: ->
    return null unless @pdf_content
    new Buffer(@pdf_content, 'base64')

  # @deprecated
  pdfBuffer: -> @fileBuffer()

  file: (format) ->
    return null unless @pdf_content
    return common.b64toAscii(@pdf_content) unless format
    return common.b64toHex(@pdf_content) if format is 'hex'
    return @pdf_content if format is 'base64'
    throw new errors.ArgumentError "unknown format #{format}"

  # @deprecated
  pdf: (format) -> @file(format)

  add_signer: (signer) ->
    if !signer.cer || !signer.signature || !signer.signedAt
      throw new errors.InvalidSignerError(
        'signer must contain cer, signature and signedAt'
      )
    if @signer_exist(signer)
      throw new errors.DuplicateSignersError(
        'signer already exists'
      )
    @signers.push(signer)

  signatures: ->
    @signers.map (signer) ->
      new Signature(
        signer.cer,
        signer.signature,
        signer.signedAt
      )

  validSignatures: ->
    return false unless @originalHash
    valid = true
    oHash = @originalHash
    @signatures().forEach (signature) ->
      valid = false if valid && !signature.valid(oHash)
    valid

  signer_exist: (signer) ->
    selected = @signers.filter (s) ->
      s.email == signer.email ||
        s.cer == signer.cer ||
        s.signature == signer.signature
    selected.length > 0

  this.fromXml = (xmlString, validate) ->
    throw new Error('xml is required') unless xmlString
    xml = new XML
    new Promise (resolve, reject) ->
      xml.parse(xmlString).then ->
        opts =
          signers: xml.xmlSigners()
          version: xml.version
          name: xml.name
          contentType: xml.contentType
          conservancyRecord: xml.getConservancyRecord()
        doc = new Document(xml.file(), opts)
        resolve({
          document: doc
          # hash as attribute in the xml
          xmlOriginalHash: xml.originalHash
        })
      .catch (error) ->
        reject(error)

module.exports = Document
