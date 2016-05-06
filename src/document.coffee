Signature = require './signature'
common = require './common'
errors = require './errors'
jsrsasign = require 'jsrsasign'

parseString = require('xml2js').parseString

class Document
  VERSION = '0.0.1'
  _pdf = null
  _signers = null

  constructor: (pdf, options) ->
    throw new Error('pdf is required') unless pdf
    _signers = []
    _pdf = pdf
    defaultOpts =
      version: VERSION
      signers: []

    options = common.extend(defaultOpts, options)
    @name = options.name
    @version = options.version
    hash = new jsrsasign.crypto.MessageDigest({
      alg: 'sha256',
      prov: 'cryptojs'
    })
    @originalHash = hash.digestHex(@pdf('hex'))

    if options.signers.length > 0
      options.signers.forEach (el) ->
        add_signer(el)

  pdfBuffer: ->
    return null unless _pdf
    new Buffer(_pdf, 'base64')

  pdf: (format) ->
    return null unless _pdf
    return common.b64toAscii(_pdf) unless format
    return common.b64toHex(_pdf) if format is 'hex'
    return _pdf if format is 'base64'
    throw new errors.ArgumentError "unknown format #{format}"

  signers: -> _signers

  add_signer = (signer) ->
    if !signer.cer || !signer.signature || !signer.signedAt
      throw new errors.InvalidSignerError(
        'signer must contain cer, signature and signedAt'
      )
    if signer_exist(signer)
      throw new errors.DuplicateSignersError(
        'signer already exists'
      )
    _signers.push(signer)

  signatures: ->
    _signers.map (signer) ->
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

  signer_exist = (signer) ->
    selected = _signers.filter (s) ->
      s.email == signer.email ||
        s.cer == signer.cer ||
        s.signature == signer.signature
    selected.length > 0

  this.fromXml = (xml, validate) ->
    throw new Error('xml is required') unless xml
    doc = null
    options = null
    parseString xml, (err, result) ->
      throw new Error("Unable to parse xml: #{err}") if err
      pdf = result.electronicDocument.pdf[0]._
      pdfAttrs = result.electronicDocument.pdf[0].$
      signers = result.electronicDocument.signers
      parsedSigners = []
      signers.forEach (signer) ->
        signer = signer.signer[0]
        attrs = signer.$
        parsedSigners.push({
          email: attrs.email
          cer: common.b64toHex(signer.certificate[0]._)
          signature: common.b64toHex(signer.signature[0]._)
          signedAt: signer.signature[0].$.signedAt
        })

      options =
        signers: parsedSigners
        version: pdfAttrs.version
        name: pdfAttrs.name
        originalHash: pdfAttrs.originalHash

      doc = new Document(pdf, options)
    return {
      document: doc,
      xmlOriginalHash: options.originalHash
    }

module.exports = Document
