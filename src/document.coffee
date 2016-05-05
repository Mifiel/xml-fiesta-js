Signature = require './signature'
common = require './common'
errors = require './errors'
crypto = require 'crypto'

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

    @version = options.version
    hash = crypto.createHash('sha256')
    hash.update(@pdfBuffer())
    @originalHash = hash.digest('hex')

    if options.signers.length > 0
      options.signers.forEach (el) ->
        add_signer(el)

  pdfBuffer: ->
    return null unless _pdf
    new Buffer(_pdf, 'base64')

  pdf: ->
    return null unless _pdf
    new Buffer(_pdf, 'base64').toString('utf8')

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

      doc = new Document(pdf, signers: parsedSigners)
    return doc

module.exports = Document
