common = require './common'
errors = require './errors'

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
    if options.signers.length > 0
      options.signers.forEach (el) ->
        add_signer(el)

  pdf: ->
    return null unless _pdf
    new Buffer(_pdf, 'base64').toString('ascii')

  signers: -> _signers

  add_signer = (signer) ->
    if !signer.cer || !signer.signature
      throw new errors.InvalidSignerError(
        'signer must contain at least cer and signature'
      )
    if signer_exist(signer)
      throw new errors.DuplicateSignersError(
        'signer already exists'
      )
    _signers.push(signer)

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
          cer: signer.certificate[0]._
          signature: signer.signature[0]._
        })

      doc = new Document(pdf, signers: parsedSigners)
    return doc

module.exports = Document
