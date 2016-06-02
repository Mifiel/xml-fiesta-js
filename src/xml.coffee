Promise = require('promise')
xml2js = require('xml2js')
xmlCrypto = require('xml-crypto')
select = require('xpath.js')
Dom = require('xmldom').DOMParser

ExclusiveCanonicalization = xmlCrypto.
                            SignedXml.
                            CanonicalizationAlgorithms['http://www.w3.org/2001/10/xml-exc-c14n#']

common = require './common'

class XML
  parse: (xml) ->
    el = this
    new Promise (resolve, reject) ->
      xml2js.parseString xml, (err, result) ->
        return reject(err) if err
        el.eDocument = result.electronicDocument
        eDocumentAttrs = el.eDocument.$
        pdfAttrs = el.eDocument.pdf[0].$
        el.version = eDocumentAttrs.version
        el.signed = eDocumentAttrs.signed
        el.name = pdfAttrs.name
        el.originalHash = pdfAttrs.originalHash
        resolve(el)

  canonical: ->
    if @eDocument.conservancyRecord
      delete @eDocument.conservancyRecord
    builder = new xml2js.Builder(
      rootName: 'electronicDocument'
      renderOpts:
        pretty: false
    )
    originalXml = builder.buildObject(@eDocument)

    doc = new Dom().parseFromString(originalXml)
    elem = select(doc, "//*")[0]
    can = new ExclusiveCanonicalization()
    can.process(elem).toString()

  pdf: -> @eDocument.pdf[0]._

  xmlSigners: ->
    parsedSigners = []
    signers = @eDocument.signers
    signers[0].signer.forEach (signer) ->
      attrs = signer.$
      parsedSigners.push({
        email: attrs.email
        cer: common.b64toHex(signer.certificate[0]._)
        signature: common.b64toHex(signer.signature[0]._)
        signedAt: signer.signature[0].$.signedAt
      })
    parsedSigners

  getConservancyRecord: ->
    return null unless @eDocument.conservancyRecord
    cr = @eDocument.conservancyRecord[0]
    {
      caCert: cr.caCertificate[0]._
      userCert: cr.userCertificate[0]._
      record: cr.record[0]
      timestamp: cr.$.timestamp
      originalXmlHash: common.sha256(@canonical())
    }

module.exports = XML
