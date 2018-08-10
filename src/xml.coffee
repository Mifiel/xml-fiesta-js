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
        el.version = eDocumentAttrs.version
        el.signed = eDocumentAttrs.signed
        v = el.version.split(/\./).map (v) -> parseInt(v)
        el.version_int = v[0] * 100 + v[1] * 10 + v[2]

        if el.version_int < 100
          el.fileElementName = 'pdf'
        else
          el.fileElementName = 'file'

        pdfAttrs = el.eDocument[el.fileElementName][0].$
        el.name = pdfAttrs.name
        el.contentType = pdfAttrs.contentType
        el.originalHash = pdfAttrs.originalHash
        resolve(el)

  canonical: ->
    edoc = JSON.parse(JSON.stringify(@eDocument))
    if edoc.conservancyRecord
      delete edoc.conservancyRecord
    if @version_int >= 100
      edoc[@fileElementName][0]._ = ''

    builder = new xml2js.Builder(
      rootName: 'electronicDocument'
      renderOpts:
        pretty: false
    )
    originalXml = builder.buildObject(edoc)

    doc = new Dom().parseFromString(originalXml)
    elem = select(doc, "//*")[0]
    can = new ExclusiveCanonicalization()
    can.process(elem).toString()

  file: ->
    @eDocument[@fileElementName][0]._

  pdf: -> @file()

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
    if !cr.$.version 
      userCertificate = cr.userCertificate[0]._ 
    else 
      crVersion = cr.$.version

    { 
      caCert: cr.caCertificate[0]._
      userCert: userCertificate
      record: cr.record[0]
      timestamp: cr.$.timestamp
      originalXmlHash: common.sha256(@canonical())
      version: crVersion
    }

module.exports = XML
