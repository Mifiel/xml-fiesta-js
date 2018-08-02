jsrsasign = require 'jsrsasign'
common = require './common'
Certificate = require './certificate'
errors = require './errors'

class ConservancyRecordNom2016

  constructor: (@caCert, @record, @timestamp, @signedHash) ->
    throw new errors.ArgumentError(
      'Conservancy must have record'
    ) unless @record


    @recordHex = common.b64toHex(@record)

    unless jsrsasign.ASN1HEX.isASN1HEX(@recordHex)
      throw new errors.InvalidRecordError('The record provided is invalid')

    @positions = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@recordHex, 0)
    
    try
      @rootCertificate = new Certificate(false,  @rootCertificateHex())
    catch error
      @rootCertificate = null

    try
      @tsaCertificate = new Certificate(false, common.b64toHex(@caCert))
      inCert = new Certificate(false,  @caCertificateHex())
      throw new errors.ArgumentError('Tsa certificates are not equals' ) unless  @tsaCertificate.toHex() == inCert.toHex()
    catch error
      throw error

    return
  
  
  rootCertificateHex: ->
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@certificatesHex(), 0)
    jsrsasign.ASN1HEX.getHexOfTLV_AtObj(@certificatesHex(), ar_pos[1])
  
  caCertificateHex: ->
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@certificatesHex(), 0)
    jsrsasign.ASN1HEX.getHexOfTLV_AtObj(@certificatesHex(), ar_pos[0])

  certificatesHex: ->
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), 0)
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[1])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[0])
    jsrsasign.ASN1HEX.getHexOfTLV_AtObj(@archiveHex(), ar_pos[3])
  
  caName: ->
    return @tsaCertificate.getSubject().O if @tsaCertificate

  
  rootName: ->
    return @rootCertificate.getSubject().O if @rootCertificate

  
  messageDigest: ->
    pkcs9 = @signedAttributesHex()
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, 0)
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[2])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[1])
    jsrsasign.ASN1HEX.getHexOfV_AtObj(pkcs9, ar_pos[0])

  signedTimeStamp: ->
    pkcs9 = @signedAttributesHex()
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, 0)
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[1])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[1])
    date = jsrsasign.ASN1HEX.getHexOfV_AtObj(pkcs9, ar_pos[0])
    common.parseDate(common.hextoAscii(date)) 
  
  signingCertificateV2: ->
    pkcs9 = @signedAttributesHex()
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, 0)
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[3])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[1])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[0])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[0])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(pkcs9, ar_pos[0])
    jsrsasign.ASN1HEX.getHexOfV_AtObj(pkcs9, ar_pos[1])
    
  tSTInfoHex: ->
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), 0)
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[1])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[0])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[2])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[1])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[0])
    jsrsasign.ASN1HEX.getHexOfTLV_AtObj(@archiveHex(), ar_pos[0])

  contentAttributesHex:->
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), 0)
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[1])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[0])
    jsrsasign.ASN1HEX.getHexOfTLV_AtObj(@archiveHex(), ar_pos[4])


  signedAttributesHex: ->
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), 0)
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[1])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[0])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[4])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[0])
    hex = jsrsasign.ASN1HEX.getHexOfTLV_AtObj(@archiveHex(), ar_pos[3])
    hex = '31' + hex.slice(2, hex.length) unless (hex.startsWith('31'))
    

  archiveHex: ->
    jsrsasign.ASN1HEX.getHexOfTLV_AtObj(@recordHex, @positions[1])

  
  archiveSignature: ->
    info = @contentAttributesHex()
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(info, 0)
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(info, ar_pos[0])
    jsrsasign.ASN1HEX.getHexOfV_AtObj(info, ar_pos[5])

  
  archiveSignedHash: ->
    tSTInfo = @tSTInfoHex()
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(tSTInfo, 0)
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(tSTInfo, ar_pos[2])
    jsrsasign.ASN1HEX.getHexOfV_AtObj(tSTInfo, ar_pos[1])
    
  validArchiveHash: ->
    return false unless @signedHash == @archiveSignedHash()
    return false unless @tsaCertificate.isValidOn(@signedTimeStamp())
    return false unless @messageDigest() == common.sha256hex(@tSTInfoHex())
    return false unless @equalTimestamps()
    return false unless @signingCertificateV2()
    @tsaCertificate.verifyHexString(@signedAttributesHex(), @archiveSignature())
    
  
  recordTimestamp: ->
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@tSTInfoHex(), 0)
    date = jsrsasign.ASN1HEX.getHexOfV_AtObj(@tSTInfoHex(), ts_pos[4])
    common.parseDate(common.hextoAscii(date))
  
  equalTimestamps: ->
      Date.parse(@timestamp) == @recordTimestamp().getTime() ==  @signedTimeStamp().getTime()

  
  valid: ->
    return false unless @rootCertificate
    @tsaCertificate.isCa(@rootCertificate.toPem())
    

  isCa: (caPemCert) ->
    @rootCertificate.isCa(caPemCert) if @rootCertificate


module.exports = ConservancyRecordNom2016
