jsrsasign = require 'jsrsasign'
common = require './common'
Certificate = require './certificate'
errors = require './errors'

class ConservancyRecord

  constructor: (@caCert, @userCert, @record, @timestamp, @signedHash) ->
    try
      @caCertificate = new Certificate(false, common.b64toHex(@caCert))
    catch error
      @caCertificate = null

    try
      @userCertificate = new Certificate(false, common.b64toHex(@userCert))
    catch error
      @userCertificate = null

    @recordHex = common.b64toHex(@record)

    unless jsrsasign.ASN1HEX.isASN1HEX(@recordHex)
      throw new errors.InvalidRecordError('The record provided is invalid')

    @positions = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@recordHex, 0)
    return

  caName: ->
    return @caCertificate.getSubject().O if @caCertificate

  userName: ->
    @userCertificate.getSubject().O if @userCertificate

  timestampHex: ->
    jsrsasign.ASN1HEX.getHexOfTLV_AtObj(@recordHex, @positions[2])

  archiveHex: ->
    jsrsasign.ASN1HEX.getHexOfTLV_AtObj(@recordHex, @positions[1])

  archiveSignature: ->
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), 0)
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[3])
    jsrsasign.ASN1HEX.getHexOfV_AtObj(@archiveHex(), ar_pos[1])

  archiveSignedHash: ->
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), 0)
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[1])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[0])
    ar_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@archiveHex(), ar_pos[1])
    signedHashH = jsrsasign.ASN1HEX.getHexOfV_AtObj(@archiveHex(), ar_pos[1])
    # remove leading 0
    common.hextoAscii(signedHashH.replace(/^[0]+/g, ''))

  validArchiveHash: ->
    return false unless @signedHash == @archiveSignedHash()
    @userCertificate.verifyString(@signedHash, @archiveSignature())

  recordTimestamp: ->
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@timestampHex(), 0)
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@timestampHex(), ts_pos[0])
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@timestampHex(), ts_pos[1])
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@timestampHex(), ts_pos[1])
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@timestampHex(), ts_pos[0])
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@timestampHex(), ts_pos[2])
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@timestampHex(), ts_pos[1])
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@timestampHex(), ts_pos[0])
    ts_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@timestampHex(), ts_pos[0])
    date = jsrsasign.ASN1HEX.getHexOfV_AtObj(@timestampHex(), ts_pos[4])
    common.parseDate(common.hextoAscii(date))

  equalTimestamps: ->
    Date.parse(@timestamp) == @recordTimestamp().getTime()

  signedData: ->
    nameHex = jsrsasign.ASN1HEX.getHexOfTLV_AtObj(@recordHex, @positions[0])

    nameHex + @archiveHex() + @timestampHex()

  signature: ->
    signature_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@recordHex, @positions[3])
    jsrsasign.ASN1HEX.getHexOfV_AtObj(@recordHex, signature_pos[1])

  valid: ->
    return false unless @caCertificate
    @caCertificate.verifyHexString(@signedData(), @signature())

  isCa: (caPemCert) ->
    @caCertificate.isCa(caPemCert) if @caCertificate


module.exports = ConservancyRecord
