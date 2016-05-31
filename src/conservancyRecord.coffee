jsrsasign = require 'jsrsasign'
common = require './common'
Certificate = require './certificate'
errors = require './errors'

class ConservancyRecord

  constructor: (@caCert, @userCert, @record, @timestamp) ->
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
