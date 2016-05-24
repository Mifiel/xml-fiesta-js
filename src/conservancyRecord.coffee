jsrsasign = require 'jsrsasign'
common = require './common'
Certificate = require './certificate'
errors = require './errors'

class ConservancyRecord

  constructor: (@caCert, @userCert, @record, @timestamp) ->
    try
      @caCertificate = new Certificate(false, common.b64toHex(@caCert))
    catch error
      throw new errors.ArgumentError("caCert is invalid: #{error}")

    try
      @userCertificate = new Certificate(false, common.b64toHex(@userCert))
    catch error
      throw new errors.ArgumentError('userCert is invalid')

    @recordHex = common.b64toHex(@record)

    unless jsrsasign.ASN1HEX.isASN1HEX(@recordHex)
      throw new errors.InvalidRecordError('The record provided is invalid')

    @positions = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@recordHex, 0)
    return

  caName: ->
    @caCertificate.getSubject().O

  userName: ->
    @userCertificate.getSubject().O

  timestampHex: ->
    jsrsasign.ASN1HEX.getHexOfTLV_AtObj(@recordHex, @positions[2])

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

  signedData: ->
    nameHex = jsrsasign.ASN1HEX.getHexOfTLV_AtObj(@recordHex, @positions[0])
    recordHex = jsrsasign.ASN1HEX.getHexOfTLV_AtObj(@recordHex, @positions[1])

    nameHex + recordHex + @timestampHex()

  signature: ->
    signature_pos = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(@recordHex, @positions[3])
    jsrsasign.ASN1HEX.getHexOfV_AtObj(@recordHex, signature_pos[1])

  valid: ->
    @caCertificate.verifyHexString(@signedData(), @signature())


module.exports = ConservancyRecord
