errors = require './errors'
jsrsasign = require 'jsrsasign'

jsrsasign.X509.hex2dnobj = (e) ->
  f = {}
  c = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(e, 0)
  d = 0
  while d < c.length
    b = jsrsasign.ASN1HEX.getHexOfTLV_AtObj(e, c[d])
    try
      rdn = jsrsasign.X509.hex2rdnobj(b)
      f[rdn[0]] = rdn[1]
    catch err
      console.error err
    d++
  f

jsrsasign.X509.hex2rdnobj = (a) ->
  f = jsrsasign.ASN1HEX.getDecendantHexTLVByNthList(a, 0, [0, 0])
  e = jsrsasign.ASN1HEX.getDecendantHexVByNthList(a, 0, [0, 1])
  c = ''
  try
    c = jsrsasign.X509.DN_ATTRHEX[f]
  catch b
    c = f
  d = jsrsasign.hextorstr(e)
  [c, d]

jsrsasign.X509::getSubjectObject = ->
  jsrsasign.X509.hex2dnobj(
    jsrsasign.ASN1HEX.getDecendantHexTLVByNthList(@hex, 0, [0, 5])
  )

jsrsasign.X509.DN_ATTRHEX =
  '0603550406': 'C'
  '060355040a': 'O'
  '060355040b': 'OU'
  '0603550403': 'CN'
  '0603550405': 'SN'
  '0603550408': 'ST'
  '0603550407': 'L'
  '060355042d': 'UI'
  # Attrbutes added by SAT
  '0603550429': 'NAME'
  '06092a864886f70d010901': 'EMAIL'

Certificate = (binaryString, hexString) ->
  hex = if binaryString then jsrsasign.rstrtohex(binaryString) else hexString
  certificate = new jsrsasign.X509()
  pubKey = null
  subject = null

  if (binaryString.length == 0 || !jsrsasign.ASN1HEX.isASN1HEX(hex))
    throw new errors.CertificateError('The certificate is not valid.')
    return this

  buildPemFromHex = (hex) ->
    jsrsasign.asn1.ASN1Util.getPEMStringFromHex(hex, 'CERTIFICATE')

  certificate.readCertPEM(buildPemFromHex(hex))
  subject = certificate.getSubjectObject()

  @toBinaryString = -> binaryString

  @toHex = -> hex

  @getX509 = -> certificate

  @getSerialNumberHex = -> certificate.getSerialNumberHex()

  @getSubject = -> subject

  @getRSAPublicKey = ->
    pubKey = if pubKey == null then certificate.subjectPublicKeyRSA else pubKey

  @verifyString = (string, signedString) ->
    try
      @verifyHexString(string, jsrsasign.b64toutf8(signedString))
    catch error
      false

  @verifyHexString = (string, signedHexString) ->
    try
      @getRSAPublicKey().verifyString(string, signedHexString)
    catch error
      false

  @getUniqueIdentifierString = (joinVal) ->
    joinVal = if joinVal then joinVal else ', '
    identifiers = @getUniqueIdentifier()
    identifiers.join(joinVal)

  parseDate = (certDate) ->
    parsed = certDate.match(/(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/)
    parsed.shift(1)
    new Date(Date.UTC(2000 + parseInt(parsed[0]), parsed[1], parsed[2], parsed[3], parsed[4], parsed[5]))

  @hasExpired = ->
    notAfter = parseDate(certificate.getNotAfter())
    notAfter.getTime() < new Date().getTime()

  return

module.exports = Certificate
