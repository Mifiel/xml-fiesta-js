errors    = require './errors'
common    = require './common'
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
  '0603550405': 'serialNumber'
  '0603550408': 'ST'
  '0603550407': 'L'
  '060355042d': 'UI'
  '0603550409': 'street'
  '0603550429': 'name'
  '0603550411': 'postalCode'
  '06092a864886f70d010901': 'emailAddress'
  '06092a864886f70d010902': 'unstructuredName'

Certificate = (binaryString, hexString) ->
  hex = if binaryString then jsrsasign.rstrtohex(binaryString) else hexString
  certificate = new jsrsasign.X509()
  pubKey = null
  subject = null

  if (binaryString.length == 0 || !jsrsasign.ASN1HEX.isASN1HEX(hex) && !hex.startsWith('2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494'))
    throw new errors.CertificateError('The certificate is not valid.')
    return this

  if hex.startsWith('2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494')
    pem = jsrsasign.hextorstr(hex) 
  else
    pem = jsrsasign.asn1.ASN1Util.getPEMStringFromHex(hex, 'CERTIFICATE')
   
  certificate.readCertPEM(pem)
  hex = certificate.hex
  subject = certificate.getSubjectObject()

  @toBinaryString = -> binaryString

  @toHex = -> certificate.hex
  @toPem = -> pem

  @getX509 = -> certificate

  @getSerialNumberHex = -> certificate.getSerialNumberHex()
  @getSerialNumber = ->
    common.hextoAscii(@getSerialNumberHex())

  @getSubject = -> subject
  @email = -> subject.emailAddress
  @owner = -> subject.name
  @owner_id = ->
    identifier = @getUniqueIdentifier()
    identifier[0]

  @getUniqueIdentifier = ->
    if subject.UI then subject.UI.split(' / ') else null

  @getRSAPublicKey = ->
    pubKey = if pubKey == null then certificate.subjectPublicKeyRSA else pubKey

  @verifyString = (string, signedHexString, alg) ->
    try
      alg ?= 'SHA256withRSA'
      sig = new jsrsasign.crypto.Signature(alg: alg)
      sig.init(pem)
      sig.updateString(string)
      sig.verify(signedHexString)
    catch error
      false

  @verifyHexString = (hexString, signedHexString, alg) ->
    try
      alg ?= 'SHA256withRSA'
      sig = new jsrsasign.crypto.Signature(alg: alg)
      sig.init(pem)
      sig.updateHex(hexString)
      sig.verify(signedHexString)
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

  @isValidOn = (date)->
    notAfter = parseDate(certificate.getNotAfter())
    notBefore = parseDate(certificate.getNotBefore())
    notAfter.getTime() >= date.getTime() && date.getTime() >= notBefore.getTime()

  @algorithm = ->
    certificate.getSignatureAlgorithmField()

  @tbsCertificate = ->
    # 1st child of SEQ is tbsCert
    jsrsasign.ASN1HEX.getDecendantHexTLVByNthList(hex, 0, [0])

  @signature = ->
    jsrsasign.X509.getSignatureValueHex(hex)

  @isCa = (rootCa) ->
    try
      rootCaCert = new jsrsasign.X509()
      rootCaCert.readCertPEM(rootCa)
      rootCaIsCa = jsrsasign.X509.getExtBasicConstraints(rootCaCert.hex).cA
      # root certificate provided is not CA
      return false unless rootCaIsCa
      rootCaCert = new Certificate(false, rootCaCert.hex)

      rootCaCert.verifyHexString(@tbsCertificate(), @signature() , @algorithm())
    catch err
      false
  return

module.exports = Certificate
