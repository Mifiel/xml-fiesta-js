common = require '../src/common'
jsrsasign = require 'jsrsasign'
fs = require 'fs'

expect = require 'expect.js'

intermediate = fs.readFileSync("#{__dirname}/../docs/AC2_Sat.crt").toString()
cert = fs.readFileSync("#{__dirname}/fixtures/production-certificate.pem").toString()

describe 'Basic certificate validation', ->
  it 'should be true', ->
    certificate = new jsrsasign.X509()
    certificate.readCertPEM(cert)

    hTbsCert = jsrsasign.ASN1HEX.getDecendantHexTLVByNthList(certificate.hex, 0, [0])
    alg = certificate.getSignatureAlgorithmField()
    signature = jsrsasign.X509.getSignatureValueHex(certificate.hex)

    sig = new jsrsasign.crypto.Signature({alg: alg})
    sig.init(intermediate)
    sig.updateHex(hTbsCert)
    expect(sig.verify(signature)).to.be true
