jsrsasign = require 'jsrsasign'

module.exports =
  extend: (object, properties) ->
    for key, val of properties
      object[key] = val
    object

  b64toHex: (b64String) ->
    new Buffer(b64String, 'base64').toString('hex')

  hextoB64: (hexString) ->
    new Buffer(hexString, 'hex').toString('base64')

  hextoAscii: (hexString) ->
    new Buffer(hexString, 'hex').toString('ascii')

  b64toAscii: (b64String) ->
    new Buffer(b64String, 'base64').toString('ascii')

  parseDate: (date) ->
    try
      parsed = date.match(/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\..*Z/)
      parsed.shift(1)
      new Date(
        Date.UTC(
          parseInt(parsed[0]),
          parseInt(parsed[1]) - 1,
          parseInt(parsed[2]),
          parseInt(parsed[3]),
          parseInt(parsed[4]),
          parseInt(parsed[5])
        )
      )
    catch
      parsed = date.match(/(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\..*Z/)
      parsed.shift(1)
      new Date(
        Date.UTC(
          parseInt(parsed[0]) + 2000,
          parseInt(parsed[1]) - 1,
          parseInt(parsed[2]),
          parseInt(parsed[3]),
          parseInt(parsed[4]),
          parseInt(parsed[5])
        )
      )
    

  sha256: (string) ->
    digest = new jsrsasign.crypto.MessageDigest(
      alg: 'sha256'
      prov: 'cryptojs'
    )
    digest.digestString(string)
  
  sha256hex: (hex) ->
    digest = new jsrsasign.crypto.MessageDigest(
      alg: 'sha256'
      prov: 'cryptojs'
    )
    digest.digestHex(hex)

return
