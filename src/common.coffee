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
