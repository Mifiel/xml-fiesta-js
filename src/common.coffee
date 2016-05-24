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
