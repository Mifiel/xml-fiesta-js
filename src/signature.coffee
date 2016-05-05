Certificate = require './certificate'
errors = require './errors'

class Signature
  _certificate = null
  _signature = null
  _signedAt = null
  _email = null

  constructor: (cer, signature, signedAt, email) ->
    throw new errors.ArgumentError(
      'Signature must have signedAt'
    ) unless signedAt
    throw new errors.ArgumentError(
      'Signature must have cer'
    ) unless cer

    _signature = signature
    _signedAt = signedAt
    _certificate = new Certificate(false, cer)
    _email = email
    _email ?= _certificate.email()

  signer: ->
    {
      id: _certificate.owner_id(),
      name: _certificate.owner(),
      email: _email
    }

  certificate: -> _certificate
  signedAt: -> _signedAt
  signature: -> _signature

  valid: (hash) ->
    throw new errors.ArgumentError 'hash is required' unless hash
    _certificate.verifyHexString(hash, _signature)

  email: -> _email

module.exports = Signature
