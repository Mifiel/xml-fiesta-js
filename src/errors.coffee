InvalidSignerError = (@message) ->
  @stack = (new Error()).stack
  this.name = 'InvalidSignerError'
  return

InvalidSignerError.prototype = Object.create(Error.prototype)

DuplicateSignersError = (@message) ->
  @stack = (new Error()).stack
  this.name = 'DuplicateSignersError'
  return

DuplicateSignersError.prototype = Object.create(Error.prototype)

CertificateError = (@message) ->
  @stack = (new Error()).stack
  this.name = 'CertificateError'
  return

CertificateError.prototype = Object.create(Error.prototype)

ArgumentError = (@message) ->
  @stack = (new Error()).stack
  this.name = 'ArgumentError'
  return

ArgumentError.prototype = Object.create(Error.prototype)

module.exports = {
  InvalidSignerError: InvalidSignerError
  DuplicateSignersError: DuplicateSignersError
  CertificateError: CertificateError
  ArgumentError: ArgumentError
}
