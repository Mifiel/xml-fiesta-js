(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.XMLFiesta = f()}})(function(){var define,module,exports;return (function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
(function() {
  var Certificate, common, errors, jsrsasign;

  errors = require('./errors');

  common = require('./common');

  jsrsasign = require('jsrsasign');

  jsrsasign.X509.hex2dnobj = function(e) {
    var b, c, d, err, error1, f, rdn;
    f = {};
    c = jsrsasign.ASN1HEX.getPosArrayOfChildren_AtObj(e, 0);
    d = 0;
    while (d < c.length) {
      b = jsrsasign.ASN1HEX.getHexOfTLV_AtObj(e, c[d]);
      try {
        rdn = jsrsasign.X509.hex2rdnobj(b);
        f[rdn[0]] = rdn[1];
      } catch (error1) {
        err = error1;
        console.error(err);
      }
      d++;
    }
    return f;
  };

  jsrsasign.X509.hex2rdnobj = function(a) {
    var b, c, d, e, error1, f;
    f = jsrsasign.ASN1HEX.getDecendantHexTLVByNthList(a, 0, [0, 0]);
    e = jsrsasign.ASN1HEX.getDecendantHexVByNthList(a, 0, [0, 1]);
    c = '';
    try {
      c = jsrsasign.X509.DN_ATTRHEX[f];
    } catch (error1) {
      b = error1;
      c = f;
    }
    d = jsrsasign.hextorstr(e);
    return [c, d];
  };

  jsrsasign.X509.prototype.getSubjectObject = function() {
    return jsrsasign.X509.hex2dnobj(jsrsasign.ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]));
  };

  jsrsasign.X509.DN_ATTRHEX = {
    '0603550406': 'C',
    '060355040a': 'O',
    '060355040b': 'OU',
    '0603550403': 'CN',
    '0603550405': 'serialNumber',
    '0603550408': 'ST',
    '0603550407': 'L',
    '060355042d': 'UI',
    '0603550409': 'street',
    '0603550429': 'name',
    '0603550411': 'postalCode',
    '06092a864886f70d010901': 'emailAddress',
    '06092a864886f70d010902': 'unstructuredName'
  };

  Certificate = function(binaryString, hexString) {
    var certificate, hex, parseDate, pem, pubKey, subject;
    hex = binaryString ? jsrsasign.rstrtohex(binaryString) : hexString;
    certificate = new jsrsasign.X509();
    pubKey = null;
    subject = null;
    if (binaryString.length === 0 || !jsrsasign.ASN1HEX.isASN1HEX(hex)) {
      throw new errors.CertificateError('The certificate is not valid.');
      return this;
    }
    pem = jsrsasign.asn1.ASN1Util.getPEMStringFromHex(hex, 'CERTIFICATE');
    certificate.readCertPEM(pem);
    subject = certificate.getSubjectObject();
    this.toBinaryString = function() {
      return binaryString;
    };
    this.toHex = function() {
      return hex;
    };
    this.toPem = function() {
      return pem;
    };
    this.getX509 = function() {
      return certificate;
    };
    this.getSerialNumberHex = function() {
      return certificate.getSerialNumberHex();
    };
    this.getSerialNumber = function() {
      return common.hextoAscii(this.getSerialNumberHex());
    };
    this.getSubject = function() {
      return subject;
    };
    this.email = function() {
      return subject.emailAddress;
    };
    this.owner = function() {
      return subject.name;
    };
    this.owner_id = function() {
      var identifier;
      identifier = this.getUniqueIdentifier();
      return identifier[0];
    };
    this.getUniqueIdentifier = function() {
      if (subject.UI) {
        return subject.UI.split(' / ');
      } else {
        return null;
      }
    };
    this.getRSAPublicKey = function() {
      return pubKey = pubKey === null ? certificate.subjectPublicKeyRSA : pubKey;
    };
    this.verifyString = function(string, signedHexString, alg) {
      var error, error1, sig;
      try {
        if (alg == null) {
          alg = 'SHA256withRSA';
        }
        sig = new jsrsasign.crypto.Signature({
          alg: alg
        });
        sig.init(pem);
        sig.updateString(string);
        return sig.verify(signedHexString);
      } catch (error1) {
        error = error1;
        return false;
      }
    };
    this.verifyHexString = function(hexString, signedHexString, alg) {
      var error, error1, sig;
      try {
        if (alg == null) {
          alg = 'SHA256withRSA';
        }
        sig = new jsrsasign.crypto.Signature({
          alg: alg
        });
        sig.init(pem);
        sig.updateHex(hexString);
        return sig.verify(signedHexString);
      } catch (error1) {
        error = error1;
        return false;
      }
    };
    this.getUniqueIdentifierString = function(joinVal) {
      var identifiers;
      joinVal = joinVal ? joinVal : ', ';
      identifiers = this.getUniqueIdentifier();
      return identifiers.join(joinVal);
    };
    parseDate = function(certDate) {
      var parsed;
      parsed = certDate.match(/(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z/);
      parsed.shift(1);
      return new Date(Date.UTC(2000 + parseInt(parsed[0]), parsed[1], parsed[2], parsed[3], parsed[4], parsed[5]));
    };
    this.hasExpired = function() {
      var notAfter;
      notAfter = parseDate(certificate.getNotAfter());
      return notAfter.getTime() < new Date().getTime();
    };
    this.algorithm = function() {
      return certificate.getSignatureAlgorithmField();
    };
    this.tbsCertificate = function() {
      return jsrsasign.ASN1HEX.getDecendantHexTLVByNthList(hex, 0, [0]);
    };
    this.signature = function() {
      return jsrsasign.X509.getSignatureValueHex(hex);
    };
    this.isCa = function(rootCa) {
      var err, error1, rootCaCert, rootCaIsCa;
      try {
        rootCaCert = new jsrsasign.X509();
        rootCaCert.readCertPEM(rootCa);
        rootCaIsCa = jsrsasign.X509.getExtBasicConstraints(rootCaCert.hex).cA;
        if (!rootCaIsCa) {
          return false;
        }
        rootCaCert = new Certificate(false, rootCaCert.hex);
        return rootCaCert.verifyHexString(this.tbsCertificate(), this.signature(), this.algorithm());
      } catch (error1) {
        err = error1;
        return false;
      }
    };
  };

  module.exports = Certificate;

}).call(this);

},{"./common":2,"./errors":4,"jsrsasign":34}],2:[function(require,module,exports){
(function (Buffer){
(function() {
  module.exports = {
    extend: function(object, properties) {
      var key, val;
      for (key in properties) {
        val = properties[key];
        object[key] = val;
      }
      return object;
    },
    b64toHex: function(b64String) {
      return new Buffer(b64String, 'base64').toString('hex');
    },
    hextoB64: function(hexString) {
      return new Buffer(hexString, 'hex').toString('base64');
    },
    hextoAscii: function(hexString) {
      return new Buffer(hexString, 'hex').toString('ascii');
    },
    b64toAscii: function(b64String) {
      return new Buffer(b64String, 'base64').toString('ascii');
    }
  };

}).call(this);

}).call(this,require("buffer").Buffer)
},{"buffer":9}],3:[function(require,module,exports){
(function (Buffer){
(function() {
  var Document, Signature, common, errors, jsrsasign, parseString;

  Signature = require('./signature');

  common = require('./common');

  errors = require('./errors');

  jsrsasign = require('jsrsasign');

  parseString = require('xml2js').parseString;

  Document = (function() {
    var VERSION;

    VERSION = '0.0.1';

    function Document(pdf, options) {
      var defaultOpts, doc, hash;
      if (!pdf) {
        throw new Error('pdf is required');
      }
      this.pdf_content = pdf;
      this.signers = [];
      defaultOpts = {
        version: VERSION,
        signers: []
      };
      options = common.extend(defaultOpts, options);
      this.name = options.name;
      this.version = options.version;
      hash = new jsrsasign.crypto.MessageDigest({
        alg: 'sha256',
        prov: 'cryptojs'
      });
      this.originalHash = hash.digestHex(this.pdf('hex'));
      if (options.signers.length > 0) {
        doc = this;
        options.signers.forEach(function(el) {
          return doc.add_signer(el);
        });
      }
    }

    Document.prototype.pdfBuffer = function() {
      if (!this.pdf_content) {
        return null;
      }
      return new Buffer(this.pdf_content, 'base64');
    };

    Document.prototype.pdf = function(format) {
      if (!this.pdf_content) {
        return null;
      }
      if (!format) {
        return common.b64toAscii(this.pdf_content);
      }
      if (format === 'hex') {
        return common.b64toHex(this.pdf_content);
      }
      if (format === 'base64') {
        return this.pdf_content;
      }
      throw new errors.ArgumentError("unknown format " + format);
    };

    Document.prototype.add_signer = function(signer) {
      if (!signer.cer || !signer.signature || !signer.signedAt) {
        throw new errors.InvalidSignerError('signer must contain cer, signature and signedAt');
      }
      if (this.signer_exist(signer)) {
        throw new errors.DuplicateSignersError('signer already exists');
      }
      return this.signers.push(signer);
    };

    Document.prototype.signatures = function() {
      return this.signers.map(function(signer) {
        return new Signature(signer.cer, signer.signature, signer.signedAt);
      });
    };

    Document.prototype.validSignatures = function() {
      var oHash, valid;
      if (!this.originalHash) {
        return false;
      }
      valid = true;
      oHash = this.originalHash;
      this.signatures().forEach(function(signature) {
        if (valid && !signature.valid(oHash)) {
          return valid = false;
        }
      });
      return valid;
    };

    Document.prototype.signer_exist = function(signer) {
      var selected;
      selected = this.signers.filter(function(s) {
        return s.email === signer.email || s.cer === signer.cer || s.signature === signer.signature;
      });
      return selected.length > 0;
    };

    Document.fromXml = function(xml, validate) {
      var doc, options;
      if (!xml) {
        throw new Error('xml is required');
      }
      doc = null;
      options = null;
      parseString(xml, function(err, result) {
        var parsedSigners, pdf, pdfAttrs, signers;
        if (err) {
          throw new Error("Unable to parse xml: " + err);
        }
        pdf = result.electronicDocument.pdf[0]._;
        pdfAttrs = result.electronicDocument.pdf[0].$;
        signers = result.electronicDocument.signers;
        parsedSigners = [];
        signers[0].signer.forEach(function(signer) {
          var attrs;
          attrs = signer.$;
          return parsedSigners.push({
            email: attrs.email,
            cer: common.b64toHex(signer.certificate[0]._),
            signature: common.b64toHex(signer.signature[0]._),
            signedAt: signer.signature[0].$.signedAt
          });
        });
        options = {
          signers: parsedSigners,
          version: pdfAttrs.version,
          name: pdfAttrs.name,
          originalHash: pdfAttrs.originalHash
        };
        return doc = new Document(pdf, options);
      });
      return {
        document: doc,
        xmlOriginalHash: options.originalHash
      };
    };

    return Document;

  })();

  module.exports = Document;

}).call(this);

}).call(this,require("buffer").Buffer)
},{"./common":2,"./errors":4,"./signature":5,"buffer":9,"jsrsasign":34,"xml2js":37}],4:[function(require,module,exports){
(function() {
  var ArgumentError, CertificateError, DuplicateSignersError, InvalidSignerError;

  InvalidSignerError = function(message) {
    this.message = message;
    this.stack = (new Error()).stack;
    this.name = 'InvalidSignerError';
  };

  InvalidSignerError.prototype = Object.create(Error.prototype);

  DuplicateSignersError = function(message) {
    this.message = message;
    this.stack = (new Error()).stack;
    this.name = 'DuplicateSignersError';
  };

  DuplicateSignersError.prototype = Object.create(Error.prototype);

  CertificateError = function(message) {
    this.message = message;
    this.stack = (new Error()).stack;
    this.name = 'CertificateError';
  };

  CertificateError.prototype = Object.create(Error.prototype);

  ArgumentError = function(message) {
    this.message = message;
    this.stack = (new Error()).stack;
    this.name = 'ArgumentError';
  };

  ArgumentError.prototype = Object.create(Error.prototype);

  module.exports = {
    InvalidSignerError: InvalidSignerError,
    DuplicateSignersError: DuplicateSignersError,
    CertificateError: CertificateError,
    ArgumentError: ArgumentError
  };

}).call(this);

},{}],5:[function(require,module,exports){
(function() {
  var Certificate, Signature, common, errors;

  Certificate = require('./certificate');

  errors = require('./errors');

  common = require('./common');

  Signature = (function() {
    function Signature(cer, signature, signedAt, email) {
      this.signature = signature;
      this.signedAt = signedAt;
      this.email = email;
      if (!this.signedAt) {
        throw new errors.ArgumentError('Signature must have signedAt');
      }
      if (!cer) {
        throw new errors.ArgumentError('Signature must have cer');
      }
      this.certificate = new Certificate(false, cer);
      if (this.email == null) {
        this.email = this.certificate.email();
      }
      this.signer = {
        id: this.certificate.owner_id(),
        name: this.certificate.owner(),
        email: this.email
      };
    }

    Signature.prototype.sig = function(format) {
      if (format === 'hex' || !format) {
        return this.signature;
      }
      if (format === 'base64') {
        return common.hextoB64(this.signature);
      }
      throw new errors.ArgumentError("unknown format " + format);
    };

    Signature.prototype.valid = function(hash) {
      if (!hash) {
        throw new errors.ArgumentError('hash is required');
      }
      return this.certificate.verifyString(hash, this.signature);
    };

    return Signature;

  })();

  module.exports = Signature;

}).call(this);

},{"./certificate":1,"./common":2,"./errors":4}],6:[function(require,module,exports){
(function() {
  module.exports = {
    Certificate: require('./document'),
    Document: require('./document'),
    Signature: require('./document'),
    errors: require('./errors')
  };

}).call(this);

},{"./document":3,"./errors":4}],7:[function(require,module,exports){

},{}],8:[function(require,module,exports){
arguments[4][7][0].apply(exports,arguments)
},{"dup":7}],9:[function(require,module,exports){
(function (global){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

'use strict'

var base64 = require('base64-js')
var ieee754 = require('ieee754')
var isArray = require('isarray')

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Use Object implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * Due to various browser bugs, sometimes the Object implementation will be used even
 * when the browser supports typed arrays.
 *
 * Note:
 *
 *   - Firefox 4-29 lacks support for adding new properties to `Uint8Array` instances,
 *     See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438.
 *
 *   - Chrome 9-10 is missing the `TypedArray.prototype.subarray` function.
 *
 *   - IE10 has a broken `TypedArray.prototype.subarray` function which returns arrays of
 *     incorrect length in some situations.

 * We detect these buggy browsers and set `Buffer.TYPED_ARRAY_SUPPORT` to `false` so they
 * get the Object implementation, which is slower but behaves correctly.
 */
Buffer.TYPED_ARRAY_SUPPORT = global.TYPED_ARRAY_SUPPORT !== undefined
  ? global.TYPED_ARRAY_SUPPORT
  : typedArraySupport()

/*
 * Export kMaxLength after typed array support is determined.
 */
exports.kMaxLength = kMaxLength()

function typedArraySupport () {
  try {
    var arr = new Uint8Array(1)
    arr.foo = function () { return 42 }
    return arr.foo() === 42 && // typed array instances can be augmented
        typeof arr.subarray === 'function' && // chrome 9-10 lack `subarray`
        arr.subarray(1, 1).byteLength === 0 // ie10 has broken `subarray`
  } catch (e) {
    return false
  }
}

function kMaxLength () {
  return Buffer.TYPED_ARRAY_SUPPORT
    ? 0x7fffffff
    : 0x3fffffff
}

function createBuffer (that, length) {
  if (kMaxLength() < length) {
    throw new RangeError('Invalid typed array length')
  }
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    // Return an augmented `Uint8Array` instance, for best performance
    that = new Uint8Array(length)
    that.__proto__ = Buffer.prototype
  } else {
    // Fallback: Return an object instance of the Buffer class
    if (that === null) {
      that = new Buffer(length)
    }
    that.length = length
  }

  return that
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  if (!Buffer.TYPED_ARRAY_SUPPORT && !(this instanceof Buffer)) {
    return new Buffer(arg, encodingOrOffset, length)
  }

  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new Error(
        'If encoding is specified then the first argument must be a string'
      )
    }
    return allocUnsafe(this, arg)
  }
  return from(this, arg, encodingOrOffset, length)
}

Buffer.poolSize = 8192 // not used by this implementation

// TODO: Legacy, not needed anymore. Remove in next major version.
Buffer._augment = function (arr) {
  arr.__proto__ = Buffer.prototype
  return arr
}

function from (that, value, encodingOrOffset, length) {
  if (typeof value === 'number') {
    throw new TypeError('"value" argument must not be a number')
  }

  if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
    return fromArrayBuffer(that, value, encodingOrOffset, length)
  }

  if (typeof value === 'string') {
    return fromString(that, value, encodingOrOffset)
  }

  return fromObject(that, value)
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(null, value, encodingOrOffset, length)
}

if (Buffer.TYPED_ARRAY_SUPPORT) {
  Buffer.prototype.__proto__ = Uint8Array.prototype
  Buffer.__proto__ = Uint8Array
  if (typeof Symbol !== 'undefined' && Symbol.species &&
      Buffer[Symbol.species] === Buffer) {
    // Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
    Object.defineProperty(Buffer, Symbol.species, {
      value: null,
      configurable: true
    })
  }
}

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be a number')
  }
}

function alloc (that, size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(that, size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(that, size).fill(fill, encoding)
      : createBuffer(that, size).fill(fill)
  }
  return createBuffer(that, size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(null, size, fill, encoding)
}

function allocUnsafe (that, size) {
  assertSize(size)
  that = createBuffer(that, size < 0 ? 0 : checked(size) | 0)
  if (!Buffer.TYPED_ARRAY_SUPPORT) {
    for (var i = 0; i < size; i++) {
      that[i] = 0
    }
  }
  return that
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(null, size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(null, size)
}

function fromString (that, string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('"encoding" must be a valid string encoding')
  }

  var length = byteLength(string, encoding) | 0
  that = createBuffer(that, length)

  that.write(string, encoding)
  return that
}

function fromArrayLike (that, array) {
  var length = checked(array.length) | 0
  that = createBuffer(that, length)
  for (var i = 0; i < length; i += 1) {
    that[i] = array[i] & 255
  }
  return that
}

function fromArrayBuffer (that, array, byteOffset, length) {
  array.byteLength // this throws if `array` is not a valid ArrayBuffer

  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('\'offset\' is out of bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('\'length\' is out of bounds')
  }

  if (length === undefined) {
    array = new Uint8Array(array, byteOffset)
  } else {
    array = new Uint8Array(array, byteOffset, length)
  }

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    // Return an augmented `Uint8Array` instance, for best performance
    that = array
    that.__proto__ = Buffer.prototype
  } else {
    // Fallback: Return an object instance of the Buffer class
    that = fromArrayLike(that, array)
  }
  return that
}

function fromObject (that, obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    that = createBuffer(that, len)

    if (that.length === 0) {
      return that
    }

    obj.copy(that, 0, 0, len)
    return that
  }

  if (obj) {
    if ((typeof ArrayBuffer !== 'undefined' &&
        obj.buffer instanceof ArrayBuffer) || 'length' in obj) {
      if (typeof obj.length !== 'number' || isnan(obj.length)) {
        return createBuffer(that, 0)
      }
      return fromArrayLike(that, obj)
    }

    if (obj.type === 'Buffer' && isArray(obj.data)) {
      return fromArrayLike(that, obj.data)
    }
  }

  throw new TypeError('First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.')
}

function checked (length) {
  // Note: cannot use `length < kMaxLength` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= kMaxLength()) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + kMaxLength().toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return !!(b != null && b._isBuffer)
}

Buffer.compare = function compare (a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError('Arguments must be Buffers')
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'binary':
    case 'base64':
    case 'raw':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; i++) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; i++) {
    var buf = list[i]
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function' &&
      (ArrayBuffer.isView(string) || string instanceof ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    string = '' + string
  }

  var len = string.length
  if (len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'binary':
      // Deprecated
      case 'raw':
      case 'raws':
        return len
      case 'utf8':
      case 'utf-8':
      case undefined:
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) return utf8ToBytes(string).length // assume utf8
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'binary':
        return binarySlice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// The property is used by `Buffer.isBuffer` and `is-buffer` (in Safari 5-7) to detect
// Buffer instances.
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length | 0
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  if (this.length > 0) {
    str = this.toString('hex', 0, max).match(/.{2}/g).join(' ')
    if (this.length > max) str += ' ... '
  }
  return '<Buffer ' + str + '>'
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (!Buffer.isBuffer(target)) {
    throw new TypeError('Argument must be a Buffer')
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

function arrayIndexOf (arr, val, byteOffset, encoding) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var foundIndex = -1
  for (var i = 0; byteOffset + i < arrLength; i++) {
    if (read(arr, byteOffset + i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
      if (foundIndex === -1) foundIndex = i
      if (i - foundIndex + 1 === valLength) return (byteOffset + foundIndex) * indexSize
    } else {
      if (foundIndex !== -1) i -= i - foundIndex
      foundIndex = -1
    }
  }
  return -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset >>= 0

  if (this.length === 0) return -1
  if (byteOffset >= this.length) return -1

  // Negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = Math.max(this.length + byteOffset, 0)

  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  if (Buffer.isBuffer(val)) {
    // special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(this, val, byteOffset, encoding)
  }
  if (typeof val === 'number') {
    if (Buffer.TYPED_ARRAY_SUPPORT && Uint8Array.prototype.indexOf === 'function') {
      return Uint8Array.prototype.indexOf.call(this, val, byteOffset)
    }
    return arrayIndexOf(this, [ val ], byteOffset, encoding)
  }

  throw new TypeError('val must be string, number or Buffer')
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  // must be an even number of digits
  var strLen = string.length
  if (strLen % 2 !== 0) throw new Error('Invalid hex string')

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; i++) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (isNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function binaryWrite (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset | 0
    if (isFinite(length)) {
      length = length | 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  // legacy write(string, encoding, offset, length) - remove in v0.13
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'binary':
        return binaryWrite(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
      : (firstByte > 0xBF) ? 2
      : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; i++) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function binarySlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; i++) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; i++) {
    out += toHex(buf[i])
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + bytes[i + 1] * 256)
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    newBuf = this.subarray(start, end)
    newBuf.__proto__ = Buffer.prototype
  } else {
    var sliceLen = end - start
    newBuf = new Buffer(sliceLen, undefined)
    for (var i = 0; i < sliceLen; i++) {
      newBuf[i] = this[i + start]
    }
  }

  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value)
  this[offset] = (value & 0xff)
  return offset + 1
}

function objectWriteUInt16 (buf, value, offset, littleEndian) {
  if (value < 0) value = 0xffff + value + 1
  for (var i = 0, j = Math.min(buf.length - offset, 2); i < j; i++) {
    buf[offset + i] = (value & (0xff << (8 * (littleEndian ? i : 1 - i)))) >>>
      (littleEndian ? i : 1 - i) * 8
  }
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value & 0xff)
    this[offset + 1] = (value >>> 8)
  } else {
    objectWriteUInt16(this, value, offset, true)
  }
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 8)
    this[offset + 1] = (value & 0xff)
  } else {
    objectWriteUInt16(this, value, offset, false)
  }
  return offset + 2
}

function objectWriteUInt32 (buf, value, offset, littleEndian) {
  if (value < 0) value = 0xffffffff + value + 1
  for (var i = 0, j = Math.min(buf.length - offset, 4); i < j; i++) {
    buf[offset + i] = (value >>> (littleEndian ? i : 3 - i) * 8) & 0xff
  }
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset + 3] = (value >>> 24)
    this[offset + 2] = (value >>> 16)
    this[offset + 1] = (value >>> 8)
    this[offset] = (value & 0xff)
  } else {
    objectWriteUInt32(this, value, offset, true)
  }
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 24)
    this[offset + 1] = (value >>> 16)
    this[offset + 2] = (value >>> 8)
    this[offset + 3] = (value & 0xff)
  } else {
    objectWriteUInt32(this, value, offset, false)
  }
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) {
    var limit = Math.pow(2, 8 * byteLength - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) {
    var limit = Math.pow(2, 8 * byteLength - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value & 0xff)
    this[offset + 1] = (value >>> 8)
  } else {
    objectWriteUInt16(this, value, offset, true)
  }
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 8)
    this[offset + 1] = (value & 0xff)
  } else {
    objectWriteUInt16(this, value, offset, false)
  }
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value & 0xff)
    this[offset + 1] = (value >>> 8)
    this[offset + 2] = (value >>> 16)
    this[offset + 3] = (value >>> 24)
  } else {
    objectWriteUInt32(this, value, offset, true)
  }
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 24)
    this[offset + 1] = (value >>> 16)
    this[offset + 2] = (value >>> 8)
    this[offset + 3] = (value & 0xff)
  } else {
    objectWriteUInt32(this, value, offset, false)
  }
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('sourceStart out of bounds')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start
  var i

  if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (i = len - 1; i >= 0; i--) {
      target[i + targetStart] = this[i + start]
    }
  } else if (len < 1000 || !Buffer.TYPED_ARRAY_SUPPORT) {
    // ascending copy from start
    for (i = 0; i < len; i++) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, start + len),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if (code < 256) {
        val = code
      }
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
  } else if (typeof val === 'number') {
    val = val & 255
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; i++) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : utf8ToBytes(new Buffer(val, encoding).toString())
    var len = bytes.length
    for (i = 0; i < end - start; i++) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+\/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = stringtrim(str).replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function stringtrim (str) {
  if (str.trim) return str.trim()
  return str.replace(/^\s+|\s+$/g, '')
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; i++) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; i++) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; i++) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; i++) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

function isnan (val) {
  return val !== val // eslint-disable-line no-self-compare
}

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"base64-js":10,"ieee754":11,"isarray":12}],10:[function(require,module,exports){
'use strict'

exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

function init () {
  var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  for (var i = 0, len = code.length; i < len; ++i) {
    lookup[i] = code[i]
    revLookup[code.charCodeAt(i)] = i
  }

  revLookup['-'.charCodeAt(0)] = 62
  revLookup['_'.charCodeAt(0)] = 63
}

init()

function toByteArray (b64) {
  var i, j, l, tmp, placeHolders, arr
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // the number of equal signs (place holders)
  // if there are two placeholders, than the two characters before it
  // represent one byte
  // if there is only one, then the three characters before it represent 2 bytes
  // this is just a cheap hack to not do indexOf twice
  placeHolders = b64[len - 2] === '=' ? 2 : b64[len - 1] === '=' ? 1 : 0

  // base64 is 4/3 + up to two characters of the original data
  arr = new Arr(len * 3 / 4 - placeHolders)

  // if there are placeholders, only get up to the last complete 4 chars
  l = placeHolders > 0 ? len - 4 : len

  var L = 0

  for (i = 0, j = 0; i < l; i += 4, j += 3) {
    tmp = (revLookup[b64.charCodeAt(i)] << 18) | (revLookup[b64.charCodeAt(i + 1)] << 12) | (revLookup[b64.charCodeAt(i + 2)] << 6) | revLookup[b64.charCodeAt(i + 3)]
    arr[L++] = (tmp >> 16) & 0xFF
    arr[L++] = (tmp >> 8) & 0xFF
    arr[L++] = tmp & 0xFF
  }

  if (placeHolders === 2) {
    tmp = (revLookup[b64.charCodeAt(i)] << 2) | (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[L++] = tmp & 0xFF
  } else if (placeHolders === 1) {
    tmp = (revLookup[b64.charCodeAt(i)] << 10) | (revLookup[b64.charCodeAt(i + 1)] << 4) | (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[L++] = (tmp >> 8) & 0xFF
    arr[L++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] + lookup[num >> 12 & 0x3F] + lookup[num >> 6 & 0x3F] + lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2])
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var output = ''
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    output += lookup[tmp >> 2]
    output += lookup[(tmp << 4) & 0x3F]
    output += '=='
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + (uint8[len - 1])
    output += lookup[tmp >> 10]
    output += lookup[(tmp >> 4) & 0x3F]
    output += lookup[(tmp << 2) & 0x3F]
    output += '='
  }

  parts.push(output)

  return parts.join('')
}

},{}],11:[function(require,module,exports){
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = nBytes * 8 - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = e * 256 + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = m * 256 + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = nBytes * 8 - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = (value * c - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}

},{}],12:[function(require,module,exports){
var toString = {}.toString;

module.exports = Array.isArray || function (arr) {
  return toString.call(arr) == '[object Array]';
};

},{}],13:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

function EventEmitter() {
  this._events = this._events || {};
  this._maxListeners = this._maxListeners || undefined;
}
module.exports = EventEmitter;

// Backwards-compat with node 0.10.x
EventEmitter.EventEmitter = EventEmitter;

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._maxListeners = undefined;

// By default EventEmitters will print a warning if more than 10 listeners are
// added to it. This is a useful default which helps finding memory leaks.
EventEmitter.defaultMaxListeners = 10;

// Obviously not all Emitters should be limited to 10. This function allows
// that to be increased. Set to zero for unlimited.
EventEmitter.prototype.setMaxListeners = function(n) {
  if (!isNumber(n) || n < 0 || isNaN(n))
    throw TypeError('n must be a positive number');
  this._maxListeners = n;
  return this;
};

EventEmitter.prototype.emit = function(type) {
  var er, handler, len, args, i, listeners;

  if (!this._events)
    this._events = {};

  // If there is no 'error' event listener then throw.
  if (type === 'error') {
    if (!this._events.error ||
        (isObject(this._events.error) && !this._events.error.length)) {
      er = arguments[1];
      if (er instanceof Error) {
        throw er; // Unhandled 'error' event
      }
      throw TypeError('Uncaught, unspecified "error" event.');
    }
  }

  handler = this._events[type];

  if (isUndefined(handler))
    return false;

  if (isFunction(handler)) {
    switch (arguments.length) {
      // fast cases
      case 1:
        handler.call(this);
        break;
      case 2:
        handler.call(this, arguments[1]);
        break;
      case 3:
        handler.call(this, arguments[1], arguments[2]);
        break;
      // slower
      default:
        args = Array.prototype.slice.call(arguments, 1);
        handler.apply(this, args);
    }
  } else if (isObject(handler)) {
    args = Array.prototype.slice.call(arguments, 1);
    listeners = handler.slice();
    len = listeners.length;
    for (i = 0; i < len; i++)
      listeners[i].apply(this, args);
  }

  return true;
};

EventEmitter.prototype.addListener = function(type, listener) {
  var m;

  if (!isFunction(listener))
    throw TypeError('listener must be a function');

  if (!this._events)
    this._events = {};

  // To avoid recursion in the case that type === "newListener"! Before
  // adding it to the listeners, first emit "newListener".
  if (this._events.newListener)
    this.emit('newListener', type,
              isFunction(listener.listener) ?
              listener.listener : listener);

  if (!this._events[type])
    // Optimize the case of one listener. Don't need the extra array object.
    this._events[type] = listener;
  else if (isObject(this._events[type]))
    // If we've already got an array, just append.
    this._events[type].push(listener);
  else
    // Adding the second element, need to change to array.
    this._events[type] = [this._events[type], listener];

  // Check for listener leak
  if (isObject(this._events[type]) && !this._events[type].warned) {
    if (!isUndefined(this._maxListeners)) {
      m = this._maxListeners;
    } else {
      m = EventEmitter.defaultMaxListeners;
    }

    if (m && m > 0 && this._events[type].length > m) {
      this._events[type].warned = true;
      console.error('(node) warning: possible EventEmitter memory ' +
                    'leak detected. %d listeners added. ' +
                    'Use emitter.setMaxListeners() to increase limit.',
                    this._events[type].length);
      if (typeof console.trace === 'function') {
        // not supported in IE 10
        console.trace();
      }
    }
  }

  return this;
};

EventEmitter.prototype.on = EventEmitter.prototype.addListener;

EventEmitter.prototype.once = function(type, listener) {
  if (!isFunction(listener))
    throw TypeError('listener must be a function');

  var fired = false;

  function g() {
    this.removeListener(type, g);

    if (!fired) {
      fired = true;
      listener.apply(this, arguments);
    }
  }

  g.listener = listener;
  this.on(type, g);

  return this;
};

// emits a 'removeListener' event iff the listener was removed
EventEmitter.prototype.removeListener = function(type, listener) {
  var list, position, length, i;

  if (!isFunction(listener))
    throw TypeError('listener must be a function');

  if (!this._events || !this._events[type])
    return this;

  list = this._events[type];
  length = list.length;
  position = -1;

  if (list === listener ||
      (isFunction(list.listener) && list.listener === listener)) {
    delete this._events[type];
    if (this._events.removeListener)
      this.emit('removeListener', type, listener);

  } else if (isObject(list)) {
    for (i = length; i-- > 0;) {
      if (list[i] === listener ||
          (list[i].listener && list[i].listener === listener)) {
        position = i;
        break;
      }
    }

    if (position < 0)
      return this;

    if (list.length === 1) {
      list.length = 0;
      delete this._events[type];
    } else {
      list.splice(position, 1);
    }

    if (this._events.removeListener)
      this.emit('removeListener', type, listener);
  }

  return this;
};

EventEmitter.prototype.removeAllListeners = function(type) {
  var key, listeners;

  if (!this._events)
    return this;

  // not listening for removeListener, no need to emit
  if (!this._events.removeListener) {
    if (arguments.length === 0)
      this._events = {};
    else if (this._events[type])
      delete this._events[type];
    return this;
  }

  // emit removeListener for all listeners on all events
  if (arguments.length === 0) {
    for (key in this._events) {
      if (key === 'removeListener') continue;
      this.removeAllListeners(key);
    }
    this.removeAllListeners('removeListener');
    this._events = {};
    return this;
  }

  listeners = this._events[type];

  if (isFunction(listeners)) {
    this.removeListener(type, listeners);
  } else if (listeners) {
    // LIFO order
    while (listeners.length)
      this.removeListener(type, listeners[listeners.length - 1]);
  }
  delete this._events[type];

  return this;
};

EventEmitter.prototype.listeners = function(type) {
  var ret;
  if (!this._events || !this._events[type])
    ret = [];
  else if (isFunction(this._events[type]))
    ret = [this._events[type]];
  else
    ret = this._events[type].slice();
  return ret;
};

EventEmitter.prototype.listenerCount = function(type) {
  if (this._events) {
    var evlistener = this._events[type];

    if (isFunction(evlistener))
      return 1;
    else if (evlistener)
      return evlistener.length;
  }
  return 0;
};

EventEmitter.listenerCount = function(emitter, type) {
  return emitter.listenerCount(type);
};

function isFunction(arg) {
  return typeof arg === 'function';
}

function isNumber(arg) {
  return typeof arg === 'number';
}

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}

function isUndefined(arg) {
  return arg === void 0;
}

},{}],14:[function(require,module,exports){
if (typeof Object.create === 'function') {
  // implementation from standard node.js 'util' module
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    ctor.prototype = Object.create(superCtor.prototype, {
      constructor: {
        value: ctor,
        enumerable: false,
        writable: true,
        configurable: true
      }
    });
  };
} else {
  // old school shim for old browsers
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    var TempCtor = function () {}
    TempCtor.prototype = superCtor.prototype
    ctor.prototype = new TempCtor()
    ctor.prototype.constructor = ctor
  }
}

},{}],15:[function(require,module,exports){
/**
 * Determine if an object is Buffer
 *
 * Author:   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
 * License:  MIT
 *
 * `npm install is-buffer`
 */

module.exports = function (obj) {
  return !!(obj != null &&
    (obj._isBuffer || // For Safari 5-7 (missing Object.prototype.constructor)
      (obj.constructor &&
      typeof obj.constructor.isBuffer === 'function' &&
      obj.constructor.isBuffer(obj))
    ))
}

},{}],16:[function(require,module,exports){
// shim for using process in browser

var process = module.exports = {};
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = setTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    clearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        setTimeout(drainQueue, 0);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],17:[function(require,module,exports){
module.exports = require("./lib/_stream_duplex.js")

},{"./lib/_stream_duplex.js":18}],18:[function(require,module,exports){
// a duplex stream is just a stream that is both readable and writable.
// Since JS doesn't have multiple prototypal inheritance, this class
// prototypally inherits from Readable, and then parasitically from
// Writable.

'use strict';

/*<replacement>*/

var objectKeys = Object.keys || function (obj) {
  var keys = [];
  for (var key in obj) {
    keys.push(key);
  }return keys;
};
/*</replacement>*/

module.exports = Duplex;

/*<replacement>*/
var processNextTick = require('process-nextick-args');
/*</replacement>*/

/*<replacement>*/
var util = require('core-util-is');
util.inherits = require('inherits');
/*</replacement>*/

var Readable = require('./_stream_readable');
var Writable = require('./_stream_writable');

util.inherits(Duplex, Readable);

var keys = objectKeys(Writable.prototype);
for (var v = 0; v < keys.length; v++) {
  var method = keys[v];
  if (!Duplex.prototype[method]) Duplex.prototype[method] = Writable.prototype[method];
}

function Duplex(options) {
  if (!(this instanceof Duplex)) return new Duplex(options);

  Readable.call(this, options);
  Writable.call(this, options);

  if (options && options.readable === false) this.readable = false;

  if (options && options.writable === false) this.writable = false;

  this.allowHalfOpen = true;
  if (options && options.allowHalfOpen === false) this.allowHalfOpen = false;

  this.once('end', onend);
}

// the no-half-open enforcer
function onend() {
  // if we allow half-open state, or if the writable side ended,
  // then we're ok.
  if (this.allowHalfOpen || this._writableState.ended) return;

  // no more data can be written.
  // But allow more writes to happen in this tick.
  processNextTick(onEndNT, this);
}

function onEndNT(self) {
  self.end();
}

function forEach(xs, f) {
  for (var i = 0, l = xs.length; i < l; i++) {
    f(xs[i], i);
  }
}
},{"./_stream_readable":20,"./_stream_writable":22,"core-util-is":23,"inherits":14,"process-nextick-args":25}],19:[function(require,module,exports){
// a passthrough stream.
// basically just the most minimal sort of Transform stream.
// Every written chunk gets output as-is.

'use strict';

module.exports = PassThrough;

var Transform = require('./_stream_transform');

/*<replacement>*/
var util = require('core-util-is');
util.inherits = require('inherits');
/*</replacement>*/

util.inherits(PassThrough, Transform);

function PassThrough(options) {
  if (!(this instanceof PassThrough)) return new PassThrough(options);

  Transform.call(this, options);
}

PassThrough.prototype._transform = function (chunk, encoding, cb) {
  cb(null, chunk);
};
},{"./_stream_transform":21,"core-util-is":23,"inherits":14}],20:[function(require,module,exports){
(function (process){
'use strict';

module.exports = Readable;

/*<replacement>*/
var processNextTick = require('process-nextick-args');
/*</replacement>*/

/*<replacement>*/
var isArray = require('isarray');
/*</replacement>*/

/*<replacement>*/
var Buffer = require('buffer').Buffer;
/*</replacement>*/

Readable.ReadableState = ReadableState;

var EE = require('events');

/*<replacement>*/
var EElistenerCount = function (emitter, type) {
  return emitter.listeners(type).length;
};
/*</replacement>*/

/*<replacement>*/
var Stream;
(function () {
  try {
    Stream = require('st' + 'ream');
  } catch (_) {} finally {
    if (!Stream) Stream = require('events').EventEmitter;
  }
})();
/*</replacement>*/

var Buffer = require('buffer').Buffer;

/*<replacement>*/
var util = require('core-util-is');
util.inherits = require('inherits');
/*</replacement>*/

/*<replacement>*/
var debugUtil = require('util');
var debug = undefined;
if (debugUtil && debugUtil.debuglog) {
  debug = debugUtil.debuglog('stream');
} else {
  debug = function () {};
}
/*</replacement>*/

var StringDecoder;

util.inherits(Readable, Stream);

var Duplex;
function ReadableState(options, stream) {
  Duplex = Duplex || require('./_stream_duplex');

  options = options || {};

  // object stream flag. Used to make read(n) ignore n and to
  // make all the buffer merging and length checks go away
  this.objectMode = !!options.objectMode;

  if (stream instanceof Duplex) this.objectMode = this.objectMode || !!options.readableObjectMode;

  // the point at which it stops calling _read() to fill the buffer
  // Note: 0 is a valid value, means "don't call _read preemptively ever"
  var hwm = options.highWaterMark;
  var defaultHwm = this.objectMode ? 16 : 16 * 1024;
  this.highWaterMark = hwm || hwm === 0 ? hwm : defaultHwm;

  // cast to ints.
  this.highWaterMark = ~ ~this.highWaterMark;

  this.buffer = [];
  this.length = 0;
  this.pipes = null;
  this.pipesCount = 0;
  this.flowing = null;
  this.ended = false;
  this.endEmitted = false;
  this.reading = false;

  // a flag to be able to tell if the onwrite cb is called immediately,
  // or on a later tick.  We set this to true at first, because any
  // actions that shouldn't happen until "later" should generally also
  // not happen before the first write call.
  this.sync = true;

  // whenever we return null, then we set a flag to say
  // that we're awaiting a 'readable' event emission.
  this.needReadable = false;
  this.emittedReadable = false;
  this.readableListening = false;
  this.resumeScheduled = false;

  // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.
  this.defaultEncoding = options.defaultEncoding || 'utf8';

  // when piping, we only care about 'readable' events that happen
  // after read()ing all the bytes and not getting any pushback.
  this.ranOut = false;

  // the number of writers that are awaiting a drain event in .pipe()s
  this.awaitDrain = 0;

  // if true, a maybeReadMore has been scheduled
  this.readingMore = false;

  this.decoder = null;
  this.encoding = null;
  if (options.encoding) {
    if (!StringDecoder) StringDecoder = require('string_decoder/').StringDecoder;
    this.decoder = new StringDecoder(options.encoding);
    this.encoding = options.encoding;
  }
}

var Duplex;
function Readable(options) {
  Duplex = Duplex || require('./_stream_duplex');

  if (!(this instanceof Readable)) return new Readable(options);

  this._readableState = new ReadableState(options, this);

  // legacy
  this.readable = true;

  if (options && typeof options.read === 'function') this._read = options.read;

  Stream.call(this);
}

// Manually shove something into the read() buffer.
// This returns true if the highWaterMark has not been hit yet,
// similar to how Writable.write() returns true if you should
// write() some more.
Readable.prototype.push = function (chunk, encoding) {
  var state = this._readableState;

  if (!state.objectMode && typeof chunk === 'string') {
    encoding = encoding || state.defaultEncoding;
    if (encoding !== state.encoding) {
      chunk = new Buffer(chunk, encoding);
      encoding = '';
    }
  }

  return readableAddChunk(this, state, chunk, encoding, false);
};

// Unshift should *always* be something directly out of read()
Readable.prototype.unshift = function (chunk) {
  var state = this._readableState;
  return readableAddChunk(this, state, chunk, '', true);
};

Readable.prototype.isPaused = function () {
  return this._readableState.flowing === false;
};

function readableAddChunk(stream, state, chunk, encoding, addToFront) {
  var er = chunkInvalid(state, chunk);
  if (er) {
    stream.emit('error', er);
  } else if (chunk === null) {
    state.reading = false;
    onEofChunk(stream, state);
  } else if (state.objectMode || chunk && chunk.length > 0) {
    if (state.ended && !addToFront) {
      var e = new Error('stream.push() after EOF');
      stream.emit('error', e);
    } else if (state.endEmitted && addToFront) {
      var e = new Error('stream.unshift() after end event');
      stream.emit('error', e);
    } else {
      var skipAdd;
      if (state.decoder && !addToFront && !encoding) {
        chunk = state.decoder.write(chunk);
        skipAdd = !state.objectMode && chunk.length === 0;
      }

      if (!addToFront) state.reading = false;

      // Don't add to the buffer if we've decoded to an empty string chunk and
      // we're not in object mode
      if (!skipAdd) {
        // if we want the data now, just emit it.
        if (state.flowing && state.length === 0 && !state.sync) {
          stream.emit('data', chunk);
          stream.read(0);
        } else {
          // update the buffer info.
          state.length += state.objectMode ? 1 : chunk.length;
          if (addToFront) state.buffer.unshift(chunk);else state.buffer.push(chunk);

          if (state.needReadable) emitReadable(stream);
        }
      }

      maybeReadMore(stream, state);
    }
  } else if (!addToFront) {
    state.reading = false;
  }

  return needMoreData(state);
}

// if it's past the high water mark, we can push in some more.
// Also, if we have no data yet, we can stand some
// more bytes.  This is to work around cases where hwm=0,
// such as the repl.  Also, if the push() triggered a
// readable event, and the user called read(largeNumber) such that
// needReadable was set, then we ought to push more, so that another
// 'readable' event will be triggered.
function needMoreData(state) {
  return !state.ended && (state.needReadable || state.length < state.highWaterMark || state.length === 0);
}

// backwards compatibility.
Readable.prototype.setEncoding = function (enc) {
  if (!StringDecoder) StringDecoder = require('string_decoder/').StringDecoder;
  this._readableState.decoder = new StringDecoder(enc);
  this._readableState.encoding = enc;
  return this;
};

// Don't raise the hwm > 8MB
var MAX_HWM = 0x800000;
function computeNewHighWaterMark(n) {
  if (n >= MAX_HWM) {
    n = MAX_HWM;
  } else {
    // Get the next highest power of 2
    n--;
    n |= n >>> 1;
    n |= n >>> 2;
    n |= n >>> 4;
    n |= n >>> 8;
    n |= n >>> 16;
    n++;
  }
  return n;
}

function howMuchToRead(n, state) {
  if (state.length === 0 && state.ended) return 0;

  if (state.objectMode) return n === 0 ? 0 : 1;

  if (n === null || isNaN(n)) {
    // only flow one buffer at a time
    if (state.flowing && state.buffer.length) return state.buffer[0].length;else return state.length;
  }

  if (n <= 0) return 0;

  // If we're asking for more than the target buffer level,
  // then raise the water mark.  Bump up to the next highest
  // power of 2, to prevent increasing it excessively in tiny
  // amounts.
  if (n > state.highWaterMark) state.highWaterMark = computeNewHighWaterMark(n);

  // don't have that much.  return null, unless we've ended.
  if (n > state.length) {
    if (!state.ended) {
      state.needReadable = true;
      return 0;
    } else {
      return state.length;
    }
  }

  return n;
}

// you can override either this method, or the async _read(n) below.
Readable.prototype.read = function (n) {
  debug('read', n);
  var state = this._readableState;
  var nOrig = n;

  if (typeof n !== 'number' || n > 0) state.emittedReadable = false;

  // if we're doing read(0) to trigger a readable event, but we
  // already have a bunch of data in the buffer, then just trigger
  // the 'readable' event and move on.
  if (n === 0 && state.needReadable && (state.length >= state.highWaterMark || state.ended)) {
    debug('read: emitReadable', state.length, state.ended);
    if (state.length === 0 && state.ended) endReadable(this);else emitReadable(this);
    return null;
  }

  n = howMuchToRead(n, state);

  // if we've ended, and we're now clear, then finish it up.
  if (n === 0 && state.ended) {
    if (state.length === 0) endReadable(this);
    return null;
  }

  // All the actual chunk generation logic needs to be
  // *below* the call to _read.  The reason is that in certain
  // synthetic stream cases, such as passthrough streams, _read
  // may be a completely synchronous operation which may change
  // the state of the read buffer, providing enough data when
  // before there was *not* enough.
  //
  // So, the steps are:
  // 1. Figure out what the state of things will be after we do
  // a read from the buffer.
  //
  // 2. If that resulting state will trigger a _read, then call _read.
  // Note that this may be asynchronous, or synchronous.  Yes, it is
  // deeply ugly to write APIs this way, but that still doesn't mean
  // that the Readable class should behave improperly, as streams are
  // designed to be sync/async agnostic.
  // Take note if the _read call is sync or async (ie, if the read call
  // has returned yet), so that we know whether or not it's safe to emit
  // 'readable' etc.
  //
  // 3. Actually pull the requested chunks out of the buffer and return.

  // if we need a readable event, then we need to do some reading.
  var doRead = state.needReadable;
  debug('need readable', doRead);

  // if we currently have less than the highWaterMark, then also read some
  if (state.length === 0 || state.length - n < state.highWaterMark) {
    doRead = true;
    debug('length less than watermark', doRead);
  }

  // however, if we've ended, then there's no point, and if we're already
  // reading, then it's unnecessary.
  if (state.ended || state.reading) {
    doRead = false;
    debug('reading or ended', doRead);
  }

  if (doRead) {
    debug('do read');
    state.reading = true;
    state.sync = true;
    // if the length is currently zero, then we *need* a readable event.
    if (state.length === 0) state.needReadable = true;
    // call internal read method
    this._read(state.highWaterMark);
    state.sync = false;
  }

  // If _read pushed data synchronously, then `reading` will be false,
  // and we need to re-evaluate how much data we can return to the user.
  if (doRead && !state.reading) n = howMuchToRead(nOrig, state);

  var ret;
  if (n > 0) ret = fromList(n, state);else ret = null;

  if (ret === null) {
    state.needReadable = true;
    n = 0;
  }

  state.length -= n;

  // If we have nothing in the buffer, then we want to know
  // as soon as we *do* get something into the buffer.
  if (state.length === 0 && !state.ended) state.needReadable = true;

  // If we tried to read() past the EOF, then emit end on the next tick.
  if (nOrig !== n && state.ended && state.length === 0) endReadable(this);

  if (ret !== null) this.emit('data', ret);

  return ret;
};

function chunkInvalid(state, chunk) {
  var er = null;
  if (!Buffer.isBuffer(chunk) && typeof chunk !== 'string' && chunk !== null && chunk !== undefined && !state.objectMode) {
    er = new TypeError('Invalid non-string/buffer chunk');
  }
  return er;
}

function onEofChunk(stream, state) {
  if (state.ended) return;
  if (state.decoder) {
    var chunk = state.decoder.end();
    if (chunk && chunk.length) {
      state.buffer.push(chunk);
      state.length += state.objectMode ? 1 : chunk.length;
    }
  }
  state.ended = true;

  // emit 'readable' now to make sure it gets picked up.
  emitReadable(stream);
}

// Don't emit readable right away in sync mode, because this can trigger
// another read() call => stack overflow.  This way, it might trigger
// a nextTick recursion warning, but that's not so bad.
function emitReadable(stream) {
  var state = stream._readableState;
  state.needReadable = false;
  if (!state.emittedReadable) {
    debug('emitReadable', state.flowing);
    state.emittedReadable = true;
    if (state.sync) processNextTick(emitReadable_, stream);else emitReadable_(stream);
  }
}

function emitReadable_(stream) {
  debug('emit readable');
  stream.emit('readable');
  flow(stream);
}

// at this point, the user has presumably seen the 'readable' event,
// and called read() to consume some data.  that may have triggered
// in turn another _read(n) call, in which case reading = true if
// it's in progress.
// However, if we're not ended, or reading, and the length < hwm,
// then go ahead and try to read some more preemptively.
function maybeReadMore(stream, state) {
  if (!state.readingMore) {
    state.readingMore = true;
    processNextTick(maybeReadMore_, stream, state);
  }
}

function maybeReadMore_(stream, state) {
  var len = state.length;
  while (!state.reading && !state.flowing && !state.ended && state.length < state.highWaterMark) {
    debug('maybeReadMore read 0');
    stream.read(0);
    if (len === state.length)
      // didn't get any data, stop spinning.
      break;else len = state.length;
  }
  state.readingMore = false;
}

// abstract method.  to be overridden in specific implementation classes.
// call cb(er, data) where data is <= n in length.
// for virtual (non-string, non-buffer) streams, "length" is somewhat
// arbitrary, and perhaps not very meaningful.
Readable.prototype._read = function (n) {
  this.emit('error', new Error('not implemented'));
};

Readable.prototype.pipe = function (dest, pipeOpts) {
  var src = this;
  var state = this._readableState;

  switch (state.pipesCount) {
    case 0:
      state.pipes = dest;
      break;
    case 1:
      state.pipes = [state.pipes, dest];
      break;
    default:
      state.pipes.push(dest);
      break;
  }
  state.pipesCount += 1;
  debug('pipe count=%d opts=%j', state.pipesCount, pipeOpts);

  var doEnd = (!pipeOpts || pipeOpts.end !== false) && dest !== process.stdout && dest !== process.stderr;

  var endFn = doEnd ? onend : cleanup;
  if (state.endEmitted) processNextTick(endFn);else src.once('end', endFn);

  dest.on('unpipe', onunpipe);
  function onunpipe(readable) {
    debug('onunpipe');
    if (readable === src) {
      cleanup();
    }
  }

  function onend() {
    debug('onend');
    dest.end();
  }

  // when the dest drains, it reduces the awaitDrain counter
  // on the source.  This would be more elegant with a .once()
  // handler in flow(), but adding and removing repeatedly is
  // too slow.
  var ondrain = pipeOnDrain(src);
  dest.on('drain', ondrain);

  var cleanedUp = false;
  function cleanup() {
    debug('cleanup');
    // cleanup event handlers once the pipe is broken
    dest.removeListener('close', onclose);
    dest.removeListener('finish', onfinish);
    dest.removeListener('drain', ondrain);
    dest.removeListener('error', onerror);
    dest.removeListener('unpipe', onunpipe);
    src.removeListener('end', onend);
    src.removeListener('end', cleanup);
    src.removeListener('data', ondata);

    cleanedUp = true;

    // if the reader is waiting for a drain event from this
    // specific writer, then it would cause it to never start
    // flowing again.
    // So, if this is awaiting a drain, then we just call it now.
    // If we don't know, then assume that we are waiting for one.
    if (state.awaitDrain && (!dest._writableState || dest._writableState.needDrain)) ondrain();
  }

  src.on('data', ondata);
  function ondata(chunk) {
    debug('ondata');
    var ret = dest.write(chunk);
    if (false === ret) {
      // If the user unpiped during `dest.write()`, it is possible
      // to get stuck in a permanently paused state if that write
      // also returned false.
      if (state.pipesCount === 1 && state.pipes[0] === dest && src.listenerCount('data') === 1 && !cleanedUp) {
        debug('false write response, pause', src._readableState.awaitDrain);
        src._readableState.awaitDrain++;
      }
      src.pause();
    }
  }

  // if the dest has an error, then stop piping into it.
  // however, don't suppress the throwing behavior for this.
  function onerror(er) {
    debug('onerror', er);
    unpipe();
    dest.removeListener('error', onerror);
    if (EElistenerCount(dest, 'error') === 0) dest.emit('error', er);
  }
  // This is a brutally ugly hack to make sure that our error handler
  // is attached before any userland ones.  NEVER DO THIS.
  if (!dest._events || !dest._events.error) dest.on('error', onerror);else if (isArray(dest._events.error)) dest._events.error.unshift(onerror);else dest._events.error = [onerror, dest._events.error];

  // Both close and finish should trigger unpipe, but only once.
  function onclose() {
    dest.removeListener('finish', onfinish);
    unpipe();
  }
  dest.once('close', onclose);
  function onfinish() {
    debug('onfinish');
    dest.removeListener('close', onclose);
    unpipe();
  }
  dest.once('finish', onfinish);

  function unpipe() {
    debug('unpipe');
    src.unpipe(dest);
  }

  // tell the dest that it's being piped to
  dest.emit('pipe', src);

  // start the flow if it hasn't been started already.
  if (!state.flowing) {
    debug('pipe resume');
    src.resume();
  }

  return dest;
};

function pipeOnDrain(src) {
  return function () {
    var state = src._readableState;
    debug('pipeOnDrain', state.awaitDrain);
    if (state.awaitDrain) state.awaitDrain--;
    if (state.awaitDrain === 0 && EElistenerCount(src, 'data')) {
      state.flowing = true;
      flow(src);
    }
  };
}

Readable.prototype.unpipe = function (dest) {
  var state = this._readableState;

  // if we're not piping anywhere, then do nothing.
  if (state.pipesCount === 0) return this;

  // just one destination.  most common case.
  if (state.pipesCount === 1) {
    // passed in one, but it's not the right one.
    if (dest && dest !== state.pipes) return this;

    if (!dest) dest = state.pipes;

    // got a match.
    state.pipes = null;
    state.pipesCount = 0;
    state.flowing = false;
    if (dest) dest.emit('unpipe', this);
    return this;
  }

  // slow case. multiple pipe destinations.

  if (!dest) {
    // remove all.
    var dests = state.pipes;
    var len = state.pipesCount;
    state.pipes = null;
    state.pipesCount = 0;
    state.flowing = false;

    for (var _i = 0; _i < len; _i++) {
      dests[_i].emit('unpipe', this);
    }return this;
  }

  // try to find the right one.
  var i = indexOf(state.pipes, dest);
  if (i === -1) return this;

  state.pipes.splice(i, 1);
  state.pipesCount -= 1;
  if (state.pipesCount === 1) state.pipes = state.pipes[0];

  dest.emit('unpipe', this);

  return this;
};

// set up data events if they are asked for
// Ensure readable listeners eventually get something
Readable.prototype.on = function (ev, fn) {
  var res = Stream.prototype.on.call(this, ev, fn);

  // If listening to data, and it has not explicitly been paused,
  // then call resume to start the flow of data on the next tick.
  if (ev === 'data' && false !== this._readableState.flowing) {
    this.resume();
  }

  if (ev === 'readable' && !this._readableState.endEmitted) {
    var state = this._readableState;
    if (!state.readableListening) {
      state.readableListening = true;
      state.emittedReadable = false;
      state.needReadable = true;
      if (!state.reading) {
        processNextTick(nReadingNextTick, this);
      } else if (state.length) {
        emitReadable(this, state);
      }
    }
  }

  return res;
};
Readable.prototype.addListener = Readable.prototype.on;

function nReadingNextTick(self) {
  debug('readable nexttick read 0');
  self.read(0);
}

// pause() and resume() are remnants of the legacy readable stream API
// If the user uses them, then switch into old mode.
Readable.prototype.resume = function () {
  var state = this._readableState;
  if (!state.flowing) {
    debug('resume');
    state.flowing = true;
    resume(this, state);
  }
  return this;
};

function resume(stream, state) {
  if (!state.resumeScheduled) {
    state.resumeScheduled = true;
    processNextTick(resume_, stream, state);
  }
}

function resume_(stream, state) {
  if (!state.reading) {
    debug('resume read 0');
    stream.read(0);
  }

  state.resumeScheduled = false;
  stream.emit('resume');
  flow(stream);
  if (state.flowing && !state.reading) stream.read(0);
}

Readable.prototype.pause = function () {
  debug('call pause flowing=%j', this._readableState.flowing);
  if (false !== this._readableState.flowing) {
    debug('pause');
    this._readableState.flowing = false;
    this.emit('pause');
  }
  return this;
};

function flow(stream) {
  var state = stream._readableState;
  debug('flow', state.flowing);
  if (state.flowing) {
    do {
      var chunk = stream.read();
    } while (null !== chunk && state.flowing);
  }
}

// wrap an old-style stream as the async data source.
// This is *not* part of the readable stream interface.
// It is an ugly unfortunate mess of history.
Readable.prototype.wrap = function (stream) {
  var state = this._readableState;
  var paused = false;

  var self = this;
  stream.on('end', function () {
    debug('wrapped end');
    if (state.decoder && !state.ended) {
      var chunk = state.decoder.end();
      if (chunk && chunk.length) self.push(chunk);
    }

    self.push(null);
  });

  stream.on('data', function (chunk) {
    debug('wrapped data');
    if (state.decoder) chunk = state.decoder.write(chunk);

    // don't skip over falsy values in objectMode
    if (state.objectMode && (chunk === null || chunk === undefined)) return;else if (!state.objectMode && (!chunk || !chunk.length)) return;

    var ret = self.push(chunk);
    if (!ret) {
      paused = true;
      stream.pause();
    }
  });

  // proxy all the other methods.
  // important when wrapping filters and duplexes.
  for (var i in stream) {
    if (this[i] === undefined && typeof stream[i] === 'function') {
      this[i] = function (method) {
        return function () {
          return stream[method].apply(stream, arguments);
        };
      }(i);
    }
  }

  // proxy certain important events.
  var events = ['error', 'close', 'destroy', 'pause', 'resume'];
  forEach(events, function (ev) {
    stream.on(ev, self.emit.bind(self, ev));
  });

  // when we try to consume some more bytes, simply unpause the
  // underlying stream.
  self._read = function (n) {
    debug('wrapped _read', n);
    if (paused) {
      paused = false;
      stream.resume();
    }
  };

  return self;
};

// exposed for testing purposes only.
Readable._fromList = fromList;

// Pluck off n bytes from an array of buffers.
// Length is the combined lengths of all the buffers in the list.
function fromList(n, state) {
  var list = state.buffer;
  var length = state.length;
  var stringMode = !!state.decoder;
  var objectMode = !!state.objectMode;
  var ret;

  // nothing in the list, definitely empty.
  if (list.length === 0) return null;

  if (length === 0) ret = null;else if (objectMode) ret = list.shift();else if (!n || n >= length) {
    // read it all, truncate the array.
    if (stringMode) ret = list.join('');else if (list.length === 1) ret = list[0];else ret = Buffer.concat(list, length);
    list.length = 0;
  } else {
    // read just some of it.
    if (n < list[0].length) {
      // just take a part of the first list item.
      // slice is the same for buffers and strings.
      var buf = list[0];
      ret = buf.slice(0, n);
      list[0] = buf.slice(n);
    } else if (n === list[0].length) {
      // first list is a perfect match
      ret = list.shift();
    } else {
      // complex case.
      // we have enough to cover it, but it spans past the first buffer.
      if (stringMode) ret = '';else ret = new Buffer(n);

      var c = 0;
      for (var i = 0, l = list.length; i < l && c < n; i++) {
        var buf = list[0];
        var cpy = Math.min(n - c, buf.length);

        if (stringMode) ret += buf.slice(0, cpy);else buf.copy(ret, c, 0, cpy);

        if (cpy < buf.length) list[0] = buf.slice(cpy);else list.shift();

        c += cpy;
      }
    }
  }

  return ret;
}

function endReadable(stream) {
  var state = stream._readableState;

  // If we get here before consuming all the bytes, then that is a
  // bug in node.  Should never happen.
  if (state.length > 0) throw new Error('endReadable called on non-empty stream');

  if (!state.endEmitted) {
    state.ended = true;
    processNextTick(endReadableNT, state, stream);
  }
}

function endReadableNT(state, stream) {
  // Check that we didn't get one last unshift.
  if (!state.endEmitted && state.length === 0) {
    state.endEmitted = true;
    stream.readable = false;
    stream.emit('end');
  }
}

function forEach(xs, f) {
  for (var i = 0, l = xs.length; i < l; i++) {
    f(xs[i], i);
  }
}

function indexOf(xs, x) {
  for (var i = 0, l = xs.length; i < l; i++) {
    if (xs[i] === x) return i;
  }
  return -1;
}
}).call(this,require('_process'))
},{"./_stream_duplex":18,"_process":16,"buffer":9,"core-util-is":23,"events":13,"inherits":14,"isarray":24,"process-nextick-args":25,"string_decoder/":32,"util":8}],21:[function(require,module,exports){
// a transform stream is a readable/writable stream where you do
// something with the data.  Sometimes it's called a "filter",
// but that's not a great name for it, since that implies a thing where
// some bits pass through, and others are simply ignored.  (That would
// be a valid example of a transform, of course.)
//
// While the output is causally related to the input, it's not a
// necessarily symmetric or synchronous transformation.  For example,
// a zlib stream might take multiple plain-text writes(), and then
// emit a single compressed chunk some time in the future.
//
// Here's how this works:
//
// The Transform stream has all the aspects of the readable and writable
// stream classes.  When you write(chunk), that calls _write(chunk,cb)
// internally, and returns false if there's a lot of pending writes
// buffered up.  When you call read(), that calls _read(n) until
// there's enough pending readable data buffered up.
//
// In a transform stream, the written data is placed in a buffer.  When
// _read(n) is called, it transforms the queued up data, calling the
// buffered _write cb's as it consumes chunks.  If consuming a single
// written chunk would result in multiple output chunks, then the first
// outputted bit calls the readcb, and subsequent chunks just go into
// the read buffer, and will cause it to emit 'readable' if necessary.
//
// This way, back-pressure is actually determined by the reading side,
// since _read has to be called to start processing a new chunk.  However,
// a pathological inflate type of transform can cause excessive buffering
// here.  For example, imagine a stream where every byte of input is
// interpreted as an integer from 0-255, and then results in that many
// bytes of output.  Writing the 4 bytes {ff,ff,ff,ff} would result in
// 1kb of data being output.  In this case, you could write a very small
// amount of input, and end up with a very large amount of output.  In
// such a pathological inflating mechanism, there'd be no way to tell
// the system to stop doing the transform.  A single 4MB write could
// cause the system to run out of memory.
//
// However, even in such a pathological case, only a single written chunk
// would be consumed, and then the rest would wait (un-transformed) until
// the results of the previous transformed chunk were consumed.

'use strict';

module.exports = Transform;

var Duplex = require('./_stream_duplex');

/*<replacement>*/
var util = require('core-util-is');
util.inherits = require('inherits');
/*</replacement>*/

util.inherits(Transform, Duplex);

function TransformState(stream) {
  this.afterTransform = function (er, data) {
    return afterTransform(stream, er, data);
  };

  this.needTransform = false;
  this.transforming = false;
  this.writecb = null;
  this.writechunk = null;
  this.writeencoding = null;
}

function afterTransform(stream, er, data) {
  var ts = stream._transformState;
  ts.transforming = false;

  var cb = ts.writecb;

  if (!cb) return stream.emit('error', new Error('no writecb in Transform class'));

  ts.writechunk = null;
  ts.writecb = null;

  if (data !== null && data !== undefined) stream.push(data);

  cb(er);

  var rs = stream._readableState;
  rs.reading = false;
  if (rs.needReadable || rs.length < rs.highWaterMark) {
    stream._read(rs.highWaterMark);
  }
}

function Transform(options) {
  if (!(this instanceof Transform)) return new Transform(options);

  Duplex.call(this, options);

  this._transformState = new TransformState(this);

  // when the writable side finishes, then flush out anything remaining.
  var stream = this;

  // start out asking for a readable event once data is transformed.
  this._readableState.needReadable = true;

  // we have implemented the _read method, and done the other things
  // that Readable wants before the first _read call, so unset the
  // sync guard flag.
  this._readableState.sync = false;

  if (options) {
    if (typeof options.transform === 'function') this._transform = options.transform;

    if (typeof options.flush === 'function') this._flush = options.flush;
  }

  this.once('prefinish', function () {
    if (typeof this._flush === 'function') this._flush(function (er) {
      done(stream, er);
    });else done(stream);
  });
}

Transform.prototype.push = function (chunk, encoding) {
  this._transformState.needTransform = false;
  return Duplex.prototype.push.call(this, chunk, encoding);
};

// This is the part where you do stuff!
// override this function in implementation classes.
// 'chunk' is an input chunk.
//
// Call `push(newChunk)` to pass along transformed output
// to the readable side.  You may call 'push' zero or more times.
//
// Call `cb(err)` when you are done with this chunk.  If you pass
// an error, then that'll put the hurt on the whole operation.  If you
// never call cb(), then you'll never get another chunk.
Transform.prototype._transform = function (chunk, encoding, cb) {
  throw new Error('not implemented');
};

Transform.prototype._write = function (chunk, encoding, cb) {
  var ts = this._transformState;
  ts.writecb = cb;
  ts.writechunk = chunk;
  ts.writeencoding = encoding;
  if (!ts.transforming) {
    var rs = this._readableState;
    if (ts.needTransform || rs.needReadable || rs.length < rs.highWaterMark) this._read(rs.highWaterMark);
  }
};

// Doesn't matter what the args are here.
// _transform does all the work.
// That we got here means that the readable side wants more data.
Transform.prototype._read = function (n) {
  var ts = this._transformState;

  if (ts.writechunk !== null && ts.writecb && !ts.transforming) {
    ts.transforming = true;
    this._transform(ts.writechunk, ts.writeencoding, ts.afterTransform);
  } else {
    // mark that we need a transform, so that any data that comes in
    // will get processed, now that we've asked for it.
    ts.needTransform = true;
  }
};

function done(stream, er) {
  if (er) return stream.emit('error', er);

  // if there's nothing in the write buffer, then that means
  // that nothing more will ever be provided
  var ws = stream._writableState;
  var ts = stream._transformState;

  if (ws.length) throw new Error('calling transform done when ws.length != 0');

  if (ts.transforming) throw new Error('calling transform done when still transforming');

  return stream.push(null);
}
},{"./_stream_duplex":18,"core-util-is":23,"inherits":14}],22:[function(require,module,exports){
(function (process){
// A bit simpler than readable streams.
// Implement an async ._write(chunk, encoding, cb), and it'll handle all
// the drain event emission and buffering.

'use strict';

module.exports = Writable;

/*<replacement>*/
var processNextTick = require('process-nextick-args');
/*</replacement>*/

/*<replacement>*/
var asyncWrite = !process.browser && ['v0.10', 'v0.9.'].indexOf(process.version.slice(0, 5)) > -1 ? setImmediate : processNextTick;
/*</replacement>*/

/*<replacement>*/
var Buffer = require('buffer').Buffer;
/*</replacement>*/

Writable.WritableState = WritableState;

/*<replacement>*/
var util = require('core-util-is');
util.inherits = require('inherits');
/*</replacement>*/

/*<replacement>*/
var internalUtil = {
  deprecate: require('util-deprecate')
};
/*</replacement>*/

/*<replacement>*/
var Stream;
(function () {
  try {
    Stream = require('st' + 'ream');
  } catch (_) {} finally {
    if (!Stream) Stream = require('events').EventEmitter;
  }
})();
/*</replacement>*/

var Buffer = require('buffer').Buffer;

util.inherits(Writable, Stream);

function nop() {}

function WriteReq(chunk, encoding, cb) {
  this.chunk = chunk;
  this.encoding = encoding;
  this.callback = cb;
  this.next = null;
}

var Duplex;
function WritableState(options, stream) {
  Duplex = Duplex || require('./_stream_duplex');

  options = options || {};

  // object stream flag to indicate whether or not this stream
  // contains buffers or objects.
  this.objectMode = !!options.objectMode;

  if (stream instanceof Duplex) this.objectMode = this.objectMode || !!options.writableObjectMode;

  // the point at which write() starts returning false
  // Note: 0 is a valid value, means that we always return false if
  // the entire buffer is not flushed immediately on write()
  var hwm = options.highWaterMark;
  var defaultHwm = this.objectMode ? 16 : 16 * 1024;
  this.highWaterMark = hwm || hwm === 0 ? hwm : defaultHwm;

  // cast to ints.
  this.highWaterMark = ~ ~this.highWaterMark;

  this.needDrain = false;
  // at the start of calling end()
  this.ending = false;
  // when end() has been called, and returned
  this.ended = false;
  // when 'finish' is emitted
  this.finished = false;

  // should we decode strings into buffers before passing to _write?
  // this is here so that some node-core streams can optimize string
  // handling at a lower level.
  var noDecode = options.decodeStrings === false;
  this.decodeStrings = !noDecode;

  // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.
  this.defaultEncoding = options.defaultEncoding || 'utf8';

  // not an actual buffer we keep track of, but a measurement
  // of how much we're waiting to get pushed to some underlying
  // socket or file.
  this.length = 0;

  // a flag to see when we're in the middle of a write.
  this.writing = false;

  // when true all writes will be buffered until .uncork() call
  this.corked = 0;

  // a flag to be able to tell if the onwrite cb is called immediately,
  // or on a later tick.  We set this to true at first, because any
  // actions that shouldn't happen until "later" should generally also
  // not happen before the first write call.
  this.sync = true;

  // a flag to know if we're processing previously buffered items, which
  // may call the _write() callback in the same tick, so that we don't
  // end up in an overlapped onwrite situation.
  this.bufferProcessing = false;

  // the callback that's passed to _write(chunk,cb)
  this.onwrite = function (er) {
    onwrite(stream, er);
  };

  // the callback that the user supplies to write(chunk,encoding,cb)
  this.writecb = null;

  // the amount that is being written when _write is called.
  this.writelen = 0;

  this.bufferedRequest = null;
  this.lastBufferedRequest = null;

  // number of pending user-supplied write callbacks
  // this must be 0 before 'finish' can be emitted
  this.pendingcb = 0;

  // emit prefinish if the only thing we're waiting for is _write cbs
  // This is relevant for synchronous Transform streams
  this.prefinished = false;

  // True if the error was already emitted and should not be thrown again
  this.errorEmitted = false;

  // count buffered requests
  this.bufferedRequestCount = 0;

  // create the two objects needed to store the corked requests
  // they are not a linked list, as no new elements are inserted in there
  this.corkedRequestsFree = new CorkedRequest(this);
  this.corkedRequestsFree.next = new CorkedRequest(this);
}

WritableState.prototype.getBuffer = function writableStateGetBuffer() {
  var current = this.bufferedRequest;
  var out = [];
  while (current) {
    out.push(current);
    current = current.next;
  }
  return out;
};

(function () {
  try {
    Object.defineProperty(WritableState.prototype, 'buffer', {
      get: internalUtil.deprecate(function () {
        return this.getBuffer();
      }, '_writableState.buffer is deprecated. Use _writableState.getBuffer ' + 'instead.')
    });
  } catch (_) {}
})();

var Duplex;
function Writable(options) {
  Duplex = Duplex || require('./_stream_duplex');

  // Writable ctor is applied to Duplexes, though they're not
  // instanceof Writable, they're instanceof Readable.
  if (!(this instanceof Writable) && !(this instanceof Duplex)) return new Writable(options);

  this._writableState = new WritableState(options, this);

  // legacy.
  this.writable = true;

  if (options) {
    if (typeof options.write === 'function') this._write = options.write;

    if (typeof options.writev === 'function') this._writev = options.writev;
  }

  Stream.call(this);
}

// Otherwise people can pipe Writable streams, which is just wrong.
Writable.prototype.pipe = function () {
  this.emit('error', new Error('Cannot pipe. Not readable.'));
};

function writeAfterEnd(stream, cb) {
  var er = new Error('write after end');
  // TODO: defer error events consistently everywhere, not just the cb
  stream.emit('error', er);
  processNextTick(cb, er);
}

// If we get something that is not a buffer, string, null, or undefined,
// and we're not in objectMode, then that's an error.
// Otherwise stream chunks are all considered to be of length=1, and the
// watermarks determine how many objects to keep in the buffer, rather than
// how many bytes or characters.
function validChunk(stream, state, chunk, cb) {
  var valid = true;

  if (!Buffer.isBuffer(chunk) && typeof chunk !== 'string' && chunk !== null && chunk !== undefined && !state.objectMode) {
    var er = new TypeError('Invalid non-string/buffer chunk');
    stream.emit('error', er);
    processNextTick(cb, er);
    valid = false;
  }
  return valid;
}

Writable.prototype.write = function (chunk, encoding, cb) {
  var state = this._writableState;
  var ret = false;

  if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }

  if (Buffer.isBuffer(chunk)) encoding = 'buffer';else if (!encoding) encoding = state.defaultEncoding;

  if (typeof cb !== 'function') cb = nop;

  if (state.ended) writeAfterEnd(this, cb);else if (validChunk(this, state, chunk, cb)) {
    state.pendingcb++;
    ret = writeOrBuffer(this, state, chunk, encoding, cb);
  }

  return ret;
};

Writable.prototype.cork = function () {
  var state = this._writableState;

  state.corked++;
};

Writable.prototype.uncork = function () {
  var state = this._writableState;

  if (state.corked) {
    state.corked--;

    if (!state.writing && !state.corked && !state.finished && !state.bufferProcessing && state.bufferedRequest) clearBuffer(this, state);
  }
};

Writable.prototype.setDefaultEncoding = function setDefaultEncoding(encoding) {
  // node::ParseEncoding() requires lower case.
  if (typeof encoding === 'string') encoding = encoding.toLowerCase();
  if (!(['hex', 'utf8', 'utf-8', 'ascii', 'binary', 'base64', 'ucs2', 'ucs-2', 'utf16le', 'utf-16le', 'raw'].indexOf((encoding + '').toLowerCase()) > -1)) throw new TypeError('Unknown encoding: ' + encoding);
  this._writableState.defaultEncoding = encoding;
};

function decodeChunk(state, chunk, encoding) {
  if (!state.objectMode && state.decodeStrings !== false && typeof chunk === 'string') {
    chunk = new Buffer(chunk, encoding);
  }
  return chunk;
}

// if we're already writing something, then just put this
// in the queue, and wait our turn.  Otherwise, call _write
// If we return false, then we need a drain event, so set that flag.
function writeOrBuffer(stream, state, chunk, encoding, cb) {
  chunk = decodeChunk(state, chunk, encoding);

  if (Buffer.isBuffer(chunk)) encoding = 'buffer';
  var len = state.objectMode ? 1 : chunk.length;

  state.length += len;

  var ret = state.length < state.highWaterMark;
  // we must ensure that previous needDrain will not be reset to false.
  if (!ret) state.needDrain = true;

  if (state.writing || state.corked) {
    var last = state.lastBufferedRequest;
    state.lastBufferedRequest = new WriteReq(chunk, encoding, cb);
    if (last) {
      last.next = state.lastBufferedRequest;
    } else {
      state.bufferedRequest = state.lastBufferedRequest;
    }
    state.bufferedRequestCount += 1;
  } else {
    doWrite(stream, state, false, len, chunk, encoding, cb);
  }

  return ret;
}

function doWrite(stream, state, writev, len, chunk, encoding, cb) {
  state.writelen = len;
  state.writecb = cb;
  state.writing = true;
  state.sync = true;
  if (writev) stream._writev(chunk, state.onwrite);else stream._write(chunk, encoding, state.onwrite);
  state.sync = false;
}

function onwriteError(stream, state, sync, er, cb) {
  --state.pendingcb;
  if (sync) processNextTick(cb, er);else cb(er);

  stream._writableState.errorEmitted = true;
  stream.emit('error', er);
}

function onwriteStateUpdate(state) {
  state.writing = false;
  state.writecb = null;
  state.length -= state.writelen;
  state.writelen = 0;
}

function onwrite(stream, er) {
  var state = stream._writableState;
  var sync = state.sync;
  var cb = state.writecb;

  onwriteStateUpdate(state);

  if (er) onwriteError(stream, state, sync, er, cb);else {
    // Check if we're actually ready to finish, but don't emit yet
    var finished = needFinish(state);

    if (!finished && !state.corked && !state.bufferProcessing && state.bufferedRequest) {
      clearBuffer(stream, state);
    }

    if (sync) {
      /*<replacement>*/
      asyncWrite(afterWrite, stream, state, finished, cb);
      /*</replacement>*/
    } else {
        afterWrite(stream, state, finished, cb);
      }
  }
}

function afterWrite(stream, state, finished, cb) {
  if (!finished) onwriteDrain(stream, state);
  state.pendingcb--;
  cb();
  finishMaybe(stream, state);
}

// Must force callback to be called on nextTick, so that we don't
// emit 'drain' before the write() consumer gets the 'false' return
// value, and has a chance to attach a 'drain' listener.
function onwriteDrain(stream, state) {
  if (state.length === 0 && state.needDrain) {
    state.needDrain = false;
    stream.emit('drain');
  }
}

// if there's something in the buffer waiting, then process it
function clearBuffer(stream, state) {
  state.bufferProcessing = true;
  var entry = state.bufferedRequest;

  if (stream._writev && entry && entry.next) {
    // Fast case, write everything using _writev()
    var l = state.bufferedRequestCount;
    var buffer = new Array(l);
    var holder = state.corkedRequestsFree;
    holder.entry = entry;

    var count = 0;
    while (entry) {
      buffer[count] = entry;
      entry = entry.next;
      count += 1;
    }

    doWrite(stream, state, true, state.length, buffer, '', holder.finish);

    // doWrite is always async, defer these to save a bit of time
    // as the hot path ends with doWrite
    state.pendingcb++;
    state.lastBufferedRequest = null;
    state.corkedRequestsFree = holder.next;
    holder.next = null;
  } else {
    // Slow case, write chunks one-by-one
    while (entry) {
      var chunk = entry.chunk;
      var encoding = entry.encoding;
      var cb = entry.callback;
      var len = state.objectMode ? 1 : chunk.length;

      doWrite(stream, state, false, len, chunk, encoding, cb);
      entry = entry.next;
      // if we didn't call the onwrite immediately, then
      // it means that we need to wait until it does.
      // also, that means that the chunk and cb are currently
      // being processed, so move the buffer counter past them.
      if (state.writing) {
        break;
      }
    }

    if (entry === null) state.lastBufferedRequest = null;
  }

  state.bufferedRequestCount = 0;
  state.bufferedRequest = entry;
  state.bufferProcessing = false;
}

Writable.prototype._write = function (chunk, encoding, cb) {
  cb(new Error('not implemented'));
};

Writable.prototype._writev = null;

Writable.prototype.end = function (chunk, encoding, cb) {
  var state = this._writableState;

  if (typeof chunk === 'function') {
    cb = chunk;
    chunk = null;
    encoding = null;
  } else if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }

  if (chunk !== null && chunk !== undefined) this.write(chunk, encoding);

  // .end() fully uncorks
  if (state.corked) {
    state.corked = 1;
    this.uncork();
  }

  // ignore unnecessary end() calls.
  if (!state.ending && !state.finished) endWritable(this, state, cb);
};

function needFinish(state) {
  return state.ending && state.length === 0 && state.bufferedRequest === null && !state.finished && !state.writing;
}

function prefinish(stream, state) {
  if (!state.prefinished) {
    state.prefinished = true;
    stream.emit('prefinish');
  }
}

function finishMaybe(stream, state) {
  var need = needFinish(state);
  if (need) {
    if (state.pendingcb === 0) {
      prefinish(stream, state);
      state.finished = true;
      stream.emit('finish');
    } else {
      prefinish(stream, state);
    }
  }
  return need;
}

function endWritable(stream, state, cb) {
  state.ending = true;
  finishMaybe(stream, state);
  if (cb) {
    if (state.finished) processNextTick(cb);else stream.once('finish', cb);
  }
  state.ended = true;
  stream.writable = false;
}

// It seems a linked list but it is not
// there will be only 2 of these for each stream
function CorkedRequest(state) {
  var _this = this;

  this.next = null;
  this.entry = null;

  this.finish = function (err) {
    var entry = _this.entry;
    _this.entry = null;
    while (entry) {
      var cb = entry.callback;
      state.pendingcb--;
      cb(err);
      entry = entry.next;
    }
    if (state.corkedRequestsFree) {
      state.corkedRequestsFree.next = _this;
    } else {
      state.corkedRequestsFree = _this;
    }
  };
}
}).call(this,require('_process'))
},{"./_stream_duplex":18,"_process":16,"buffer":9,"core-util-is":23,"events":13,"inherits":14,"process-nextick-args":25,"util-deprecate":26}],23:[function(require,module,exports){
(function (Buffer){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.

function isArray(arg) {
  if (Array.isArray) {
    return Array.isArray(arg);
  }
  return objectToString(arg) === '[object Array]';
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}
exports.isObject = isObject;

function isDate(d) {
  return objectToString(d) === '[object Date]';
}
exports.isDate = isDate;

function isError(e) {
  return (objectToString(e) === '[object Error]' || e instanceof Error);
}
exports.isError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

exports.isBuffer = Buffer.isBuffer;

function objectToString(o) {
  return Object.prototype.toString.call(o);
}

}).call(this,{"isBuffer":require("../../../../insert-module-globals/node_modules/is-buffer/index.js")})
},{"../../../../insert-module-globals/node_modules/is-buffer/index.js":15}],24:[function(require,module,exports){
arguments[4][12][0].apply(exports,arguments)
},{"dup":12}],25:[function(require,module,exports){
(function (process){
'use strict';

if (!process.version ||
    process.version.indexOf('v0.') === 0 ||
    process.version.indexOf('v1.') === 0 && process.version.indexOf('v1.8.') !== 0) {
  module.exports = nextTick;
} else {
  module.exports = process.nextTick;
}

function nextTick(fn) {
  var args = new Array(arguments.length - 1);
  var i = 0;
  while (i < args.length) {
    args[i++] = arguments[i];
  }
  process.nextTick(function afterTick() {
    fn.apply(null, args);
  });
}

}).call(this,require('_process'))
},{"_process":16}],26:[function(require,module,exports){
(function (global){

/**
 * Module exports.
 */

module.exports = deprecate;

/**
 * Mark that a method should not be used.
 * Returns a modified function which warns once by default.
 *
 * If `localStorage.noDeprecation = true` is set, then it is a no-op.
 *
 * If `localStorage.throwDeprecation = true` is set, then deprecated functions
 * will throw an Error when invoked.
 *
 * If `localStorage.traceDeprecation = true` is set, then deprecated functions
 * will invoke `console.trace()` instead of `console.error()`.
 *
 * @param {Function} fn - the function to deprecate
 * @param {String} msg - the string to print to the console when `fn` is invoked
 * @returns {Function} a new "deprecated" version of `fn`
 * @api public
 */

function deprecate (fn, msg) {
  if (config('noDeprecation')) {
    return fn;
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (config('throwDeprecation')) {
        throw new Error(msg);
      } else if (config('traceDeprecation')) {
        console.trace(msg);
      } else {
        console.warn(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
}

/**
 * Checks `localStorage` for boolean values for the given `name`.
 *
 * @param {String} name
 * @returns {Boolean}
 * @api private
 */

function config (name) {
  // accessing global.localStorage can trigger a DOMException in sandboxed iframes
  try {
    if (!global.localStorage) return false;
  } catch (_) {
    return false;
  }
  var val = global.localStorage[name];
  if (null == val) return false;
  return String(val).toLowerCase() === 'true';
}

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],27:[function(require,module,exports){
module.exports = require("./lib/_stream_passthrough.js")

},{"./lib/_stream_passthrough.js":19}],28:[function(require,module,exports){
(function (process){
var Stream = (function (){
  try {
    return require('st' + 'ream'); // hack to fix a circular dependency issue when used with browserify
  } catch(_){}
}());
exports = module.exports = require('./lib/_stream_readable.js');
exports.Stream = Stream || exports;
exports.Readable = exports;
exports.Writable = require('./lib/_stream_writable.js');
exports.Duplex = require('./lib/_stream_duplex.js');
exports.Transform = require('./lib/_stream_transform.js');
exports.PassThrough = require('./lib/_stream_passthrough.js');

if (!process.browser && process.env.READABLE_STREAM === 'disable' && Stream) {
  module.exports = Stream;
}

}).call(this,require('_process'))
},{"./lib/_stream_duplex.js":18,"./lib/_stream_passthrough.js":19,"./lib/_stream_readable.js":20,"./lib/_stream_transform.js":21,"./lib/_stream_writable.js":22,"_process":16}],29:[function(require,module,exports){
module.exports = require("./lib/_stream_transform.js")

},{"./lib/_stream_transform.js":21}],30:[function(require,module,exports){
module.exports = require("./lib/_stream_writable.js")

},{"./lib/_stream_writable.js":22}],31:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

module.exports = Stream;

var EE = require('events').EventEmitter;
var inherits = require('inherits');

inherits(Stream, EE);
Stream.Readable = require('readable-stream/readable.js');
Stream.Writable = require('readable-stream/writable.js');
Stream.Duplex = require('readable-stream/duplex.js');
Stream.Transform = require('readable-stream/transform.js');
Stream.PassThrough = require('readable-stream/passthrough.js');

// Backwards-compat with node 0.4.x
Stream.Stream = Stream;



// old-style streams.  Note that the pipe method (the only relevant
// part of this class) is overridden in the Readable class.

function Stream() {
  EE.call(this);
}

Stream.prototype.pipe = function(dest, options) {
  var source = this;

  function ondata(chunk) {
    if (dest.writable) {
      if (false === dest.write(chunk) && source.pause) {
        source.pause();
      }
    }
  }

  source.on('data', ondata);

  function ondrain() {
    if (source.readable && source.resume) {
      source.resume();
    }
  }

  dest.on('drain', ondrain);

  // If the 'end' option is not supplied, dest.end() will be called when
  // source gets the 'end' or 'close' events.  Only dest.end() once.
  if (!dest._isStdio && (!options || options.end !== false)) {
    source.on('end', onend);
    source.on('close', onclose);
  }

  var didOnEnd = false;
  function onend() {
    if (didOnEnd) return;
    didOnEnd = true;

    dest.end();
  }


  function onclose() {
    if (didOnEnd) return;
    didOnEnd = true;

    if (typeof dest.destroy === 'function') dest.destroy();
  }

  // don't leave dangling pipes when there are errors.
  function onerror(er) {
    cleanup();
    if (EE.listenerCount(this, 'error') === 0) {
      throw er; // Unhandled stream error in pipe.
    }
  }

  source.on('error', onerror);
  dest.on('error', onerror);

  // remove all the event listeners that were added.
  function cleanup() {
    source.removeListener('data', ondata);
    dest.removeListener('drain', ondrain);

    source.removeListener('end', onend);
    source.removeListener('close', onclose);

    source.removeListener('error', onerror);
    dest.removeListener('error', onerror);

    source.removeListener('end', cleanup);
    source.removeListener('close', cleanup);

    dest.removeListener('close', cleanup);
  }

  source.on('end', cleanup);
  source.on('close', cleanup);

  dest.on('close', cleanup);

  dest.emit('pipe', source);

  // Allow for unix-like usage: A.pipe(B).pipe(C)
  return dest;
};

},{"events":13,"inherits":14,"readable-stream/duplex.js":17,"readable-stream/passthrough.js":27,"readable-stream/readable.js":28,"readable-stream/transform.js":29,"readable-stream/writable.js":30}],32:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var Buffer = require('buffer').Buffer;

var isBufferEncoding = Buffer.isEncoding
  || function(encoding) {
       switch (encoding && encoding.toLowerCase()) {
         case 'hex': case 'utf8': case 'utf-8': case 'ascii': case 'binary': case 'base64': case 'ucs2': case 'ucs-2': case 'utf16le': case 'utf-16le': case 'raw': return true;
         default: return false;
       }
     }


function assertEncoding(encoding) {
  if (encoding && !isBufferEncoding(encoding)) {
    throw new Error('Unknown encoding: ' + encoding);
  }
}

// StringDecoder provides an interface for efficiently splitting a series of
// buffers into a series of JS strings without breaking apart multi-byte
// characters. CESU-8 is handled as part of the UTF-8 encoding.
//
// @TODO Handling all encodings inside a single object makes it very difficult
// to reason about this code, so it should be split up in the future.
// @TODO There should be a utf8-strict encoding that rejects invalid UTF-8 code
// points as used by CESU-8.
var StringDecoder = exports.StringDecoder = function(encoding) {
  this.encoding = (encoding || 'utf8').toLowerCase().replace(/[-_]/, '');
  assertEncoding(encoding);
  switch (this.encoding) {
    case 'utf8':
      // CESU-8 represents each of Surrogate Pair by 3-bytes
      this.surrogateSize = 3;
      break;
    case 'ucs2':
    case 'utf16le':
      // UTF-16 represents each of Surrogate Pair by 2-bytes
      this.surrogateSize = 2;
      this.detectIncompleteChar = utf16DetectIncompleteChar;
      break;
    case 'base64':
      // Base-64 stores 3 bytes in 4 chars, and pads the remainder.
      this.surrogateSize = 3;
      this.detectIncompleteChar = base64DetectIncompleteChar;
      break;
    default:
      this.write = passThroughWrite;
      return;
  }

  // Enough space to store all bytes of a single character. UTF-8 needs 4
  // bytes, but CESU-8 may require up to 6 (3 bytes per surrogate).
  this.charBuffer = new Buffer(6);
  // Number of bytes received for the current incomplete multi-byte character.
  this.charReceived = 0;
  // Number of bytes expected for the current incomplete multi-byte character.
  this.charLength = 0;
};


// write decodes the given buffer and returns it as JS string that is
// guaranteed to not contain any partial multi-byte characters. Any partial
// character found at the end of the buffer is buffered up, and will be
// returned when calling write again with the remaining bytes.
//
// Note: Converting a Buffer containing an orphan surrogate to a String
// currently works, but converting a String to a Buffer (via `new Buffer`, or
// Buffer#write) will replace incomplete surrogates with the unicode
// replacement character. See https://codereview.chromium.org/121173009/ .
StringDecoder.prototype.write = function(buffer) {
  var charStr = '';
  // if our last write ended with an incomplete multibyte character
  while (this.charLength) {
    // determine how many remaining bytes this buffer has to offer for this char
    var available = (buffer.length >= this.charLength - this.charReceived) ?
        this.charLength - this.charReceived :
        buffer.length;

    // add the new bytes to the char buffer
    buffer.copy(this.charBuffer, this.charReceived, 0, available);
    this.charReceived += available;

    if (this.charReceived < this.charLength) {
      // still not enough chars in this buffer? wait for more ...
      return '';
    }

    // remove bytes belonging to the current character from the buffer
    buffer = buffer.slice(available, buffer.length);

    // get the character that was split
    charStr = this.charBuffer.slice(0, this.charLength).toString(this.encoding);

    // CESU-8: lead surrogate (D800-DBFF) is also the incomplete character
    var charCode = charStr.charCodeAt(charStr.length - 1);
    if (charCode >= 0xD800 && charCode <= 0xDBFF) {
      this.charLength += this.surrogateSize;
      charStr = '';
      continue;
    }
    this.charReceived = this.charLength = 0;

    // if there are no more bytes in this buffer, just emit our char
    if (buffer.length === 0) {
      return charStr;
    }
    break;
  }

  // determine and set charLength / charReceived
  this.detectIncompleteChar(buffer);

  var end = buffer.length;
  if (this.charLength) {
    // buffer the incomplete character bytes we got
    buffer.copy(this.charBuffer, 0, buffer.length - this.charReceived, end);
    end -= this.charReceived;
  }

  charStr += buffer.toString(this.encoding, 0, end);

  var end = charStr.length - 1;
  var charCode = charStr.charCodeAt(end);
  // CESU-8: lead surrogate (D800-DBFF) is also the incomplete character
  if (charCode >= 0xD800 && charCode <= 0xDBFF) {
    var size = this.surrogateSize;
    this.charLength += size;
    this.charReceived += size;
    this.charBuffer.copy(this.charBuffer, size, 0, size);
    buffer.copy(this.charBuffer, 0, 0, size);
    return charStr.substring(0, end);
  }

  // or just emit the charStr
  return charStr;
};

// detectIncompleteChar determines if there is an incomplete UTF-8 character at
// the end of the given buffer. If so, it sets this.charLength to the byte
// length that character, and sets this.charReceived to the number of bytes
// that are available for this character.
StringDecoder.prototype.detectIncompleteChar = function(buffer) {
  // determine how many bytes we have to check at the end of this buffer
  var i = (buffer.length >= 3) ? 3 : buffer.length;

  // Figure out if one of the last i bytes of our buffer announces an
  // incomplete char.
  for (; i > 0; i--) {
    var c = buffer[buffer.length - i];

    // See http://en.wikipedia.org/wiki/UTF-8#Description

    // 110XXXXX
    if (i == 1 && c >> 5 == 0x06) {
      this.charLength = 2;
      break;
    }

    // 1110XXXX
    if (i <= 2 && c >> 4 == 0x0E) {
      this.charLength = 3;
      break;
    }

    // 11110XXX
    if (i <= 3 && c >> 3 == 0x1E) {
      this.charLength = 4;
      break;
    }
  }
  this.charReceived = i;
};

StringDecoder.prototype.end = function(buffer) {
  var res = '';
  if (buffer && buffer.length)
    res = this.write(buffer);

  if (this.charReceived) {
    var cr = this.charReceived;
    var buf = this.charBuffer;
    var enc = this.encoding;
    res += buf.slice(0, cr).toString(enc);
  }

  return res;
};

function passThroughWrite(buffer) {
  return buffer.toString(this.encoding);
}

function utf16DetectIncompleteChar(buffer) {
  this.charReceived = buffer.length % 2;
  this.charLength = this.charReceived ? 2 : 0;
}

function base64DetectIncompleteChar(buffer) {
  this.charReceived = buffer.length % 3;
  this.charLength = this.charReceived ? 3 : 0;
}

},{"buffer":9}],33:[function(require,module,exports){
var nextTick = require('process/browser.js').nextTick;
var apply = Function.prototype.apply;
var slice = Array.prototype.slice;
var immediateIds = {};
var nextImmediateId = 0;

// DOM APIs, for completeness

exports.setTimeout = function() {
  return new Timeout(apply.call(setTimeout, window, arguments), clearTimeout);
};
exports.setInterval = function() {
  return new Timeout(apply.call(setInterval, window, arguments), clearInterval);
};
exports.clearTimeout =
exports.clearInterval = function(timeout) { timeout.close(); };

function Timeout(id, clearFn) {
  this._id = id;
  this._clearFn = clearFn;
}
Timeout.prototype.unref = Timeout.prototype.ref = function() {};
Timeout.prototype.close = function() {
  this._clearFn.call(window, this._id);
};

// Does not start the time, just sets up the members needed.
exports.enroll = function(item, msecs) {
  clearTimeout(item._idleTimeoutId);
  item._idleTimeout = msecs;
};

exports.unenroll = function(item) {
  clearTimeout(item._idleTimeoutId);
  item._idleTimeout = -1;
};

exports._unrefActive = exports.active = function(item) {
  clearTimeout(item._idleTimeoutId);

  var msecs = item._idleTimeout;
  if (msecs >= 0) {
    item._idleTimeoutId = setTimeout(function onTimeout() {
      if (item._onTimeout)
        item._onTimeout();
    }, msecs);
  }
};

// That's not how node.js implements it but the exposed api is the same.
exports.setImmediate = typeof setImmediate === "function" ? setImmediate : function(fn) {
  var id = nextImmediateId++;
  var args = arguments.length < 2 ? false : slice.call(arguments, 1);

  immediateIds[id] = true;

  nextTick(function onNextTick() {
    if (immediateIds[id]) {
      // fn.call() is faster so we optimize for the common use-case
      // @see http://jsperf.com/call-apply-segu
      if (args) {
        fn.apply(null, args);
      } else {
        fn.call(null);
      }
      // Prevent ids from leaking
      exports.clearImmediate(id);
    }
  });

  return id;
};

exports.clearImmediate = typeof clearImmediate === "function" ? clearImmediate : function(id) {
  delete immediateIds[id];
};
},{"process/browser.js":16}],34:[function(require,module,exports){
(function (Buffer){
var navigator = {};
navigator.userAgent = false;

var window = {};
/*
 * jsrsasign 5.0.10 (c) 2010-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */

/*
yahoo-min.js
Copyright (c) 2011, Yahoo! Inc. All rights reserved.
Code licensed under the BSD License:
http://developer.yahoo.com/yui/license.html
version: 2.9.0
*/
if (typeof YAHOO == "undefined" || !YAHOO) {
    var YAHOO = {};
}
YAHOO.namespace = function() {
    var b = arguments,
        g = null,
        e, c, f;
    for (e = 0; e < b.length; e = e + 1) {
        f = ("" + b[e]).split(".");
        g = YAHOO;
        for (c = (f[0] == "YAHOO") ? 1 : 0; c < f.length; c = c + 1) {
            g[f[c]] = g[f[c]] || {};
            g = g[f[c]];
        }
    }
    return g;
};
YAHOO.log = function(d, a, c) {
    var b = YAHOO.widget.Logger;
    if (b && b.log) {
        return b.log(d, a, c);
    } else {
        return false;
    }
};
YAHOO.register = function(a, f, e) {
    var k = YAHOO.env.modules,
        c, j, h, g, d;
    if (!k[a]) { k[a] = { versions: [], builds: [] }; }
    c = k[a];
    j = e.version;
    h = e.build;
    g = YAHOO.env.listeners;
    c.name = a;
    c.version = j;
    c.build = h;
    c.versions.push(j);
    c.builds.push(h);
    c.mainClass = f;
    for (d = 0; d < g.length; d = d + 1) { g[d](c); }
    if (f) {
        f.VERSION = j;
        f.BUILD = h;
    } else { YAHOO.log("mainClass is undefined for module " + a, "warn"); }
};
YAHOO.env = YAHOO.env || { modules: [], listeners: [] };
YAHOO.env.getVersion = function(a) {
    return YAHOO.env.modules[a] || null;
};
YAHOO.env.parseUA = function(d) {
    var e = function(i) {
            var j = 0;
            return parseFloat(i.replace(/\./g, function() {
                return (j++ == 1) ? "" : ".";
            }));
        },
        h = navigator,
        g = { ie: 0, opera: 0, gecko: 0, webkit: 0, chrome: 0, mobile: null, air: 0, ipad: 0, iphone: 0, ipod: 0, ios: null, android: 0, webos: 0, caja: h && h.cajaVersion, secure: false, os: null },
        c = d || (navigator && navigator.userAgent),
        f = window && window.location,
        b = f && f.href,
        a;
    g.secure = b && (b.toLowerCase().indexOf("https") === 0);
    if (c) {
        if ((/windows|win32/i).test(c)) { g.os = "windows"; } else {
            if ((/macintosh/i).test(c)) { g.os = "macintosh"; } else {
                if ((/rhino/i).test(c)) { g.os = "rhino"; }
            }
        }
        if ((/KHTML/).test(c)) { g.webkit = 1; }
        a = c.match(/AppleWebKit\/([^\s]*)/);
        if (a && a[1]) {
            g.webkit = e(a[1]);
            if (/ Mobile\//.test(c)) {
                g.mobile = "Apple";
                a = c.match(/OS ([^\s]*)/);
                if (a && a[1]) { a = e(a[1].replace("_", ".")); }
                g.ios = a;
                g.ipad = g.ipod = g.iphone = 0;
                a = c.match(/iPad|iPod|iPhone/);
                if (a && a[0]) { g[a[0].toLowerCase()] = g.ios; }
            } else {
                a = c.match(/NokiaN[^\/]*|Android \d\.\d|webOS\/\d\.\d/);
                if (a) { g.mobile = a[0]; }
                if (/webOS/.test(c)) {
                    g.mobile = "WebOS";
                    a = c.match(/webOS\/([^\s]*);/);
                    if (a && a[1]) { g.webos = e(a[1]); }
                }
                if (/ Android/.test(c)) {
                    g.mobile = "Android";
                    a = c.match(/Android ([^\s]*);/);
                    if (a && a[1]) { g.android = e(a[1]); }
                }
            }
            a = c.match(/Chrome\/([^\s]*)/);
            if (a && a[1]) { g.chrome = e(a[1]); } else {
                a = c.match(/AdobeAIR\/([^\s]*)/);
                if (a) { g.air = a[0]; }
            }
        }
        if (!g.webkit) {
            a = c.match(/Opera[\s\/]([^\s]*)/);
            if (a && a[1]) {
                g.opera = e(a[1]);
                a = c.match(/Version\/([^\s]*)/);
                if (a && a[1]) { g.opera = e(a[1]); }
                a = c.match(/Opera Mini[^;]*/);
                if (a) { g.mobile = a[0]; }
            } else {
                a = c.match(/MSIE\s([^;]*)/);
                if (a && a[1]) { g.ie = e(a[1]); } else {
                    a = c.match(/Gecko\/([^\s]*)/);
                    if (a) {
                        g.gecko = 1;
                        a = c.match(/rv:([^\s\)]*)/);
                        if (a && a[1]) { g.gecko = e(a[1]); }
                    }
                }
            }
        }
    }
    return g;
};
YAHOO.env.ua = YAHOO.env.parseUA();
(function() {
    YAHOO.namespace("util", "widget", "example");
    if ("undefined" !== typeof YAHOO_config) {
        var b = YAHOO_config.listener,
            a = YAHOO.env.listeners,
            d = true,
            c;
        if (b) {
            for (c = 0; c < a.length; c++) {
                if (a[c] == b) {
                    d = false;
                    break;
                }
            }
            if (d) { a.push(b); }
        }
    }
})();
YAHOO.lang = YAHOO.lang || {};
(function() {
    var f = YAHOO.lang,
        a = Object.prototype,
        c = "[object Array]",
        h = "[object Function]",
        i = "[object Object]",
        b = [],
        g = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;", "/": "&#x2F;", "`": "&#x60;" },
        d = ["toString", "valueOf"],
        e = {
            isArray: function(j) {
                return a.toString.apply(j) === c;
            },
            isBoolean: function(j) {
                return typeof j === "boolean";
            },
            isFunction: function(j) {
                return (typeof j === "function") || a.toString.apply(j) === h;
            },
            isNull: function(j) {
                return j === null;
            },
            isNumber: function(j) {
                return typeof j === "number" && isFinite(j);
            },
            isObject: function(j) {
                return (j && (typeof j === "object" || f.isFunction(j))) || false;
            },
            isString: function(j) {
                return typeof j === "string";
            },
            isUndefined: function(j) {
                return typeof j === "undefined";
            },
            _IEEnumFix: (YAHOO.env.ua.ie) ? function(l, k) {
                var j, n, m;
                for (j = 0; j < d.length; j = j + 1) {
                    n = d[j];
                    m = k[n];
                    if (f.isFunction(m) && m != a[n]) { l[n] = m; }
                }
            } : function() {},
            escapeHTML: function(j) {
                return j.replace(/[&<>"'\/`]/g, function(k) {
                    return g[k];
                });
            },
            extend: function(m, n, l) {
                if (!n || !m) {
                    throw new Error("extend failed, please check that " + "all dependencies are included.");
                }
                var k = function() {},
                    j;
                k.prototype = n.prototype;
                m.prototype = new k();
                m.prototype.constructor = m;
                m.superclass = n.prototype;
                if (n.prototype.constructor == a.constructor) { n.prototype.constructor = n; }
                if (l) {
                    for (j in l) {
                        if (f.hasOwnProperty(l, j)) { m.prototype[j] = l[j]; }
                    }
                    f._IEEnumFix(m.prototype, l);
                }
            },
            augmentObject: function(n, m) {
                if (!m || !n) {
                    throw new Error("Absorb failed, verify dependencies.");
                }
                var j = arguments,
                    l, o, k = j[2];
                if (k && k !== true) {
                    for (l = 2; l < j.length; l = l + 1) { n[j[l]] = m[j[l]]; }
                } else {
                    for (o in m) {
                        if (k || !(o in n)) { n[o] = m[o]; }
                    }
                    f._IEEnumFix(n, m);
                }
                return n;
            },
            augmentProto: function(m, l) {
                if (!l || !m) {
                    throw new Error("Augment failed, verify dependencies.");
                }
                var j = [m.prototype, l.prototype],
                    k;
                for (k = 2; k < arguments.length; k = k + 1) { j.push(arguments[k]); }
                f.augmentObject.apply(this, j);
                return m;
            },
            dump: function(j, p) {
                var l, n, r = [],
                    t = "{...}",
                    k = "f(){...}",
                    q = ", ",
                    m = " => ";
                if (!f.isObject(j)) {
                    return j + "";
                } else {
                    if (j instanceof Date || ("nodeType" in j && "tagName" in j)) {
                        return j;
                    } else {
                        if (f.isFunction(j)) {
                            return k;
                        }
                    }
                }
                p = (f.isNumber(p)) ? p : 3;
                if (f.isArray(j)) {
                    r.push("[");
                    for (l = 0, n = j.length; l < n; l = l + 1) {
                        if (f.isObject(j[l])) { r.push((p > 0) ? f.dump(j[l], p - 1) : t); } else { r.push(j[l]); }
                        r.push(q);
                    }
                    if (r.length > 1) { r.pop(); }
                    r.push("]");
                } else {
                    r.push("{");
                    for (l in j) {
                        if (f.hasOwnProperty(j, l)) {
                            r.push(l + m);
                            if (f.isObject(j[l])) { r.push((p > 0) ? f.dump(j[l], p - 1) : t); } else { r.push(j[l]); }
                            r.push(q);
                        }
                    }
                    if (r.length > 1) { r.pop(); }
                    r.push("}");
                }
                return r.join("");
            },
            substitute: function(x, y, E, l) {
                var D, C, B, G, t, u, F = [],
                    p, z = x.length,
                    A = "dump",
                    r = " ",
                    q = "{",
                    m = "}",
                    n, w;
                for (;;) {
                    D = x.lastIndexOf(q, z);
                    if (D < 0) {
                        break;
                    }
                    C = x.indexOf(m, D);
                    if (D + 1 > C) {
                        break;
                    }
                    p = x.substring(D + 1, C);
                    G = p;
                    u = null;
                    B = G.indexOf(r);
                    if (B > -1) {
                        u = G.substring(B + 1);
                        G = G.substring(0, B);
                    }
                    t = y[G];
                    if (E) { t = E(G, t, u); }
                    if (f.isObject(t)) {
                        if (f.isArray(t)) { t = f.dump(t, parseInt(u, 10)); } else {
                            u = u || "";
                            n = u.indexOf(A);
                            if (n > -1) { u = u.substring(4); }
                            w = t.toString();
                            if (w === i || n > -1) { t = f.dump(t, parseInt(u, 10)); } else { t = w; }
                        }
                    } else {
                        if (!f.isString(t) && !f.isNumber(t)) {
                            t = "~-" + F.length + "-~";
                            F[F.length] = p;
                        }
                    }
                    x = x.substring(0, D) + t + x.substring(C + 1);
                    if (l === false) { z = D - 1; }
                }
                for (D = F.length - 1; D >= 0; D = D - 1) { x = x.replace(new RegExp("~-" + D + "-~"), "{" + F[D] + "}", "g"); }
                return x;
            },
            trim: function(j) {
                try {
                    return j.replace(/^\s+|\s+$/g, "");
                } catch (k) {
                    return j;
                }
            },
            merge: function() {
                var n = {},
                    k = arguments,
                    j = k.length,
                    m;
                for (m = 0; m < j; m = m + 1) { f.augmentObject(n, k[m], true); }
                return n;
            },
            later: function(t, k, u, n, p) {
                t = t || 0;
                k = k || {};
                var l = u,
                    s = n,
                    q, j;
                if (f.isString(u)) { l = k[u]; }
                if (!l) {
                    throw new TypeError("method undefined");
                }
                if (!f.isUndefined(n) && !f.isArray(s)) { s = [n]; }
                q = function() { l.apply(k, s || b); };
                j = (p) ? setInterval(q, t) : setTimeout(q, t);
                return {
                    interval: p,
                    cancel: function() {
                        if (this.interval) { clearInterval(j); } else { clearTimeout(j); }
                    }
                };
            },
            isValue: function(j) {
                return (f.isObject(j) || f.isString(j) || f.isNumber(j) || f.isBoolean(j));
            }
        };
    f.hasOwnProperty = (a.hasOwnProperty) ? function(j, k) {
        return j && j.hasOwnProperty && j.hasOwnProperty(k);
    } : function(j, k) {
        return !f.isUndefined(j[k]) && j.constructor.prototype[k] !== j[k];
    };
    e.augmentObject(f, e, true);
    YAHOO.util.Lang = f;
    f.augment = f.augmentProto;
    YAHOO.augment = f.augmentProto;
    YAHOO.extend = f.extend;
})();
YAHOO.register("yahoo", YAHOO, { version: "2.9.0", build: "2800" });

/*! CryptoJS v3.1.2 core-fix.js
 * code.google.com/p/crypto-js
 * (c) 2009-2013 by Jeff Mott. All rights reserved.
 * code.google.com/p/crypto-js/wiki/License
 * THIS IS FIX of 'core.js' to fix Hmac issue.
 * https://code.google.com/p/crypto-js/issues/detail?id=84
 * https://crypto-js.googlecode.com/svn-history/r667/branches/3.x/src/core.js
 */
var CryptoJS = CryptoJS || (function(e, g) {
    var a = {};
    var b = a.lib = {};
    var j = b.Base = (function() {
        function n() {}
        return {
            extend: function(p) {
                n.prototype = this;
                var o = new n();
                if (p) { o.mixIn(p) }
                if (!o.hasOwnProperty("init")) { o.init = function() { o.$super.init.apply(this, arguments) } }
                o.init.prototype = o;
                o.$super = this;
                return o
            },
            create: function() {
                var o = this.extend();
                o.init.apply(o, arguments);
                return o
            },
            init: function() {},
            mixIn: function(p) {
                for (var o in p) {
                    if (p.hasOwnProperty(o)) { this[o] = p[o] }
                }
                if (p.hasOwnProperty("toString")) { this.toString = p.toString }
            },
            clone: function() {
                return this.init.prototype.extend(this)
            }
        }
    }());
    var l = b.WordArray = j.extend({
        init: function(o, n) {
            o = this.words = o || [];
            if (n != g) { this.sigBytes = n } else { this.sigBytes = o.length * 4 }
        },
        toString: function(n) {
            return (n || h).stringify(this)
        },
        concat: function(t) {
            var q = this.words;
            var p = t.words;
            var n = this.sigBytes;
            var s = t.sigBytes;
            this.clamp();
            if (n % 4) {
                for (var r = 0; r < s; r++) {
                    var o = (p[r >>> 2] >>> (24 - (r % 4) * 8)) & 255;
                    q[(n + r) >>> 2] |= o << (24 - ((n + r) % 4) * 8)
                }
            } else {
                for (var r = 0; r < s; r += 4) { q[(n + r) >>> 2] = p[r >>> 2] }
            }
            this.sigBytes += s;
            return this
        },
        clamp: function() {
            var o = this.words;
            var n = this.sigBytes;
            o[n >>> 2] &= 4294967295 << (32 - (n % 4) * 8);
            o.length = e.ceil(n / 4)
        },
        clone: function() {
            var n = j.clone.call(this);
            n.words = this.words.slice(0);
            return n
        },
        random: function(p) {
            var o = [];
            for (var n = 0; n < p; n += 4) { o.push((e.random() * 4294967296) | 0) }
            return new l.init(o, p)
        }
    });
    var m = a.enc = {};
    var h = m.Hex = {
        stringify: function(p) {
            var r = p.words;
            var o = p.sigBytes;
            var q = [];
            for (var n = 0; n < o; n++) {
                var s = (r[n >>> 2] >>> (24 - (n % 4) * 8)) & 255;
                q.push((s >>> 4).toString(16));
                q.push((s & 15).toString(16))
            }
            return q.join("")
        },
        parse: function(p) {
            var n = p.length;
            var q = [];
            for (var o = 0; o < n; o += 2) { q[o >>> 3] |= parseInt(p.substr(o, 2), 16) << (24 - (o % 8) * 4) }
            return new l.init(q, n / 2)
        }
    };
    var d = m.Latin1 = {
        stringify: function(q) {
            var r = q.words;
            var p = q.sigBytes;
            var n = [];
            for (var o = 0; o < p; o++) {
                var s = (r[o >>> 2] >>> (24 - (o % 4) * 8)) & 255;
                n.push(String.fromCharCode(s))
            }
            return n.join("")
        },
        parse: function(p) {
            var n = p.length;
            var q = [];
            for (var o = 0; o < n; o++) { q[o >>> 2] |= (p.charCodeAt(o) & 255) << (24 - (o % 4) * 8) }
            return new l.init(q, n)
        }
    };
    var c = m.Utf8 = {
        stringify: function(n) {
            try {
                return decodeURIComponent(escape(d.stringify(n)))
            } catch (o) {
                throw new Error("Malformed UTF-8 data")
            }
        },
        parse: function(n) {
            return d.parse(unescape(encodeURIComponent(n)))
        }
    };
    var i = b.BufferedBlockAlgorithm = j.extend({
        reset: function() {
            this._data = new l.init();
            this._nDataBytes = 0
        },
        _append: function(n) {
            if (typeof n == "string") { n = c.parse(n) }
            this._data.concat(n);
            this._nDataBytes += n.sigBytes
        },
        _process: function(w) {
            var q = this._data;
            var x = q.words;
            var n = q.sigBytes;
            var t = this.blockSize;
            var v = t * 4;
            var u = n / v;
            if (w) { u = e.ceil(u) } else { u = e.max((u | 0) - this._minBufferSize, 0) }
            var s = u * t;
            var r = e.min(s * 4, n);
            if (s) {
                for (var p = 0; p < s; p += t) { this._doProcessBlock(x, p) }
                var o = x.splice(0, s);
                q.sigBytes -= r
            }
            return new l.init(o, r)
        },
        clone: function() {
            var n = j.clone.call(this);
            n._data = this._data.clone();
            return n
        },
        _minBufferSize: 0
    });
    var f = b.Hasher = i.extend({
        cfg: j.extend(),
        init: function(n) {
            this.cfg = this.cfg.extend(n);
            this.reset()
        },
        reset: function() {
            i.reset.call(this);
            this._doReset()
        },
        update: function(n) {
            this._append(n);
            this._process();
            return this
        },
        finalize: function(n) {
            if (n) { this._append(n) }
            var o = this._doFinalize();
            return o
        },
        blockSize: 512 / 32,
        _createHelper: function(n) {
            return function(p, o) {
                return new n.init(o).finalize(p)
            }
        },
        _createHmacHelper: function(n) {
            return function(p, o) {
                return new k.HMAC.init(n, o).finalize(p)
            }
        }
    });
    var k = a.algo = {};
    return a
}(Math));
/*
CryptoJS v3.1.2 x64-core-min.js
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(g) {
    var a = CryptoJS,
        f = a.lib,
        e = f.Base,
        h = f.WordArray,
        a = a.x64 = {};
    a.Word = e.extend({
        init: function(b, c) {
            this.high = b;
            this.low = c
        }
    });
    a.WordArray = e.extend({
        init: function(b, c) {
            b = this.words = b || [];
            this.sigBytes = c != g ? c : 8 * b.length
        },
        toX32: function() {
            for (var b = this.words, c = b.length, a = [], d = 0; d < c; d++) {
                var e = b[d];
                a.push(e.high);
                a.push(e.low)
            }
            return h.create(a, this.sigBytes)
        },
        clone: function() {
            for (var b = e.clone.call(this), c = b.words = this.words.slice(0), a = c.length, d = 0; d < a; d++) c[d] = c[d].clone();
            return b
        }
    })
})();

/*
CryptoJS v3.1.2 cipher-core-min.js
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
CryptoJS.lib.Cipher || function(u) {
    var g = CryptoJS,
        f = g.lib,
        k = f.Base,
        l = f.WordArray,
        q = f.BufferedBlockAlgorithm,
        r = g.enc.Base64,
        v = g.algo.EvpKDF,
        n = f.Cipher = q.extend({
            cfg: k.extend(),
            createEncryptor: function(a, b) {
                return this.create(this._ENC_XFORM_MODE, a, b)
            },
            createDecryptor: function(a, b) {
                return this.create(this._DEC_XFORM_MODE, a, b)
            },
            init: function(a, b, c) {
                this.cfg = this.cfg.extend(c);
                this._xformMode = a;
                this._key = b;
                this.reset()
            },
            reset: function() {
                q.reset.call(this);
                this._doReset()
            },
            process: function(a) {
                this._append(a);
                return this._process()
            },
            finalize: function(a) {
                a && this._append(a);
                return this._doFinalize()
            },
            keySize: 4,
            ivSize: 4,
            _ENC_XFORM_MODE: 1,
            _DEC_XFORM_MODE: 2,
            _createHelper: function(a) {
                return {
                    encrypt: function(b, c, d) {
                        return ("string" == typeof c ? s : j).encrypt(a, b, c, d)
                    },
                    decrypt: function(b, c, d) {
                        return ("string" == typeof c ? s : j).decrypt(a, b, c, d)
                    }
                }
            }
        });
    f.StreamCipher = n.extend({
        _doFinalize: function() {
            return this._process(!0)
        },
        blockSize: 1
    });
    var m = g.mode = {},
        t = function(a, b, c) {
            var d = this._iv;
            d ? this._iv = u : d = this._prevBlock;
            for (var e =
                    0; e < c; e++) a[b + e] ^= d[e]
        },
        h = (f.BlockCipherMode = k.extend({
            createEncryptor: function(a, b) {
                return this.Encryptor.create(a, b)
            },
            createDecryptor: function(a, b) {
                return this.Decryptor.create(a, b)
            },
            init: function(a, b) {
                this._cipher = a;
                this._iv = b
            }
        })).extend();
    h.Encryptor = h.extend({
        processBlock: function(a, b) {
            var c = this._cipher,
                d = c.blockSize;
            t.call(this, a, b, d);
            c.encryptBlock(a, b);
            this._prevBlock = a.slice(b, b + d)
        }
    });
    h.Decryptor = h.extend({
        processBlock: function(a, b) {
            var c = this._cipher,
                d = c.blockSize,
                e = a.slice(b, b + d);
            c.decryptBlock(a,
                b);
            t.call(this, a, b, d);
            this._prevBlock = e
        }
    });
    m = m.CBC = h;
    h = (g.pad = {}).Pkcs7 = {
        pad: function(a, b) {
            for (var c = 4 * b, c = c - a.sigBytes % c, d = c << 24 | c << 16 | c << 8 | c, e = [], f = 0; f < c; f += 4) e.push(d);
            c = l.create(e, c);
            a.concat(c)
        },
        unpad: function(a) { a.sigBytes -= a.words[a.sigBytes - 1 >>> 2] & 255 }
    };
    f.BlockCipher = n.extend({
        cfg: n.cfg.extend({ mode: m, padding: h }),
        reset: function() {
            n.reset.call(this);
            var a = this.cfg,
                b = a.iv,
                a = a.mode;
            if (this._xformMode == this._ENC_XFORM_MODE) var c = a.createEncryptor;
            else c = a.createDecryptor, this._minBufferSize = 1;
            this._mode = c.call(a, this, b && b.words)
        },
        _doProcessBlock: function(a, b) { this._mode.processBlock(a, b) },
        _doFinalize: function() {
            var a = this.cfg.padding;
            if (this._xformMode == this._ENC_XFORM_MODE) {
                a.pad(this._data, this.blockSize);
                var b = this._process(!0)
            } else b = this._process(!0), a.unpad(b);
            return b
        },
        blockSize: 4
    });
    var p = f.CipherParams = k.extend({
            init: function(a) { this.mixIn(a) },
            toString: function(a) {
                return (a || this.formatter).stringify(this)
            }
        }),
        m = (g.format = {}).OpenSSL = {
            stringify: function(a) {
                var b = a.ciphertext;
                a = a.salt;
                return (a ? l.create([1398893684, 1701076831]).concat(a).concat(b) : b).toString(r)
            },
            parse: function(a) {
                a = r.parse(a);
                var b = a.words;
                if (1398893684 == b[0] && 1701076831 == b[1]) {
                    var c = l.create(b.slice(2, 4));
                    b.splice(0, 4);
                    a.sigBytes -= 16
                }
                return p.create({ ciphertext: a, salt: c })
            }
        },
        j = f.SerializableCipher = k.extend({
            cfg: k.extend({ format: m }),
            encrypt: function(a, b, c, d) {
                d = this.cfg.extend(d);
                var e = a.createEncryptor(c, d);
                b = e.finalize(b);
                e = e.cfg;
                return p.create({
                    ciphertext: b,
                    key: c,
                    iv: e.iv,
                    algorithm: a,
                    mode: e.mode,
                    padding: e.padding,
                    blockSize: a.blockSize,
                    formatter: d.format
                })
            },
            decrypt: function(a, b, c, d) {
                d = this.cfg.extend(d);
                b = this._parse(b, d.format);
                return a.createDecryptor(c, d).finalize(b.ciphertext)
            },
            _parse: function(a, b) {
                return "string" == typeof a ? b.parse(a, this) : a
            }
        }),
        g = (g.kdf = {}).OpenSSL = {
            execute: function(a, b, c, d) {
                d || (d = l.random(8));
                a = v.create({ keySize: b + c }).compute(a, d);
                c = l.create(a.words.slice(b), 4 * c);
                a.sigBytes = 4 * b;
                return p.create({ key: a, iv: c, salt: d })
            }
        },
        s = f.PasswordBasedCipher = j.extend({
            cfg: j.cfg.extend({ kdf: g }),
            encrypt: function(a,
                b, c, d) {
                d = this.cfg.extend(d);
                c = d.kdf.execute(c, a.keySize, a.ivSize);
                d.iv = c.iv;
                a = j.encrypt.call(this, a, b, c.key, d);
                a.mixIn(c);
                return a
            },
            decrypt: function(a, b, c, d) {
                d = this.cfg.extend(d);
                b = this._parse(b, d.format);
                c = d.kdf.execute(c, a.keySize, a.ivSize, b.salt);
                d.iv = c.iv;
                return j.decrypt.call(this, a, b, c.key, d)
            }
        })
}();

/*
CryptoJS v3.1.2 aes-min.js
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function() {
    for (var q = CryptoJS, x = q.lib.BlockCipher, r = q.algo, j = [], y = [], z = [], A = [], B = [], C = [], s = [], u = [], v = [], w = [], g = [], k = 0; 256 > k; k++) g[k] = 128 > k ? k << 1 : k << 1 ^ 283;
    for (var n = 0, l = 0, k = 0; 256 > k; k++) {
        var f = l ^ l << 1 ^ l << 2 ^ l << 3 ^ l << 4,
            f = f >>> 8 ^ f & 255 ^ 99;
        j[n] = f;
        y[f] = n;
        var t = g[n],
            D = g[t],
            E = g[D],
            b = 257 * g[f] ^ 16843008 * f;
        z[n] = b << 24 | b >>> 8;
        A[n] = b << 16 | b >>> 16;
        B[n] = b << 8 | b >>> 24;
        C[n] = b;
        b = 16843009 * E ^ 65537 * D ^ 257 * t ^ 16843008 * n;
        s[f] = b << 24 | b >>> 8;
        u[f] = b << 16 | b >>> 16;
        v[f] = b << 8 | b >>> 24;
        w[f] = b;
        n ? (n = t ^ g[g[g[E ^ t]]], l ^= g[g[l]]) : n = l = 1
    }
    var F = [0, 1, 2, 4, 8,
            16, 32, 64, 128, 27, 54
        ],
        r = r.AES = x.extend({
            _doReset: function() {
                for (var c = this._key, e = c.words, a = c.sigBytes / 4, c = 4 * ((this._nRounds = a + 6) + 1), b = this._keySchedule = [], h = 0; h < c; h++)
                    if (h < a) b[h] = e[h];
                    else {
                        var d = b[h - 1];
                        h % a ? 6 < a && 4 == h % a && (d = j[d >>> 24] << 24 | j[d >>> 16 & 255] << 16 | j[d >>> 8 & 255] << 8 | j[d & 255]) : (d = d << 8 | d >>> 24, d = j[d >>> 24] << 24 | j[d >>> 16 & 255] << 16 | j[d >>> 8 & 255] << 8 | j[d & 255], d ^= F[h / a | 0] << 24);
                        b[h] = b[h - a] ^ d
                    }
                e = this._invKeySchedule = [];
                for (a = 0; a < c; a++) h = c - a, d = a % 4 ? b[h] : b[h - 4], e[a] = 4 > a || 4 >= h ? d : s[j[d >>> 24]] ^ u[j[d >>> 16 & 255]] ^ v[j[d >>>
                    8 & 255]] ^ w[j[d & 255]]
            },
            encryptBlock: function(c, e) { this._doCryptBlock(c, e, this._keySchedule, z, A, B, C, j) },
            decryptBlock: function(c, e) {
                var a = c[e + 1];
                c[e + 1] = c[e + 3];
                c[e + 3] = a;
                this._doCryptBlock(c, e, this._invKeySchedule, s, u, v, w, y);
                a = c[e + 1];
                c[e + 1] = c[e + 3];
                c[e + 3] = a
            },
            _doCryptBlock: function(c, e, a, b, h, d, j, m) {
                for (var n = this._nRounds, f = c[e] ^ a[0], g = c[e + 1] ^ a[1], k = c[e + 2] ^ a[2], p = c[e + 3] ^ a[3], l = 4, t = 1; t < n; t++) var q = b[f >>> 24] ^ h[g >>> 16 & 255] ^ d[k >>> 8 & 255] ^ j[p & 255] ^ a[l++],
                    r = b[g >>> 24] ^ h[k >>> 16 & 255] ^ d[p >>> 8 & 255] ^ j[f & 255] ^ a[l++],
                    s =
                    b[k >>> 24] ^ h[p >>> 16 & 255] ^ d[f >>> 8 & 255] ^ j[g & 255] ^ a[l++],
                    p = b[p >>> 24] ^ h[f >>> 16 & 255] ^ d[g >>> 8 & 255] ^ j[k & 255] ^ a[l++],
                    f = q,
                    g = r,
                    k = s;
                q = (m[f >>> 24] << 24 | m[g >>> 16 & 255] << 16 | m[k >>> 8 & 255] << 8 | m[p & 255]) ^ a[l++];
                r = (m[g >>> 24] << 24 | m[k >>> 16 & 255] << 16 | m[p >>> 8 & 255] << 8 | m[f & 255]) ^ a[l++];
                s = (m[k >>> 24] << 24 | m[p >>> 16 & 255] << 16 | m[f >>> 8 & 255] << 8 | m[g & 255]) ^ a[l++];
                p = (m[p >>> 24] << 24 | m[f >>> 16 & 255] << 16 | m[g >>> 8 & 255] << 8 | m[k & 255]) ^ a[l++];
                c[e] = q;
                c[e + 1] = r;
                c[e + 2] = s;
                c[e + 3] = p
            },
            keySize: 8
        });
    q.AES = x._createHelper(r)
})();

/*
CryptoJS v3.1.2 tripledes-min.js
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function() {
    function j(b, c) {
        var a = (this._lBlock >>> b ^ this._rBlock) & c;
        this._rBlock ^= a;
        this._lBlock ^= a << b
    }

    function l(b, c) {
        var a = (this._rBlock >>> b ^ this._lBlock) & c;
        this._lBlock ^= a;
        this._rBlock ^= a << b
    }
    var h = CryptoJS,
        e = h.lib,
        n = e.WordArray,
        e = e.BlockCipher,
        g = h.algo,
        q = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4],
        p = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47,
            55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
        ],
        r = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28],
        s = [{
            "0": 8421888,
            268435456: 32768,
            536870912: 8421378,
            805306368: 2,
            1073741824: 512,
            1342177280: 8421890,
            1610612736: 8389122,
            1879048192: 8388608,
            2147483648: 514,
            2415919104: 8389120,
            2684354560: 33280,
            2952790016: 8421376,
            3221225472: 32770,
            3489660928: 8388610,
            3758096384: 0,
            4026531840: 33282,
            134217728: 0,
            402653184: 8421890,
            671088640: 33282,
            939524096: 32768,
            1207959552: 8421888,
            1476395008: 512,
            1744830464: 8421378,
            2013265920: 2,
            2281701376: 8389120,
            2550136832: 33280,
            2818572288: 8421376,
            3087007744: 8389122,
            3355443200: 8388610,
            3623878656: 32770,
            3892314112: 514,
            4160749568: 8388608,
            1: 32768,
            268435457: 2,
            536870913: 8421888,
            805306369: 8388608,
            1073741825: 8421378,
            1342177281: 33280,
            1610612737: 512,
            1879048193: 8389122,
            2147483649: 8421890,
            2415919105: 8421376,
            2684354561: 8388610,
            2952790017: 33282,
            3221225473: 514,
            3489660929: 8389120,
            3758096385: 32770,
            4026531841: 0,
            134217729: 8421890,
            402653185: 8421376,
            671088641: 8388608,
            939524097: 512,
            1207959553: 32768,
            1476395009: 8388610,
            1744830465: 2,
            2013265921: 33282,
            2281701377: 32770,
            2550136833: 8389122,
            2818572289: 514,
            3087007745: 8421888,
            3355443201: 8389120,
            3623878657: 0,
            3892314113: 33280,
            4160749569: 8421378
        }, {
            "0": 1074282512,
            16777216: 16384,
            33554432: 524288,
            50331648: 1074266128,
            67108864: 1073741840,
            83886080: 1074282496,
            100663296: 1073758208,
            117440512: 16,
            134217728: 540672,
            150994944: 1073758224,
            167772160: 1073741824,
            184549376: 540688,
            201326592: 524304,
            218103808: 0,
            234881024: 16400,
            251658240: 1074266112,
            8388608: 1073758208,
            25165824: 540688,
            41943040: 16,
            58720256: 1073758224,
            75497472: 1074282512,
            92274688: 1073741824,
            109051904: 524288,
            125829120: 1074266128,
            142606336: 524304,
            159383552: 0,
            176160768: 16384,
            192937984: 1074266112,
            209715200: 1073741840,
            226492416: 540672,
            243269632: 1074282496,
            260046848: 16400,
            268435456: 0,
            285212672: 1074266128,
            301989888: 1073758224,
            318767104: 1074282496,
            335544320: 1074266112,
            352321536: 16,
            369098752: 540688,
            385875968: 16384,
            402653184: 16400,
            419430400: 524288,
            436207616: 524304,
            452984832: 1073741840,
            469762048: 540672,
            486539264: 1073758208,
            503316480: 1073741824,
            520093696: 1074282512,
            276824064: 540688,
            293601280: 524288,
            310378496: 1074266112,
            327155712: 16384,
            343932928: 1073758208,
            360710144: 1074282512,
            377487360: 16,
            394264576: 1073741824,
            411041792: 1074282496,
            427819008: 1073741840,
            444596224: 1073758224,
            461373440: 524304,
            478150656: 0,
            494927872: 16400,
            511705088: 1074266128,
            528482304: 540672
        }, {
            "0": 260,
            1048576: 0,
            2097152: 67109120,
            3145728: 65796,
            4194304: 65540,
            5242880: 67108868,
            6291456: 67174660,
            7340032: 67174400,
            8388608: 67108864,
            9437184: 67174656,
            10485760: 65792,
            11534336: 67174404,
            12582912: 67109124,
            13631488: 65536,
            14680064: 4,
            15728640: 256,
            524288: 67174656,
            1572864: 67174404,
            2621440: 0,
            3670016: 67109120,
            4718592: 67108868,
            5767168: 65536,
            6815744: 65540,
            7864320: 260,
            8912896: 4,
            9961472: 256,
            11010048: 67174400,
            12058624: 65796,
            13107200: 65792,
            14155776: 67109124,
            15204352: 67174660,
            16252928: 67108864,
            16777216: 67174656,
            17825792: 65540,
            18874368: 65536,
            19922944: 67109120,
            20971520: 256,
            22020096: 67174660,
            23068672: 67108868,
            24117248: 0,
            25165824: 67109124,
            26214400: 67108864,
            27262976: 4,
            28311552: 65792,
            29360128: 67174400,
            30408704: 260,
            31457280: 65796,
            32505856: 67174404,
            17301504: 67108864,
            18350080: 260,
            19398656: 67174656,
            20447232: 0,
            21495808: 65540,
            22544384: 67109120,
            23592960: 256,
            24641536: 67174404,
            25690112: 65536,
            26738688: 67174660,
            27787264: 65796,
            28835840: 67108868,
            29884416: 67109124,
            30932992: 67174400,
            31981568: 4,
            33030144: 65792
        }, {
            "0": 2151682048,
            65536: 2147487808,
            131072: 4198464,
            196608: 2151677952,
            262144: 0,
            327680: 4198400,
            393216: 2147483712,
            458752: 4194368,
            524288: 2147483648,
            589824: 4194304,
            655360: 64,
            720896: 2147487744,
            786432: 2151678016,
            851968: 4160,
            917504: 4096,
            983040: 2151682112,
            32768: 2147487808,
            98304: 64,
            163840: 2151678016,
            229376: 2147487744,
            294912: 4198400,
            360448: 2151682112,
            425984: 0,
            491520: 2151677952,
            557056: 4096,
            622592: 2151682048,
            688128: 4194304,
            753664: 4160,
            819200: 2147483648,
            884736: 4194368,
            950272: 4198464,
            1015808: 2147483712,
            1048576: 4194368,
            1114112: 4198400,
            1179648: 2147483712,
            1245184: 0,
            1310720: 4160,
            1376256: 2151678016,
            1441792: 2151682048,
            1507328: 2147487808,
            1572864: 2151682112,
            1638400: 2147483648,
            1703936: 2151677952,
            1769472: 4198464,
            1835008: 2147487744,
            1900544: 4194304,
            1966080: 64,
            2031616: 4096,
            1081344: 2151677952,
            1146880: 2151682112,
            1212416: 0,
            1277952: 4198400,
            1343488: 4194368,
            1409024: 2147483648,
            1474560: 2147487808,
            1540096: 64,
            1605632: 2147483712,
            1671168: 4096,
            1736704: 2147487744,
            1802240: 2151678016,
            1867776: 4160,
            1933312: 2151682048,
            1998848: 4194304,
            2064384: 4198464
        }, {
            "0": 128,
            4096: 17039360,
            8192: 262144,
            12288: 536870912,
            16384: 537133184,
            20480: 16777344,
            24576: 553648256,
            28672: 262272,
            32768: 16777216,
            36864: 537133056,
            40960: 536871040,
            45056: 553910400,
            49152: 553910272,
            53248: 0,
            57344: 17039488,
            61440: 553648128,
            2048: 17039488,
            6144: 553648256,
            10240: 128,
            14336: 17039360,
            18432: 262144,
            22528: 537133184,
            26624: 553910272,
            30720: 536870912,
            34816: 537133056,
            38912: 0,
            43008: 553910400,
            47104: 16777344,
            51200: 536871040,
            55296: 553648128,
            59392: 16777216,
            63488: 262272,
            65536: 262144,
            69632: 128,
            73728: 536870912,
            77824: 553648256,
            81920: 16777344,
            86016: 553910272,
            90112: 537133184,
            94208: 16777216,
            98304: 553910400,
            102400: 553648128,
            106496: 17039360,
            110592: 537133056,
            114688: 262272,
            118784: 536871040,
            122880: 0,
            126976: 17039488,
            67584: 553648256,
            71680: 16777216,
            75776: 17039360,
            79872: 537133184,
            83968: 536870912,
            88064: 17039488,
            92160: 128,
            96256: 553910272,
            100352: 262272,
            104448: 553910400,
            108544: 0,
            112640: 553648128,
            116736: 16777344,
            120832: 262144,
            124928: 537133056,
            129024: 536871040
        }, {
            "0": 268435464,
            256: 8192,
            512: 270532608,
            768: 270540808,
            1024: 268443648,
            1280: 2097152,
            1536: 2097160,
            1792: 268435456,
            2048: 0,
            2304: 268443656,
            2560: 2105344,
            2816: 8,
            3072: 270532616,
            3328: 2105352,
            3584: 8200,
            3840: 270540800,
            128: 270532608,
            384: 270540808,
            640: 8,
            896: 2097152,
            1152: 2105352,
            1408: 268435464,
            1664: 268443648,
            1920: 8200,
            2176: 2097160,
            2432: 8192,
            2688: 268443656,
            2944: 270532616,
            3200: 0,
            3456: 270540800,
            3712: 2105344,
            3968: 268435456,
            4096: 268443648,
            4352: 270532616,
            4608: 270540808,
            4864: 8200,
            5120: 2097152,
            5376: 268435456,
            5632: 268435464,
            5888: 2105344,
            6144: 2105352,
            6400: 0,
            6656: 8,
            6912: 270532608,
            7168: 8192,
            7424: 268443656,
            7680: 270540800,
            7936: 2097160,
            4224: 8,
            4480: 2105344,
            4736: 2097152,
            4992: 268435464,
            5248: 268443648,
            5504: 8200,
            5760: 270540808,
            6016: 270532608,
            6272: 270540800,
            6528: 270532616,
            6784: 8192,
            7040: 2105352,
            7296: 2097160,
            7552: 0,
            7808: 268435456,
            8064: 268443656
        }, {
            "0": 1048576,
            16: 33555457,
            32: 1024,
            48: 1049601,
            64: 34604033,
            80: 0,
            96: 1,
            112: 34603009,
            128: 33555456,
            144: 1048577,
            160: 33554433,
            176: 34604032,
            192: 34603008,
            208: 1025,
            224: 1049600,
            240: 33554432,
            8: 34603009,
            24: 0,
            40: 33555457,
            56: 34604032,
            72: 1048576,
            88: 33554433,
            104: 33554432,
            120: 1025,
            136: 1049601,
            152: 33555456,
            168: 34603008,
            184: 1048577,
            200: 1024,
            216: 34604033,
            232: 1,
            248: 1049600,
            256: 33554432,
            272: 1048576,
            288: 33555457,
            304: 34603009,
            320: 1048577,
            336: 33555456,
            352: 34604032,
            368: 1049601,
            384: 1025,
            400: 34604033,
            416: 1049600,
            432: 1,
            448: 0,
            464: 34603008,
            480: 33554433,
            496: 1024,
            264: 1049600,
            280: 33555457,
            296: 34603009,
            312: 1,
            328: 33554432,
            344: 1048576,
            360: 1025,
            376: 34604032,
            392: 33554433,
            408: 34603008,
            424: 0,
            440: 34604033,
            456: 1049601,
            472: 1024,
            488: 33555456,
            504: 1048577
        }, {
            "0": 134219808,
            1: 131072,
            2: 134217728,
            3: 32,
            4: 131104,
            5: 134350880,
            6: 134350848,
            7: 2048,
            8: 134348800,
            9: 134219776,
            10: 133120,
            11: 134348832,
            12: 2080,
            13: 0,
            14: 134217760,
            15: 133152,
            2147483648: 2048,
            2147483649: 134350880,
            2147483650: 134219808,
            2147483651: 134217728,
            2147483652: 134348800,
            2147483653: 133120,
            2147483654: 133152,
            2147483655: 32,
            2147483656: 134217760,
            2147483657: 2080,
            2147483658: 131104,
            2147483659: 134350848,
            2147483660: 0,
            2147483661: 134348832,
            2147483662: 134219776,
            2147483663: 131072,
            16: 133152,
            17: 134350848,
            18: 32,
            19: 2048,
            20: 134219776,
            21: 134217760,
            22: 134348832,
            23: 131072,
            24: 0,
            25: 131104,
            26: 134348800,
            27: 134219808,
            28: 134350880,
            29: 133120,
            30: 2080,
            31: 134217728,
            2147483664: 131072,
            2147483665: 2048,
            2147483666: 134348832,
            2147483667: 133152,
            2147483668: 32,
            2147483669: 134348800,
            2147483670: 134217728,
            2147483671: 134219808,
            2147483672: 134350880,
            2147483673: 134217760,
            2147483674: 134219776,
            2147483675: 0,
            2147483676: 133120,
            2147483677: 2080,
            2147483678: 131104,
            2147483679: 134350848
        }],
        t = [4160749569, 528482304, 33030144, 2064384, 129024, 8064, 504, 2147483679],
        m = g.DES = e.extend({
            _doReset: function() {
                for (var b = this._key.words, c = [], a = 0; 56 > a; a++) {
                    var f = q[a] - 1;
                    c[a] = b[f >>> 5] >>> 31 - f % 32 & 1
                }
                b = this._subKeys = [];
                for (f = 0; 16 > f; f++) {
                    for (var d = b[f] = [], e = r[f], a = 0; 24 > a; a++) d[a / 6 | 0] |= c[(p[a] - 1 + e) % 28] << 31 - a % 6, d[4 + (a / 6 | 0)] |= c[28 + (p[a + 24] - 1 + e) % 28] << 31 - a % 6;
                    d[0] = d[0] << 1 | d[0] >>> 31;
                    for (a = 1; 7 > a; a++) d[a] >>>=
                        4 * (a - 1) + 3;
                    d[7] = d[7] << 5 | d[7] >>> 27
                }
                c = this._invSubKeys = [];
                for (a = 0; 16 > a; a++) c[a] = b[15 - a]
            },
            encryptBlock: function(b, c) { this._doCryptBlock(b, c, this._subKeys) },
            decryptBlock: function(b, c) { this._doCryptBlock(b, c, this._invSubKeys) },
            _doCryptBlock: function(b, c, a) {
                this._lBlock = b[c];
                this._rBlock = b[c + 1];
                j.call(this, 4, 252645135);
                j.call(this, 16, 65535);
                l.call(this, 2, 858993459);
                l.call(this, 8, 16711935);
                j.call(this, 1, 1431655765);
                for (var f = 0; 16 > f; f++) {
                    for (var d = a[f], e = this._lBlock, h = this._rBlock, g = 0, k = 0; 8 > k; k++) g |= s[k][((h ^
                        d[k]) & t[k]) >>> 0];
                    this._lBlock = h;
                    this._rBlock = e ^ g
                }
                a = this._lBlock;
                this._lBlock = this._rBlock;
                this._rBlock = a;
                j.call(this, 1, 1431655765);
                l.call(this, 8, 16711935);
                l.call(this, 2, 858993459);
                j.call(this, 16, 65535);
                j.call(this, 4, 252645135);
                b[c] = this._lBlock;
                b[c + 1] = this._rBlock
            },
            keySize: 2,
            ivSize: 2,
            blockSize: 2
        });
    h.DES = e._createHelper(m);
    g = g.TripleDES = e.extend({
        _doReset: function() {
            var b = this._key.words;
            this._des1 = m.createEncryptor(n.create(b.slice(0, 2)));
            this._des2 = m.createEncryptor(n.create(b.slice(2, 4)));
            this._des3 =
                m.createEncryptor(n.create(b.slice(4, 6)))
        },
        encryptBlock: function(b, c) {
            this._des1.encryptBlock(b, c);
            this._des2.decryptBlock(b, c);
            this._des3.encryptBlock(b, c)
        },
        decryptBlock: function(b, c) {
            this._des3.decryptBlock(b, c);
            this._des2.encryptBlock(b, c);
            this._des1.decryptBlock(b, c)
        },
        keySize: 6,
        ivSize: 2,
        blockSize: 2
    });
    h.TripleDES = e._createHelper(g)
})();

/*
CryptoJS v3.1.2 enc-base64-min.js
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function() {
    var h = CryptoJS,
        j = h.lib.WordArray;
    h.enc.Base64 = {
        stringify: function(b) {
            var e = b.words,
                f = b.sigBytes,
                c = this._map;
            b.clamp();
            b = [];
            for (var a = 0; a < f; a += 3)
                for (var d = (e[a >>> 2] >>> 24 - 8 * (a % 4) & 255) << 16 | (e[a + 1 >>> 2] >>> 24 - 8 * ((a + 1) % 4) & 255) << 8 | e[a + 2 >>> 2] >>> 24 - 8 * ((a + 2) % 4) & 255, g = 0; 4 > g && a + 0.75 * g < f; g++) b.push(c.charAt(d >>> 6 * (3 - g) & 63));
            if (e = c.charAt(64))
                for (; b.length % 4;) b.push(e);
            return b.join("")
        },
        parse: function(b) {
            var e = b.length,
                f = this._map,
                c = f.charAt(64);
            c && (c = b.indexOf(c), -1 != c && (e = c));
            for (var c = [], a = 0, d = 0; d <
                e; d++)
                if (d % 4) {
                    var g = f.indexOf(b.charAt(d - 1)) << 2 * (d % 4),
                        h = f.indexOf(b.charAt(d)) >>> 6 - 2 * (d % 4);
                    c[a >>> 2] |= (g | h) << 24 - 8 * (a % 4);
                    a++
                }
            return j.create(c, a)
        },
        _map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    }
})();

/*
CryptoJS v3.1.2 md5-min.js
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(E) {
    function h(a, f, g, j, p, h, k) {
        a = a + (f & g | ~f & j) + p + k;
        return (a << h | a >>> 32 - h) + f
    }

    function k(a, f, g, j, p, h, k) {
        a = a + (f & j | g & ~j) + p + k;
        return (a << h | a >>> 32 - h) + f
    }

    function l(a, f, g, j, h, k, l) {
        a = a + (f ^ g ^ j) + h + l;
        return (a << k | a >>> 32 - k) + f
    }

    function n(a, f, g, j, h, k, l) {
        a = a + (g ^ (f | ~j)) + h + l;
        return (a << k | a >>> 32 - k) + f
    }
    for (var r = CryptoJS, q = r.lib, F = q.WordArray, s = q.Hasher, q = r.algo, a = [], t = 0; 64 > t; t++) a[t] = 4294967296 * E.abs(E.sin(t + 1)) | 0;
    q = q.MD5 = s.extend({
        _doReset: function() { this._hash = new F.init([1732584193, 4023233417, 2562383102, 271733878]) },
        _doProcessBlock: function(m, f) {
            for (var g = 0; 16 > g; g++) {
                var j = f + g,
                    p = m[j];
                m[j] = (p << 8 | p >>> 24) & 16711935 | (p << 24 | p >>> 8) & 4278255360
            }
            var g = this._hash.words,
                j = m[f + 0],
                p = m[f + 1],
                q = m[f + 2],
                r = m[f + 3],
                s = m[f + 4],
                t = m[f + 5],
                u = m[f + 6],
                v = m[f + 7],
                w = m[f + 8],
                x = m[f + 9],
                y = m[f + 10],
                z = m[f + 11],
                A = m[f + 12],
                B = m[f + 13],
                C = m[f + 14],
                D = m[f + 15],
                b = g[0],
                c = g[1],
                d = g[2],
                e = g[3],
                b = h(b, c, d, e, j, 7, a[0]),
                e = h(e, b, c, d, p, 12, a[1]),
                d = h(d, e, b, c, q, 17, a[2]),
                c = h(c, d, e, b, r, 22, a[3]),
                b = h(b, c, d, e, s, 7, a[4]),
                e = h(e, b, c, d, t, 12, a[5]),
                d = h(d, e, b, c, u, 17, a[6]),
                c = h(c, d, e, b, v, 22, a[7]),
                b = h(b, c, d, e, w, 7, a[8]),
                e = h(e, b, c, d, x, 12, a[9]),
                d = h(d, e, b, c, y, 17, a[10]),
                c = h(c, d, e, b, z, 22, a[11]),
                b = h(b, c, d, e, A, 7, a[12]),
                e = h(e, b, c, d, B, 12, a[13]),
                d = h(d, e, b, c, C, 17, a[14]),
                c = h(c, d, e, b, D, 22, a[15]),
                b = k(b, c, d, e, p, 5, a[16]),
                e = k(e, b, c, d, u, 9, a[17]),
                d = k(d, e, b, c, z, 14, a[18]),
                c = k(c, d, e, b, j, 20, a[19]),
                b = k(b, c, d, e, t, 5, a[20]),
                e = k(e, b, c, d, y, 9, a[21]),
                d = k(d, e, b, c, D, 14, a[22]),
                c = k(c, d, e, b, s, 20, a[23]),
                b = k(b, c, d, e, x, 5, a[24]),
                e = k(e, b, c, d, C, 9, a[25]),
                d = k(d, e, b, c, r, 14, a[26]),
                c = k(c, d, e, b, w, 20, a[27]),
                b = k(b, c, d, e, B, 5, a[28]),
                e = k(e, b,
                    c, d, q, 9, a[29]),
                d = k(d, e, b, c, v, 14, a[30]),
                c = k(c, d, e, b, A, 20, a[31]),
                b = l(b, c, d, e, t, 4, a[32]),
                e = l(e, b, c, d, w, 11, a[33]),
                d = l(d, e, b, c, z, 16, a[34]),
                c = l(c, d, e, b, C, 23, a[35]),
                b = l(b, c, d, e, p, 4, a[36]),
                e = l(e, b, c, d, s, 11, a[37]),
                d = l(d, e, b, c, v, 16, a[38]),
                c = l(c, d, e, b, y, 23, a[39]),
                b = l(b, c, d, e, B, 4, a[40]),
                e = l(e, b, c, d, j, 11, a[41]),
                d = l(d, e, b, c, r, 16, a[42]),
                c = l(c, d, e, b, u, 23, a[43]),
                b = l(b, c, d, e, x, 4, a[44]),
                e = l(e, b, c, d, A, 11, a[45]),
                d = l(d, e, b, c, D, 16, a[46]),
                c = l(c, d, e, b, q, 23, a[47]),
                b = n(b, c, d, e, j, 6, a[48]),
                e = n(e, b, c, d, v, 10, a[49]),
                d = n(d, e, b, c,
                    C, 15, a[50]),
                c = n(c, d, e, b, t, 21, a[51]),
                b = n(b, c, d, e, A, 6, a[52]),
                e = n(e, b, c, d, r, 10, a[53]),
                d = n(d, e, b, c, y, 15, a[54]),
                c = n(c, d, e, b, p, 21, a[55]),
                b = n(b, c, d, e, w, 6, a[56]),
                e = n(e, b, c, d, D, 10, a[57]),
                d = n(d, e, b, c, u, 15, a[58]),
                c = n(c, d, e, b, B, 21, a[59]),
                b = n(b, c, d, e, s, 6, a[60]),
                e = n(e, b, c, d, z, 10, a[61]),
                d = n(d, e, b, c, q, 15, a[62]),
                c = n(c, d, e, b, x, 21, a[63]);
            g[0] = g[0] + b | 0;
            g[1] = g[1] + c | 0;
            g[2] = g[2] + d | 0;
            g[3] = g[3] + e | 0
        },
        _doFinalize: function() {
            var a = this._data,
                f = a.words,
                g = 8 * this._nDataBytes,
                j = 8 * a.sigBytes;
            f[j >>> 5] |= 128 << 24 - j % 32;
            var h = E.floor(g /
                4294967296);
            f[(j + 64 >>> 9 << 4) + 15] = (h << 8 | h >>> 24) & 16711935 | (h << 24 | h >>> 8) & 4278255360;
            f[(j + 64 >>> 9 << 4) + 14] = (g << 8 | g >>> 24) & 16711935 | (g << 24 | g >>> 8) & 4278255360;
            a.sigBytes = 4 * (f.length + 1);
            this._process();
            a = this._hash;
            f = a.words;
            for (g = 0; 4 > g; g++) j = f[g], f[g] = (j << 8 | j >>> 24) & 16711935 | (j << 24 | j >>> 8) & 4278255360;
            return a
        },
        clone: function() {
            var a = s.clone.call(this);
            a._hash = this._hash.clone();
            return a
        }
    });
    r.MD5 = s._createHelper(q);
    r.HmacMD5 = s._createHmacHelper(q)
})(Math);

/*
CryptoJS v3.1.2 sha1-min.js
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function() {
    var k = CryptoJS,
        b = k.lib,
        m = b.WordArray,
        l = b.Hasher,
        d = [],
        b = k.algo.SHA1 = l.extend({
            _doReset: function() { this._hash = new m.init([1732584193, 4023233417, 2562383102, 271733878, 3285377520]) },
            _doProcessBlock: function(n, p) {
                for (var a = this._hash.words, e = a[0], f = a[1], h = a[2], j = a[3], b = a[4], c = 0; 80 > c; c++) {
                    if (16 > c) d[c] = n[p + c] | 0;
                    else {
                        var g = d[c - 3] ^ d[c - 8] ^ d[c - 14] ^ d[c - 16];
                        d[c] = g << 1 | g >>> 31
                    }
                    g = (e << 5 | e >>> 27) + b + d[c];
                    g = 20 > c ? g + ((f & h | ~f & j) + 1518500249) : 40 > c ? g + ((f ^ h ^ j) + 1859775393) : 60 > c ? g + ((f & h | f & j | h & j) - 1894007588) : g + ((f ^ h ^
                        j) - 899497514);
                    b = j;
                    j = h;
                    h = f << 30 | f >>> 2;
                    f = e;
                    e = g
                }
                a[0] = a[0] + e | 0;
                a[1] = a[1] + f | 0;
                a[2] = a[2] + h | 0;
                a[3] = a[3] + j | 0;
                a[4] = a[4] + b | 0
            },
            _doFinalize: function() {
                var b = this._data,
                    d = b.words,
                    a = 8 * this._nDataBytes,
                    e = 8 * b.sigBytes;
                d[e >>> 5] |= 128 << 24 - e % 32;
                d[(e + 64 >>> 9 << 4) + 14] = Math.floor(a / 4294967296);
                d[(e + 64 >>> 9 << 4) + 15] = a;
                b.sigBytes = 4 * d.length;
                this._process();
                return this._hash
            },
            clone: function() {
                var b = l.clone.call(this);
                b._hash = this._hash.clone();
                return b
            }
        });
    k.SHA1 = l._createHelper(b);
    k.HmacSHA1 = l._createHmacHelper(b)
})();

/*
CryptoJS v3.1.2 sha256-min.js
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function(k) {
    for (var g = CryptoJS, h = g.lib, v = h.WordArray, j = h.Hasher, h = g.algo, s = [], t = [], u = function(q) {
            return 4294967296 * (q - (q | 0)) | 0
        }, l = 2, b = 0; 64 > b;) {
        var d;
        a: {
            d = l;
            for (var w = k.sqrt(d), r = 2; r <= w; r++)
                if (!(d % r)) {
                    d = !1;
                    break a
                }
            d = !0
        }
        d && (8 > b && (s[b] = u(k.pow(l, 0.5))), t[b] = u(k.pow(l, 1 / 3)), b++);
        l++
    }
    var n = [],
        h = h.SHA256 = j.extend({
            _doReset: function() { this._hash = new v.init(s.slice(0)) },
            _doProcessBlock: function(q, h) {
                for (var a = this._hash.words, c = a[0], d = a[1], b = a[2], k = a[3], f = a[4], g = a[5], j = a[6], l = a[7], e = 0; 64 > e; e++) {
                    if (16 > e) n[e] =
                        q[h + e] | 0;
                    else {
                        var m = n[e - 15],
                            p = n[e - 2];
                        n[e] = ((m << 25 | m >>> 7) ^ (m << 14 | m >>> 18) ^ m >>> 3) + n[e - 7] + ((p << 15 | p >>> 17) ^ (p << 13 | p >>> 19) ^ p >>> 10) + n[e - 16]
                    }
                    m = l + ((f << 26 | f >>> 6) ^ (f << 21 | f >>> 11) ^ (f << 7 | f >>> 25)) + (f & g ^ ~f & j) + t[e] + n[e];
                    p = ((c << 30 | c >>> 2) ^ (c << 19 | c >>> 13) ^ (c << 10 | c >>> 22)) + (c & d ^ c & b ^ d & b);
                    l = j;
                    j = g;
                    g = f;
                    f = k + m | 0;
                    k = b;
                    b = d;
                    d = c;
                    c = m + p | 0
                }
                a[0] = a[0] + c | 0;
                a[1] = a[1] + d | 0;
                a[2] = a[2] + b | 0;
                a[3] = a[3] + k | 0;
                a[4] = a[4] + f | 0;
                a[5] = a[5] + g | 0;
                a[6] = a[6] + j | 0;
                a[7] = a[7] + l | 0
            },
            _doFinalize: function() {
                var d = this._data,
                    b = d.words,
                    a = 8 * this._nDataBytes,
                    c = 8 * d.sigBytes;
                b[c >>> 5] |= 128 << 24 - c % 32;
                b[(c + 64 >>> 9 << 4) + 14] = k.floor(a / 4294967296);
                b[(c + 64 >>> 9 << 4) + 15] = a;
                d.sigBytes = 4 * b.length;
                this._process();
                return this._hash
            },
            clone: function() {
                var b = j.clone.call(this);
                b._hash = this._hash.clone();
                return b
            }
        });
    g.SHA256 = j._createHelper(h);
    g.HmacSHA256 = j._createHmacHelper(h)
})(Math);

/*
CryptoJS v3.1.2 sha224-min.js
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function() {
    var b = CryptoJS,
        d = b.lib.WordArray,
        a = b.algo,
        c = a.SHA256,
        a = a.SHA224 = c.extend({
            _doReset: function() { this._hash = new d.init([3238371032, 914150663, 812702999, 4144912697, 4290775857, 1750603025, 1694076839, 3204075428]) },
            _doFinalize: function() {
                var a = c._doFinalize.call(this);
                a.sigBytes -= 4;
                return a
            }
        });
    b.SHA224 = c._createHelper(a);
    b.HmacSHA224 = c._createHmacHelper(a)
})();

/*
CryptoJS v3.1.2 sha512-min.js
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function() {
    function a() {
        return d.create.apply(d, arguments)
    }
    for (var n = CryptoJS, r = n.lib.Hasher, e = n.x64, d = e.Word, T = e.WordArray, e = n.algo, ea = [a(1116352408, 3609767458), a(1899447441, 602891725), a(3049323471, 3964484399), a(3921009573, 2173295548), a(961987163, 4081628472), a(1508970993, 3053834265), a(2453635748, 2937671579), a(2870763221, 3664609560), a(3624381080, 2734883394), a(310598401, 1164996542), a(607225278, 1323610764), a(1426881987, 3590304994), a(1925078388, 4068182383), a(2162078206, 991336113), a(2614888103, 633803317),
            a(3248222580, 3479774868), a(3835390401, 2666613458), a(4022224774, 944711139), a(264347078, 2341262773), a(604807628, 2007800933), a(770255983, 1495990901), a(1249150122, 1856431235), a(1555081692, 3175218132), a(1996064986, 2198950837), a(2554220882, 3999719339), a(2821834349, 766784016), a(2952996808, 2566594879), a(3210313671, 3203337956), a(3336571891, 1034457026), a(3584528711, 2466948901), a(113926993, 3758326383), a(338241895, 168717936), a(666307205, 1188179964), a(773529912, 1546045734), a(1294757372, 1522805485), a(1396182291,
                2643833823), a(1695183700, 2343527390), a(1986661051, 1014477480), a(2177026350, 1206759142), a(2456956037, 344077627), a(2730485921, 1290863460), a(2820302411, 3158454273), a(3259730800, 3505952657), a(3345764771, 106217008), a(3516065817, 3606008344), a(3600352804, 1432725776), a(4094571909, 1467031594), a(275423344, 851169720), a(430227734, 3100823752), a(506948616, 1363258195), a(659060556, 3750685593), a(883997877, 3785050280), a(958139571, 3318307427), a(1322822218, 3812723403), a(1537002063, 2003034995), a(1747873779, 3602036899),
            a(1955562222, 1575990012), a(2024104815, 1125592928), a(2227730452, 2716904306), a(2361852424, 442776044), a(2428436474, 593698344), a(2756734187, 3733110249), a(3204031479, 2999351573), a(3329325298, 3815920427), a(3391569614, 3928383900), a(3515267271, 566280711), a(3940187606, 3454069534), a(4118630271, 4000239992), a(116418474, 1914138554), a(174292421, 2731055270), a(289380356, 3203993006), a(460393269, 320620315), a(685471733, 587496836), a(852142971, 1086792851), a(1017036298, 365543100), a(1126000580, 2618297676), a(1288033470,
                3409855158), a(1501505948, 4234509866), a(1607167915, 987167468), a(1816402316, 1246189591)
        ], v = [], w = 0; 80 > w; w++) v[w] = a();
    e = e.SHA512 = r.extend({
        _doReset: function() { this._hash = new T.init([new d.init(1779033703, 4089235720), new d.init(3144134277, 2227873595), new d.init(1013904242, 4271175723), new d.init(2773480762, 1595750129), new d.init(1359893119, 2917565137), new d.init(2600822924, 725511199), new d.init(528734635, 4215389547), new d.init(1541459225, 327033209)]) },
        _doProcessBlock: function(a, d) {
            for (var f = this._hash.words,
                    F = f[0], e = f[1], n = f[2], r = f[3], G = f[4], H = f[5], I = f[6], f = f[7], w = F.high, J = F.low, X = e.high, K = e.low, Y = n.high, L = n.low, Z = r.high, M = r.low, $ = G.high, N = G.low, aa = H.high, O = H.low, ba = I.high, P = I.low, ca = f.high, Q = f.low, k = w, g = J, z = X, x = K, A = Y, y = L, U = Z, B = M, l = $, h = N, R = aa, C = O, S = ba, D = P, V = ca, E = Q, m = 0; 80 > m; m++) {
                var s = v[m];
                if (16 > m) var j = s.high = a[d + 2 * m] | 0,
                    b = s.low = a[d + 2 * m + 1] | 0;
                else {
                    var j = v[m - 15],
                        b = j.high,
                        p = j.low,
                        j = (b >>> 1 | p << 31) ^ (b >>> 8 | p << 24) ^ b >>> 7,
                        p = (p >>> 1 | b << 31) ^ (p >>> 8 | b << 24) ^ (p >>> 7 | b << 25),
                        u = v[m - 2],
                        b = u.high,
                        c = u.low,
                        u = (b >>> 19 | c << 13) ^ (b <<
                            3 | c >>> 29) ^ b >>> 6,
                        c = (c >>> 19 | b << 13) ^ (c << 3 | b >>> 29) ^ (c >>> 6 | b << 26),
                        b = v[m - 7],
                        W = b.high,
                        t = v[m - 16],
                        q = t.high,
                        t = t.low,
                        b = p + b.low,
                        j = j + W + (b >>> 0 < p >>> 0 ? 1 : 0),
                        b = b + c,
                        j = j + u + (b >>> 0 < c >>> 0 ? 1 : 0),
                        b = b + t,
                        j = j + q + (b >>> 0 < t >>> 0 ? 1 : 0);
                    s.high = j;
                    s.low = b
                }
                var W = l & R ^ ~l & S,
                    t = h & C ^ ~h & D,
                    s = k & z ^ k & A ^ z & A,
                    T = g & x ^ g & y ^ x & y,
                    p = (k >>> 28 | g << 4) ^ (k << 30 | g >>> 2) ^ (k << 25 | g >>> 7),
                    u = (g >>> 28 | k << 4) ^ (g << 30 | k >>> 2) ^ (g << 25 | k >>> 7),
                    c = ea[m],
                    fa = c.high,
                    da = c.low,
                    c = E + ((h >>> 14 | l << 18) ^ (h >>> 18 | l << 14) ^ (h << 23 | l >>> 9)),
                    q = V + ((l >>> 14 | h << 18) ^ (l >>> 18 | h << 14) ^ (l << 23 | h >>> 9)) + (c >>> 0 < E >>> 0 ? 1 :
                        0),
                    c = c + t,
                    q = q + W + (c >>> 0 < t >>> 0 ? 1 : 0),
                    c = c + da,
                    q = q + fa + (c >>> 0 < da >>> 0 ? 1 : 0),
                    c = c + b,
                    q = q + j + (c >>> 0 < b >>> 0 ? 1 : 0),
                    b = u + T,
                    s = p + s + (b >>> 0 < u >>> 0 ? 1 : 0),
                    V = S,
                    E = D,
                    S = R,
                    D = C,
                    R = l,
                    C = h,
                    h = B + c | 0,
                    l = U + q + (h >>> 0 < B >>> 0 ? 1 : 0) | 0,
                    U = A,
                    B = y,
                    A = z,
                    y = x,
                    z = k,
                    x = g,
                    g = c + b | 0,
                    k = q + s + (g >>> 0 < c >>> 0 ? 1 : 0) | 0
            }
            J = F.low = J + g;
            F.high = w + k + (J >>> 0 < g >>> 0 ? 1 : 0);
            K = e.low = K + x;
            e.high = X + z + (K >>> 0 < x >>> 0 ? 1 : 0);
            L = n.low = L + y;
            n.high = Y + A + (L >>> 0 < y >>> 0 ? 1 : 0);
            M = r.low = M + B;
            r.high = Z + U + (M >>> 0 < B >>> 0 ? 1 : 0);
            N = G.low = N + h;
            G.high = $ + l + (N >>> 0 < h >>> 0 ? 1 : 0);
            O = H.low = O + C;
            H.high = aa + R + (O >>> 0 < C >>> 0 ? 1 : 0);
            P = I.low = P + D;
            I.high = ba + S + (P >>> 0 < D >>> 0 ? 1 : 0);
            Q = f.low = Q + E;
            f.high = ca + V + (Q >>> 0 < E >>> 0 ? 1 : 0)
        },
        _doFinalize: function() {
            var a = this._data,
                d = a.words,
                f = 8 * this._nDataBytes,
                e = 8 * a.sigBytes;
            d[e >>> 5] |= 128 << 24 - e % 32;
            d[(e + 128 >>> 10 << 5) + 30] = Math.floor(f / 4294967296);
            d[(e + 128 >>> 10 << 5) + 31] = f;
            a.sigBytes = 4 * d.length;
            this._process();
            return this._hash.toX32()
        },
        clone: function() {
            var a = r.clone.call(this);
            a._hash = this._hash.clone();
            return a
        },
        blockSize: 32
    });
    n.SHA512 = r._createHelper(e);
    n.HmacSHA512 = r._createHmacHelper(e)
})();

/*
CryptoJS v3.1.2 sha384-min.js
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function() {
    var c = CryptoJS,
        a = c.x64,
        b = a.Word,
        e = a.WordArray,
        a = c.algo,
        d = a.SHA512,
        a = a.SHA384 = d.extend({
            _doReset: function() { this._hash = new e.init([new b.init(3418070365, 3238371032), new b.init(1654270250, 914150663), new b.init(2438529370, 812702999), new b.init(355462360, 4144912697), new b.init(1731405415, 4290775857), new b.init(2394180231, 1750603025), new b.init(3675008525, 1694076839), new b.init(1203062813, 3204075428)]) },
            _doFinalize: function() {
                var a = d._doFinalize.call(this);
                a.sigBytes -= 16;
                return a
            }
        });
    c.SHA384 =
        d._createHelper(a);
    c.HmacSHA384 = d._createHmacHelper(a)
})();

/*
CryptoJS v3.1.2 ripemd160-min.js
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
/*

(c) 2012 by Cedric Mesnil. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    - Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
(function() {
    var q = CryptoJS,
        d = q.lib,
        n = d.WordArray,
        p = d.Hasher,
        d = q.algo,
        x = n.create([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]),
        y = n.create([5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]),
        z = n.create([11, 14, 15, 12,
            5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
        ]),
        A = n.create([8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]),
        B = n.create([0, 1518500249, 1859775393, 2400959708, 2840853838]),
        C = n.create([1352829926, 1548603684, 1836072691,
            2053994217, 0
        ]),
        d = d.RIPEMD160 = p.extend({
            _doReset: function() { this._hash = n.create([1732584193, 4023233417, 2562383102, 271733878, 3285377520]) },
            _doProcessBlock: function(e, v) {
                for (var b = 0; 16 > b; b++) {
                    var c = v + b,
                        f = e[c];
                    e[c] = (f << 8 | f >>> 24) & 16711935 | (f << 24 | f >>> 8) & 4278255360
                }
                var c = this._hash.words,
                    f = B.words,
                    d = C.words,
                    n = x.words,
                    q = y.words,
                    p = z.words,
                    w = A.words,
                    t, g, h, j, r, u, k, l, m, s;
                u = t = c[0];
                k = g = c[1];
                l = h = c[2];
                m = j = c[3];
                s = r = c[4];
                for (var a, b = 0; 80 > b; b += 1) a = t + e[v + n[b]] | 0, a = 16 > b ? a + ((g ^ h ^ j) + f[0]) : 32 > b ? a + ((g & h | ~g & j) + f[1]) : 48 > b ?
                    a + (((g | ~h) ^ j) + f[2]) : 64 > b ? a + ((g & j | h & ~j) + f[3]) : a + ((g ^ (h | ~j)) + f[4]), a |= 0, a = a << p[b] | a >>> 32 - p[b], a = a + r | 0, t = r, r = j, j = h << 10 | h >>> 22, h = g, g = a, a = u + e[v + q[b]] | 0, a = 16 > b ? a + ((k ^ (l | ~m)) + d[0]) : 32 > b ? a + ((k & m | l & ~m) + d[1]) : 48 > b ? a + (((k | ~l) ^ m) + d[2]) : 64 > b ? a + ((k & l | ~k & m) + d[3]) : a + ((k ^ l ^ m) + d[4]), a |= 0, a = a << w[b] | a >>> 32 - w[b], a = a + s | 0, u = s, s = m, m = l << 10 | l >>> 22, l = k, k = a;
                a = c[1] + h + m | 0;
                c[1] = c[2] + j + s | 0;
                c[2] = c[3] + r + u | 0;
                c[3] = c[4] + t + k | 0;
                c[4] = c[0] + g + l | 0;
                c[0] = a
            },
            _doFinalize: function() {
                var e = this._data,
                    d = e.words,
                    b = 8 * this._nDataBytes,
                    c = 8 * e.sigBytes;
                d[c >>> 5] |= 128 << 24 - c % 32;
                d[(c + 64 >>> 9 << 4) + 14] = (b << 8 | b >>> 24) & 16711935 | (b << 24 | b >>> 8) & 4278255360;
                e.sigBytes = 4 * (d.length + 1);
                this._process();
                e = this._hash;
                d = e.words;
                for (b = 0; 5 > b; b++) c = d[b], d[b] = (c << 8 | c >>> 24) & 16711935 | (c << 24 | c >>> 8) & 4278255360;
                return e
            },
            clone: function() {
                var d = p.clone.call(this);
                d._hash = this._hash.clone();
                return d
            }
        });
    q.RIPEMD160 = p._createHelper(d);
    q.HmacRIPEMD160 = p._createHmacHelper(d)
})(Math);

/*
CryptoJS v3.1.2 hmac-min.js
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function() {
    var c = CryptoJS,
        k = c.enc.Utf8;
    c.algo.HMAC = c.lib.Base.extend({
        init: function(a, b) {
            a = this._hasher = new a.init;
            "string" == typeof b && (b = k.parse(b));
            var c = a.blockSize,
                e = 4 * c;
            b.sigBytes > e && (b = a.finalize(b));
            b.clamp();
            for (var f = this._oKey = b.clone(), g = this._iKey = b.clone(), h = f.words, j = g.words, d = 0; d < c; d++) h[d] ^= 1549556828, j[d] ^= 909522486;
            f.sigBytes = g.sigBytes = e;
            this.reset()
        },
        reset: function() {
            var a = this._hasher;
            a.reset();
            a.update(this._iKey)
        },
        update: function(a) {
            this._hasher.update(a);
            return this
        },
        finalize: function(a) {
            var b =
                this._hasher;
            a = b.finalize(a);
            b.reset();
            return b.finalize(this._oKey.clone().concat(a))
        }
    })
})();

/*
CryptoJS v3.1.2 pbkdf2-min.js
code.google.com/p/crypto-js
(c) 2009-2013 by Jeff Mott. All rights reserved.
code.google.com/p/crypto-js/wiki/License
*/
(function() {
    var b = CryptoJS,
        a = b.lib,
        d = a.Base,
        m = a.WordArray,
        a = b.algo,
        q = a.HMAC,
        l = a.PBKDF2 = d.extend({
            cfg: d.extend({ keySize: 4, hasher: a.SHA1, iterations: 1 }),
            init: function(a) { this.cfg = this.cfg.extend(a) },
            compute: function(a, b) {
                for (var c = this.cfg, f = q.create(c.hasher, a), g = m.create(), d = m.create([1]), l = g.words, r = d.words, n = c.keySize, c = c.iterations; l.length < n;) {
                    var h = f.update(b).finalize(d);
                    f.reset();
                    for (var j = h.words, s = j.length, k = h, p = 1; p < c; p++) {
                        k = f.finalize(k);
                        f.reset();
                        for (var t = k.words, e = 0; e < s; e++) j[e] ^= t[e]
                    }
                    g.concat(h);
                    r[0]++
                }
                g.sigBytes = 4 * n;
                return g
            }
        });
    b.PBKDF2 = function(a, b, c) {
        return l.create(c).compute(a, b)
    }
})();

/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
var b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var b64pad = "=";

function hex2b64(d) {
    var b;
    var e;
    var a = "";
    for (b = 0; b + 3 <= d.length; b += 3) {
        e = parseInt(d.substring(b, b + 3), 16);
        a += b64map.charAt(e >> 6) + b64map.charAt(e & 63)
    }
    if (b + 1 == d.length) {
        e = parseInt(d.substring(b, b + 1), 16);
        a += b64map.charAt(e << 2)
    } else {
        if (b + 2 == d.length) {
            e = parseInt(d.substring(b, b + 2), 16);
            a += b64map.charAt(e >> 2) + b64map.charAt((e & 3) << 4)
        }
    }
    if (b64pad) {
        while ((a.length & 3) > 0) { a += b64pad }
    }
    return a
}

function b64tohex(f) {
    var d = "";
    var e;
    var b = 0;
    var c;
    var a;
    for (e = 0; e < f.length; ++e) {
        if (f.charAt(e) == b64pad) {
            break
        }
        a = b64map.indexOf(f.charAt(e));
        if (a < 0) {
            continue
        }
        if (b == 0) {
            d += int2char(a >> 2);
            c = a & 3;
            b = 1
        } else {
            if (b == 1) {
                d += int2char((c << 2) | (a >> 4));
                c = a & 15;
                b = 2
            } else {
                if (b == 2) {
                    d += int2char(c);
                    d += int2char(a >> 2);
                    c = a & 3;
                    b = 3
                } else {
                    d += int2char((c << 2) | (a >> 4));
                    d += int2char(a & 15);
                    b = 0
                }
            }
        }
    }
    if (b == 1) { d += int2char(c << 2) }
    return d
}

function b64toBA(e) {
    var d = b64tohex(e);
    var c;
    var b = new Array();
    for (c = 0; 2 * c < d.length; ++c) { b[c] = parseInt(d.substring(2 * c, 2 * c + 2), 16) }
    return b
};
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
var dbits;
var canary = 244837814094590;
var j_lm = ((canary & 16777215) == 15715070);

function BigInteger(e, d, f) {
    if (e != null) {
        if ("number" == typeof e) { this.fromNumber(e, d, f) } else {
            if (d == null && "string" != typeof e) { this.fromString(e, 256) } else { this.fromString(e, d) }
        }
    }
}

function nbi() {
    return new BigInteger(null)
}

function am1(f, a, b, e, h, g) {
    while (--g >= 0) {
        var d = a * this[f++] + b[e] + h;
        h = Math.floor(d / 67108864);
        b[e++] = d & 67108863
    }
    return h
}

function am2(f, q, r, e, o, a) {
    var k = q & 32767,
        p = q >> 15;
    while (--a >= 0) {
        var d = this[f] & 32767;
        var g = this[f++] >> 15;
        var b = p * d + g * k;
        d = k * d + ((b & 32767) << 15) + r[e] + (o & 1073741823);
        o = (d >>> 30) + (b >>> 15) + p * g + (o >>> 30);
        r[e++] = d & 1073741823
    }
    return o
}

function am3(f, q, r, e, o, a) {
    var k = q & 16383,
        p = q >> 14;
    while (--a >= 0) {
        var d = this[f] & 16383;
        var g = this[f++] >> 14;
        var b = p * d + g * k;
        d = k * d + ((b & 16383) << 14) + r[e] + o;
        o = (d >> 28) + (b >> 14) + p * g;
        r[e++] = d & 268435455
    }
    return o
}
if (j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
    BigInteger.prototype.am = am2;
    dbits = 30
} else {
    if (j_lm && (navigator.appName != "Netscape")) {
        BigInteger.prototype.am = am1;
        dbits = 26
    } else {
        BigInteger.prototype.am = am3;
        dbits = 28
    }
}
BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1 << dbits) - 1);
BigInteger.prototype.DV = (1 << dbits);
var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2, BI_FP);
BigInteger.prototype.F1 = BI_FP - dbits;
BigInteger.prototype.F2 = 2 * dbits - BI_FP;
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr, vv;
rr = "0".charCodeAt(0);
for (vv = 0; vv <= 9; ++vv) { BI_RC[rr++] = vv }
rr = "a".charCodeAt(0);
for (vv = 10; vv < 36; ++vv) { BI_RC[rr++] = vv }
rr = "A".charCodeAt(0);
for (vv = 10; vv < 36; ++vv) { BI_RC[rr++] = vv }

function int2char(a) {
    return BI_RM.charAt(a)
}

function intAt(b, a) {
    var d = BI_RC[b.charCodeAt(a)];
    return (d == null) ? -1 : d
}

function bnpCopyTo(b) {
    for (var a = this.t - 1; a >= 0; --a) { b[a] = this[a] }
    b.t = this.t;
    b.s = this.s
}

function bnpFromInt(a) {
    this.t = 1;
    this.s = (a < 0) ? -1 : 0;
    if (a > 0) { this[0] = a } else {
        if (a < -1) { this[0] = a + this.DV } else { this.t = 0 }
    }
}

function nbv(a) {
    var b = nbi();
    b.fromInt(a);
    return b
}

function bnpFromString(h, c) {
    var e;
    if (c == 16) { e = 4 } else {
        if (c == 8) { e = 3 } else {
            if (c == 256) { e = 8 } else {
                if (c == 2) { e = 1 } else {
                    if (c == 32) { e = 5 } else {
                        if (c == 4) { e = 2 } else {
                            this.fromRadix(h, c);
                            return
                        }
                    }
                }
            }
        }
    }
    this.t = 0;
    this.s = 0;
    var g = h.length,
        d = false,
        f = 0;
    while (--g >= 0) {
        var a = (e == 8) ? h[g] & 255 : intAt(h, g);
        if (a < 0) {
            if (h.charAt(g) == "-") { d = true }
            continue
        }
        d = false;
        if (f == 0) { this[this.t++] = a } else {
            if (f + e > this.DB) {
                this[this.t - 1] |= (a & ((1 << (this.DB - f)) - 1)) << f;
                this[this.t++] = (a >> (this.DB - f))
            } else { this[this.t - 1] |= a << f }
        }
        f += e;
        if (f >= this.DB) { f -= this.DB }
    }
    if (e == 8 && (h[0] & 128) != 0) {
        this.s = -1;
        if (f > 0) { this[this.t - 1] |= ((1 << (this.DB - f)) - 1) << f }
    }
    this.clamp();
    if (d) { BigInteger.ZERO.subTo(this, this) }
}

function bnpClamp() {
    var a = this.s & this.DM;
    while (this.t > 0 && this[this.t - 1] == a) {--this.t }
}

function bnToString(c) {
    if (this.s < 0) {
        return "-" + this.negate().toString(c)
    }
    var e;
    if (c == 16) { e = 4 } else {
        if (c == 8) { e = 3 } else {
            if (c == 2) { e = 1 } else {
                if (c == 32) { e = 5 } else {
                    if (c == 4) { e = 2 } else {
                        return this.toRadix(c)
                    }
                }
            }
        }
    }
    var g = (1 << e) - 1,
        l, a = false,
        h = "",
        f = this.t;
    var j = this.DB - (f * this.DB) % e;
    if (f-- > 0) {
        if (j < this.DB && (l = this[f] >> j) > 0) {
            a = true;
            h = int2char(l)
        }
        while (f >= 0) {
            if (j < e) {
                l = (this[f] & ((1 << j) - 1)) << (e - j);
                l |= this[--f] >> (j += this.DB - e)
            } else {
                l = (this[f] >> (j -= e)) & g;
                if (j <= 0) { j += this.DB;--f }
            }
            if (l > 0) { a = true }
            if (a) { h += int2char(l) }
        }
    }
    return a ? h : "0"
}

function bnNegate() {
    var a = nbi();
    BigInteger.ZERO.subTo(this, a);
    return a
}

function bnAbs() {
    return (this.s < 0) ? this.negate() : this
}

function bnCompareTo(b) {
    var d = this.s - b.s;
    if (d != 0) {
        return d
    }
    var c = this.t;
    d = c - b.t;
    if (d != 0) {
        return (this.s < 0) ? -d : d
    }
    while (--c >= 0) {
        if ((d = this[c] - b[c]) != 0) {
            return d
        }
    }
    return 0
}

function nbits(a) {
    var c = 1,
        b;
    if ((b = a >>> 16) != 0) {
        a = b;
        c += 16
    }
    if ((b = a >> 8) != 0) {
        a = b;
        c += 8
    }
    if ((b = a >> 4) != 0) {
        a = b;
        c += 4
    }
    if ((b = a >> 2) != 0) {
        a = b;
        c += 2
    }
    if ((b = a >> 1) != 0) {
        a = b;
        c += 1
    }
    return c
}

function bnBitLength() {
    if (this.t <= 0) {
        return 0
    }
    return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM))
}

function bnpDLShiftTo(c, b) {
    var a;
    for (a = this.t - 1; a >= 0; --a) { b[a + c] = this[a] }
    for (a = c - 1; a >= 0; --a) { b[a] = 0 }
    b.t = this.t + c;
    b.s = this.s
}

function bnpDRShiftTo(c, b) {
    for (var a = c; a < this.t; ++a) { b[a - c] = this[a] }
    b.t = Math.max(this.t - c, 0);
    b.s = this.s
}

function bnpLShiftTo(j, e) {
    var b = j % this.DB;
    var a = this.DB - b;
    var g = (1 << a) - 1;
    var f = Math.floor(j / this.DB),
        h = (this.s << b) & this.DM,
        d;
    for (d = this.t - 1; d >= 0; --d) {
        e[d + f + 1] = (this[d] >> a) | h;
        h = (this[d] & g) << b
    }
    for (d = f - 1; d >= 0; --d) { e[d] = 0 }
    e[f] = h;
    e.t = this.t + f + 1;
    e.s = this.s;
    e.clamp()
}

function bnpRShiftTo(g, d) {
    d.s = this.s;
    var e = Math.floor(g / this.DB);
    if (e >= this.t) {
        d.t = 0;
        return
    }
    var b = g % this.DB;
    var a = this.DB - b;
    var f = (1 << b) - 1;
    d[0] = this[e] >> b;
    for (var c = e + 1; c < this.t; ++c) {
        d[c - e - 1] |= (this[c] & f) << a;
        d[c - e] = this[c] >> b
    }
    if (b > 0) { d[this.t - e - 1] |= (this.s & f) << a }
    d.t = this.t - e;
    d.clamp()
}

function bnpSubTo(d, f) {
    var e = 0,
        g = 0,
        b = Math.min(d.t, this.t);
    while (e < b) {
        g += this[e] - d[e];
        f[e++] = g & this.DM;
        g >>= this.DB
    }
    if (d.t < this.t) {
        g -= d.s;
        while (e < this.t) {
            g += this[e];
            f[e++] = g & this.DM;
            g >>= this.DB
        }
        g += this.s
    } else {
        g += this.s;
        while (e < d.t) {
            g -= d[e];
            f[e++] = g & this.DM;
            g >>= this.DB
        }
        g -= d.s
    }
    f.s = (g < 0) ? -1 : 0;
    if (g < -1) { f[e++] = this.DV + g } else {
        if (g > 0) { f[e++] = g }
    }
    f.t = e;
    f.clamp()
}

function bnpMultiplyTo(c, e) {
    var b = this.abs(),
        f = c.abs();
    var d = b.t;
    e.t = d + f.t;
    while (--d >= 0) { e[d] = 0 }
    for (d = 0; d < f.t; ++d) { e[d + b.t] = b.am(0, f[d], e, d, 0, b.t) }
    e.s = 0;
    e.clamp();
    if (this.s != c.s) { BigInteger.ZERO.subTo(e, e) }
}

function bnpSquareTo(d) {
    var a = this.abs();
    var b = d.t = 2 * a.t;
    while (--b >= 0) { d[b] = 0 }
    for (b = 0; b < a.t - 1; ++b) {
        var e = a.am(b, a[b], d, 2 * b, 0, 1);
        if ((d[b + a.t] += a.am(b + 1, 2 * a[b], d, 2 * b + 1, e, a.t - b - 1)) >= a.DV) {
            d[b + a.t] -= a.DV;
            d[b + a.t + 1] = 1
        }
    }
    if (d.t > 0) { d[d.t - 1] += a.am(b, a[b], d, 2 * b, 0, 1) }
    d.s = 0;
    d.clamp()
}

function bnpDivRemTo(n, h, g) {
    var w = n.abs();
    if (w.t <= 0) {
        return
    }
    var k = this.abs();
    if (k.t < w.t) {
        if (h != null) { h.fromInt(0) }
        if (g != null) { this.copyTo(g) }
        return
    }
    if (g == null) { g = nbi() }
    var d = nbi(),
        a = this.s,
        l = n.s;
    var v = this.DB - nbits(w[w.t - 1]);
    if (v > 0) {
        w.lShiftTo(v, d);
        k.lShiftTo(v, g)
    } else {
        w.copyTo(d);
        k.copyTo(g)
    }
    var p = d.t;
    var b = d[p - 1];
    if (b == 0) {
        return
    }
    var o = b * (1 << this.F1) + ((p > 1) ? d[p - 2] >> this.F2 : 0);
    var A = this.FV / o,
        z = (1 << this.F1) / o,
        x = 1 << this.F2;
    var u = g.t,
        s = u - p,
        f = (h == null) ? nbi() : h;
    d.dlShiftTo(s, f);
    if (g.compareTo(f) >= 0) {
        g[g.t++] = 1;
        g.subTo(f, g)
    }
    BigInteger.ONE.dlShiftTo(p, f);
    f.subTo(d, d);
    while (d.t < p) { d[d.t++] = 0 }
    while (--s >= 0) {
        var c = (g[--u] == b) ? this.DM : Math.floor(g[u] * A + (g[u - 1] + x) * z);
        if ((g[u] += d.am(0, c, g, s, 0, p)) < c) {
            d.dlShiftTo(s, f);
            g.subTo(f, g);
            while (g[u] < --c) { g.subTo(f, g) }
        }
    }
    if (h != null) {
        g.drShiftTo(p, h);
        if (a != l) { BigInteger.ZERO.subTo(h, h) }
    }
    g.t = p;
    g.clamp();
    if (v > 0) { g.rShiftTo(v, g) }
    if (a < 0) { BigInteger.ZERO.subTo(g, g) }
}

function bnMod(b) {
    var c = nbi();
    this.abs().divRemTo(b, null, c);
    if (this.s < 0 && c.compareTo(BigInteger.ZERO) > 0) { b.subTo(c, c) }
    return c
}

function Classic(a) { this.m = a }

function cConvert(a) {
    if (a.s < 0 || a.compareTo(this.m) >= 0) {
        return a.mod(this.m)
    } else {
        return a
    }
}

function cRevert(a) {
    return a
}

function cReduce(a) { a.divRemTo(this.m, null, a) }

function cMulTo(a, c, b) {
    a.multiplyTo(c, b);
    this.reduce(b)
}

function cSqrTo(a, b) {
    a.squareTo(b);
    this.reduce(b)
}
Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

function bnpInvDigit() {
    if (this.t < 1) {
        return 0
    }
    var a = this[0];
    if ((a & 1) == 0) {
        return 0
    }
    var b = a & 3;
    b = (b * (2 - (a & 15) * b)) & 15;
    b = (b * (2 - (a & 255) * b)) & 255;
    b = (b * (2 - (((a & 65535) * b) & 65535))) & 65535;
    b = (b * (2 - a * b % this.DV)) % this.DV;
    return (b > 0) ? this.DV - b : -b
}

function Montgomery(a) {
    this.m = a;
    this.mp = a.invDigit();
    this.mpl = this.mp & 32767;
    this.mph = this.mp >> 15;
    this.um = (1 << (a.DB - 15)) - 1;
    this.mt2 = 2 * a.t
}

function montConvert(a) {
    var b = nbi();
    a.abs().dlShiftTo(this.m.t, b);
    b.divRemTo(this.m, null, b);
    if (a.s < 0 && b.compareTo(BigInteger.ZERO) > 0) { this.m.subTo(b, b) }
    return b
}

function montRevert(a) {
    var b = nbi();
    a.copyTo(b);
    this.reduce(b);
    return b
}

function montReduce(a) {
    while (a.t <= this.mt2) { a[a.t++] = 0 }
    for (var c = 0; c < this.m.t; ++c) {
        var b = a[c] & 32767;
        var d = (b * this.mpl + (((b * this.mph + (a[c] >> 15) * this.mpl) & this.um) << 15)) & a.DM;
        b = c + this.m.t;
        a[b] += this.m.am(0, d, a, c, 0, this.m.t);
        while (a[b] >= a.DV) {
            a[b] -= a.DV;
            a[++b]++
        }
    }
    a.clamp();
    a.drShiftTo(this.m.t, a);
    if (a.compareTo(this.m) >= 0) { a.subTo(this.m, a) }
}

function montSqrTo(a, b) {
    a.squareTo(b);
    this.reduce(b)
}

function montMulTo(a, c, b) {
    a.multiplyTo(c, b);
    this.reduce(b)
}
Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

function bnpIsEven() {
    return ((this.t > 0) ? (this[0] & 1) : this.s) == 0
}

function bnpExp(h, j) {
    if (h > 4294967295 || h < 1) {
        return BigInteger.ONE
    }
    var f = nbi(),
        a = nbi(),
        d = j.convert(this),
        c = nbits(h) - 1;
    d.copyTo(f);
    while (--c >= 0) {
        j.sqrTo(f, a);
        if ((h & (1 << c)) > 0) { j.mulTo(a, d, f) } else {
            var b = f;
            f = a;
            a = b
        }
    }
    return j.revert(f)
}

function bnModPowInt(b, a) {
    var c;
    if (b < 256 || a.isEven()) { c = new Classic(a) } else { c = new Montgomery(a) }
    return this.exp(b, c)
}
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function bnClone() {
    var a = nbi();
    this.copyTo(a);
    return a
}

function bnIntValue() {
    if (this.s < 0) {
        if (this.t == 1) {
            return this[0] - this.DV
        } else {
            if (this.t == 0) {
                return -1
            }
        }
    } else {
        if (this.t == 1) {
            return this[0]
        } else {
            if (this.t == 0) {
                return 0
            }
        }
    }
    return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0]
}

function bnByteValue() {
    return (this.t == 0) ? this.s : (this[0] << 24) >> 24
}

function bnShortValue() {
    return (this.t == 0) ? this.s : (this[0] << 16) >> 16
}

function bnpChunkSize(a) {
    return Math.floor(Math.LN2 * this.DB / Math.log(a))
}

function bnSigNum() {
    if (this.s < 0) {
        return -1
    } else {
        if (this.t <= 0 || (this.t == 1 && this[0] <= 0)) {
            return 0
        } else {
            return 1
        }
    }
}

function bnpToRadix(c) {
    if (c == null) { c = 10 }
    if (this.signum() == 0 || c < 2 || c > 36) {
        return "0"
    }
    var f = this.chunkSize(c);
    var e = Math.pow(c, f);
    var i = nbv(e),
        j = nbi(),
        h = nbi(),
        g = "";
    this.divRemTo(i, j, h);
    while (j.signum() > 0) {
        g = (e + h.intValue()).toString(c).substr(1) + g;
        j.divRemTo(i, j, h)
    }
    return h.intValue().toString(c) + g
}

function bnpFromRadix(m, h) {
    this.fromInt(0);
    if (h == null) { h = 10 }
    var f = this.chunkSize(h);
    var g = Math.pow(h, f),
        e = false,
        a = 0,
        l = 0;
    for (var c = 0; c < m.length; ++c) {
        var k = intAt(m, c);
        if (k < 0) {
            if (m.charAt(c) == "-" && this.signum() == 0) { e = true }
            continue
        }
        l = h * l + k;
        if (++a >= f) {
            this.dMultiply(g);
            this.dAddOffset(l, 0);
            a = 0;
            l = 0
        }
    }
    if (a > 0) {
        this.dMultiply(Math.pow(h, a));
        this.dAddOffset(l, 0)
    }
    if (e) { BigInteger.ZERO.subTo(this, this) }
}

function bnpFromNumber(f, e, h) {
    if ("number" == typeof e) {
        if (f < 2) { this.fromInt(1) } else {
            this.fromNumber(f, h);
            if (!this.testBit(f - 1)) { this.bitwiseTo(BigInteger.ONE.shiftLeft(f - 1), op_or, this) }
            if (this.isEven()) { this.dAddOffset(1, 0) }
            while (!this.isProbablePrime(e)) {
                this.dAddOffset(2, 0);
                if (this.bitLength() > f) { this.subTo(BigInteger.ONE.shiftLeft(f - 1), this) }
            }
        }
    } else {
        var d = new Array(),
            g = f & 7;
        d.length = (f >> 3) + 1;
        e.nextBytes(d);
        if (g > 0) { d[0] &= ((1 << g) - 1) } else { d[0] = 0 }
        this.fromString(d, 256)
    }
}

function bnToByteArray() {
    var b = this.t,
        c = new Array();
    c[0] = this.s;
    var e = this.DB - (b * this.DB) % 8,
        f, a = 0;
    if (b-- > 0) {
        if (e < this.DB && (f = this[b] >> e) != (this.s & this.DM) >> e) { c[a++] = f | (this.s << (this.DB - e)) }
        while (b >= 0) {
            if (e < 8) {
                f = (this[b] & ((1 << e) - 1)) << (8 - e);
                f |= this[--b] >> (e += this.DB - 8)
            } else {
                f = (this[b] >> (e -= 8)) & 255;
                if (e <= 0) { e += this.DB;--b }
            }
            if ((f & 128) != 0) { f |= -256 }
            if (a == 0 && (this.s & 128) != (f & 128)) {++a }
            if (a > 0 || f != this.s) { c[a++] = f }
        }
    }
    return c
}

function bnEquals(b) {
    return (this.compareTo(b) == 0)
}

function bnMin(b) {
    return (this.compareTo(b) < 0) ? this : b
}

function bnMax(b) {
    return (this.compareTo(b) > 0) ? this : b
}

function bnpBitwiseTo(c, h, e) {
    var d, g, b = Math.min(c.t, this.t);
    for (d = 0; d < b; ++d) { e[d] = h(this[d], c[d]) }
    if (c.t < this.t) {
        g = c.s & this.DM;
        for (d = b; d < this.t; ++d) { e[d] = h(this[d], g) }
        e.t = this.t
    } else {
        g = this.s & this.DM;
        for (d = b; d < c.t; ++d) { e[d] = h(g, c[d]) }
        e.t = c.t
    }
    e.s = h(this.s, c.s);
    e.clamp()
}

function op_and(a, b) {
    return a & b
}

function bnAnd(b) {
    var c = nbi();
    this.bitwiseTo(b, op_and, c);
    return c
}

function op_or(a, b) {
    return a | b
}

function bnOr(b) {
    var c = nbi();
    this.bitwiseTo(b, op_or, c);
    return c
}

function op_xor(a, b) {
    return a ^ b
}

function bnXor(b) {
    var c = nbi();
    this.bitwiseTo(b, op_xor, c);
    return c
}

function op_andnot(a, b) {
    return a & ~b
}

function bnAndNot(b) {
    var c = nbi();
    this.bitwiseTo(b, op_andnot, c);
    return c
}

function bnNot() {
    var b = nbi();
    for (var a = 0; a < this.t; ++a) { b[a] = this.DM & ~this[a] }
    b.t = this.t;
    b.s = ~this.s;
    return b
}

function bnShiftLeft(b) {
    var a = nbi();
    if (b < 0) { this.rShiftTo(-b, a) } else { this.lShiftTo(b, a) }
    return a
}

function bnShiftRight(b) {
    var a = nbi();
    if (b < 0) { this.lShiftTo(-b, a) } else { this.rShiftTo(b, a) }
    return a
}

function lbit(a) {
    if (a == 0) {
        return -1
    }
    var b = 0;
    if ((a & 65535) == 0) {
        a >>= 16;
        b += 16
    }
    if ((a & 255) == 0) {
        a >>= 8;
        b += 8
    }
    if ((a & 15) == 0) {
        a >>= 4;
        b += 4
    }
    if ((a & 3) == 0) {
        a >>= 2;
        b += 2
    }
    if ((a & 1) == 0) {++b }
    return b
}

function bnGetLowestSetBit() {
    for (var a = 0; a < this.t; ++a) {
        if (this[a] != 0) {
            return a * this.DB + lbit(this[a])
        }
    }
    if (this.s < 0) {
        return this.t * this.DB
    }
    return -1
}

function cbit(a) {
    var b = 0;
    while (a != 0) { a &= a - 1;++b }
    return b
}

function bnBitCount() {
    var c = 0,
        a = this.s & this.DM;
    for (var b = 0; b < this.t; ++b) { c += cbit(this[b] ^ a) }
    return c
}

function bnTestBit(b) {
    var a = Math.floor(b / this.DB);
    if (a >= this.t) {
        return (this.s != 0)
    }
    return ((this[a] & (1 << (b % this.DB))) != 0)
}

function bnpChangeBit(c, b) {
    var a = BigInteger.ONE.shiftLeft(c);
    this.bitwiseTo(a, b, a);
    return a
}

function bnSetBit(a) {
    return this.changeBit(a, op_or)
}

function bnClearBit(a) {
    return this.changeBit(a, op_andnot)
}

function bnFlipBit(a) {
    return this.changeBit(a, op_xor)
}

function bnpAddTo(d, f) {
    var e = 0,
        g = 0,
        b = Math.min(d.t, this.t);
    while (e < b) {
        g += this[e] + d[e];
        f[e++] = g & this.DM;
        g >>= this.DB
    }
    if (d.t < this.t) {
        g += d.s;
        while (e < this.t) {
            g += this[e];
            f[e++] = g & this.DM;
            g >>= this.DB
        }
        g += this.s
    } else {
        g += this.s;
        while (e < d.t) {
            g += d[e];
            f[e++] = g & this.DM;
            g >>= this.DB
        }
        g += d.s
    }
    f.s = (g < 0) ? -1 : 0;
    if (g > 0) { f[e++] = g } else {
        if (g < -1) { f[e++] = this.DV + g }
    }
    f.t = e;
    f.clamp()
}

function bnAdd(b) {
    var c = nbi();
    this.addTo(b, c);
    return c
}

function bnSubtract(b) {
    var c = nbi();
    this.subTo(b, c);
    return c
}

function bnMultiply(b) {
    var c = nbi();
    this.multiplyTo(b, c);
    return c
}

function bnSquare() {
    var a = nbi();
    this.squareTo(a);
    return a
}

function bnDivide(b) {
    var c = nbi();
    this.divRemTo(b, c, null);
    return c
}

function bnRemainder(b) {
    var c = nbi();
    this.divRemTo(b, null, c);
    return c
}

function bnDivideAndRemainder(b) {
    var d = nbi(),
        c = nbi();
    this.divRemTo(b, d, c);
    return new Array(d, c)
}

function bnpDMultiply(a) {
    this[this.t] = this.am(0, a - 1, this, 0, 0, this.t);
    ++this.t;
    this.clamp()
}

function bnpDAddOffset(b, a) {
    if (b == 0) {
        return
    }
    while (this.t <= a) { this[this.t++] = 0 }
    this[a] += b;
    while (this[a] >= this.DV) {
        this[a] -= this.DV;
        if (++a >= this.t) { this[this.t++] = 0 }++this[a]
    }
}

function NullExp() {}

function nNop(a) {
    return a
}

function nMulTo(a, c, b) { a.multiplyTo(c, b) }

function nSqrTo(a, b) { a.squareTo(b) }
NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

function bnPow(a) {
    return this.exp(a, new NullExp())
}

function bnpMultiplyLowerTo(b, f, e) {
    var d = Math.min(this.t + b.t, f);
    e.s = 0;
    e.t = d;
    while (d > 0) { e[--d] = 0 }
    var c;
    for (c = e.t - this.t; d < c; ++d) { e[d + this.t] = this.am(0, b[d], e, d, 0, this.t) }
    for (c = Math.min(b.t, f); d < c; ++d) { this.am(0, b[d], e, d, 0, f - d) }
    e.clamp()
}

function bnpMultiplyUpperTo(b, e, d) {
    --e;
    var c = d.t = this.t + b.t - e;
    d.s = 0;
    while (--c >= 0) { d[c] = 0 }
    for (c = Math.max(e - this.t, 0); c < b.t; ++c) { d[this.t + c - e] = this.am(e - c, b[c], d, 0, 0, this.t + c - e) }
    d.clamp();
    d.drShiftTo(1, d)
}

function Barrett(a) {
    this.r2 = nbi();
    this.q3 = nbi();
    BigInteger.ONE.dlShiftTo(2 * a.t, this.r2);
    this.mu = this.r2.divide(a);
    this.m = a
}

function barrettConvert(a) {
    if (a.s < 0 || a.t > 2 * this.m.t) {
        return a.mod(this.m)
    } else {
        if (a.compareTo(this.m) < 0) {
            return a
        } else {
            var b = nbi();
            a.copyTo(b);
            this.reduce(b);
            return b
        }
    }
}

function barrettRevert(a) {
    return a
}

function barrettReduce(a) {
    a.drShiftTo(this.m.t - 1, this.r2);
    if (a.t > this.m.t + 1) {
        a.t = this.m.t + 1;
        a.clamp()
    }
    this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
    this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
    while (a.compareTo(this.r2) < 0) { a.dAddOffset(1, this.m.t + 1) }
    a.subTo(this.r2, a);
    while (a.compareTo(this.m) >= 0) { a.subTo(this.m, a) }
}

function barrettSqrTo(a, b) {
    a.squareTo(b);
    this.reduce(b)
}

function barrettMulTo(a, c, b) {
    a.multiplyTo(c, b);
    this.reduce(b)
}
Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

function bnModPow(q, f) {
    var o = q.bitLength(),
        h, b = nbv(1),
        v;
    if (o <= 0) {
        return b
    } else {
        if (o < 18) { h = 1 } else {
            if (o < 48) { h = 3 } else {
                if (o < 144) { h = 4 } else {
                    if (o < 768) { h = 5 } else { h = 6 }
                }
            }
        }
    }
    if (o < 8) { v = new Classic(f) } else {
        if (f.isEven()) { v = new Barrett(f) } else { v = new Montgomery(f) }
    }
    var p = new Array(),
        d = 3,
        s = h - 1,
        a = (1 << h) - 1;
    p[1] = v.convert(this);
    if (h > 1) {
        var A = nbi();
        v.sqrTo(p[1], A);
        while (d <= a) {
            p[d] = nbi();
            v.mulTo(A, p[d - 2], p[d]);
            d += 2
        }
    }
    var l = q.t - 1,
        x, u = true,
        c = nbi(),
        y;
    o = nbits(q[l]) - 1;
    while (l >= 0) {
        if (o >= s) { x = (q[l] >> (o - s)) & a } else {
            x = (q[l] & ((1 << (o + 1)) - 1)) << (s - o);
            if (l > 0) { x |= q[l - 1] >> (this.DB + o - s) }
        }
        d = h;
        while ((x & 1) == 0) { x >>= 1;--d }
        if ((o -= d) < 0) { o += this.DB;--l }
        if (u) {
            p[x].copyTo(b);
            u = false
        } else {
            while (d > 1) {
                v.sqrTo(b, c);
                v.sqrTo(c, b);
                d -= 2
            }
            if (d > 0) { v.sqrTo(b, c) } else {
                y = b;
                b = c;
                c = y
            }
            v.mulTo(c, p[x], b)
        }
        while (l >= 0 && (q[l] & (1 << o)) == 0) {
            v.sqrTo(b, c);
            y = b;
            b = c;
            c = y;
            if (--o < 0) { o = this.DB - 1;--l }
        }
    }
    return v.revert(b)
}

function bnGCD(c) {
    var b = (this.s < 0) ? this.negate() : this.clone();
    var h = (c.s < 0) ? c.negate() : c.clone();
    if (b.compareTo(h) < 0) {
        var e = b;
        b = h;
        h = e
    }
    var d = b.getLowestSetBit(),
        f = h.getLowestSetBit();
    if (f < 0) {
        return b
    }
    if (d < f) { f = d }
    if (f > 0) {
        b.rShiftTo(f, b);
        h.rShiftTo(f, h)
    }
    while (b.signum() > 0) {
        if ((d = b.getLowestSetBit()) > 0) { b.rShiftTo(d, b) }
        if ((d = h.getLowestSetBit()) > 0) { h.rShiftTo(d, h) }
        if (b.compareTo(h) >= 0) {
            b.subTo(h, b);
            b.rShiftTo(1, b)
        } else {
            h.subTo(b, h);
            h.rShiftTo(1, h)
        }
    }
    if (f > 0) { h.lShiftTo(f, h) }
    return h
}

function bnpModInt(e) {
    if (e <= 0) {
        return 0
    }
    var c = this.DV % e,
        b = (this.s < 0) ? e - 1 : 0;
    if (this.t > 0) {
        if (c == 0) { b = this[0] % e } else {
            for (var a = this.t - 1; a >= 0; --a) { b = (c * b + this[a]) % e }
        }
    }
    return b
}

function bnModInverse(f) {
    var j = f.isEven();
    if ((this.isEven() && j) || f.signum() == 0) {
        return BigInteger.ZERO
    }
    var i = f.clone(),
        h = this.clone();
    var g = nbv(1),
        e = nbv(0),
        l = nbv(0),
        k = nbv(1);
    while (i.signum() != 0) {
        while (i.isEven()) {
            i.rShiftTo(1, i);
            if (j) {
                if (!g.isEven() || !e.isEven()) {
                    g.addTo(this, g);
                    e.subTo(f, e)
                }
                g.rShiftTo(1, g)
            } else {
                if (!e.isEven()) { e.subTo(f, e) }
            }
            e.rShiftTo(1, e)
        }
        while (h.isEven()) {
            h.rShiftTo(1, h);
            if (j) {
                if (!l.isEven() || !k.isEven()) {
                    l.addTo(this, l);
                    k.subTo(f, k)
                }
                l.rShiftTo(1, l)
            } else {
                if (!k.isEven()) { k.subTo(f, k) }
            }
            k.rShiftTo(1, k)
        }
        if (i.compareTo(h) >= 0) {
            i.subTo(h, i);
            if (j) { g.subTo(l, g) }
            e.subTo(k, e)
        } else {
            h.subTo(i, h);
            if (j) { l.subTo(g, l) }
            k.subTo(e, k)
        }
    }
    if (h.compareTo(BigInteger.ONE) != 0) {
        return BigInteger.ZERO
    }
    if (k.compareTo(f) >= 0) {
        return k.subtract(f)
    }
    if (k.signum() < 0) { k.addTo(f, k) } else {
        return k
    }
    if (k.signum() < 0) {
        return k.add(f)
    } else {
        return k
    }
}
var lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997];
var lplim = (1 << 26) / lowprimes[lowprimes.length - 1];

function bnIsProbablePrime(e) {
    var d, b = this.abs();
    if (b.t == 1 && b[0] <= lowprimes[lowprimes.length - 1]) {
        for (d = 0; d < lowprimes.length; ++d) {
            if (b[0] == lowprimes[d]) {
                return true
            }
        }
        return false
    }
    if (b.isEven()) {
        return false
    }
    d = 1;
    while (d < lowprimes.length) {
        var a = lowprimes[d],
            c = d + 1;
        while (c < lowprimes.length && a < lplim) { a *= lowprimes[c++] }
        a = b.modInt(a);
        while (d < c) {
            if (a % lowprimes[d++] == 0) {
                return false
            }
        }
    }
    return b.millerRabin(e)
}

function bnpMillerRabin(f) {
    var g = this.subtract(BigInteger.ONE);
    var c = g.getLowestSetBit();
    if (c <= 0) {
        return false
    }
    var h = g.shiftRight(c);
    f = (f + 1) >> 1;
    if (f > lowprimes.length) { f = lowprimes.length }
    var b = nbi();
    for (var e = 0; e < f; ++e) {
        b.fromInt(lowprimes[Math.floor(Math.random() * lowprimes.length)]);
        var l = b.modPow(h, this);
        if (l.compareTo(BigInteger.ONE) != 0 && l.compareTo(g) != 0) {
            var d = 1;
            while (d++ < c && l.compareTo(g) != 0) {
                l = l.modPowInt(2, this);
                if (l.compareTo(BigInteger.ONE) == 0) {
                    return false
                }
            }
            if (l.compareTo(g) != 0) {
                return false
            }
        }
    }
    return true
}
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;
BigInteger.prototype.square = bnSquare;
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function Arcfour() {
    this.i = 0;
    this.j = 0;
    this.S = new Array()
}

function ARC4init(d) {
    var c, a, b;
    for (c = 0; c < 256; ++c) { this.S[c] = c }
    a = 0;
    for (c = 0; c < 256; ++c) {
        a = (a + this.S[c] + d[c % d.length]) & 255;
        b = this.S[c];
        this.S[c] = this.S[a];
        this.S[a] = b
    }
    this.i = 0;
    this.j = 0
}

function ARC4next() {
    var a;
    this.i = (this.i + 1) & 255;
    this.j = (this.j + this.S[this.i]) & 255;
    a = this.S[this.i];
    this.S[this.i] = this.S[this.j];
    this.S[this.j] = a;
    return this.S[(a + this.S[this.i]) & 255]
}
Arcfour.prototype.init = ARC4init;
Arcfour.prototype.next = ARC4next;

function prng_newstate() {
    return new Arcfour()
}
var rng_psize = 256;
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
var rng_state;
var rng_pool;
var rng_pptr;

function rng_seed_int(a) {
    rng_pool[rng_pptr++] ^= a & 255;
    rng_pool[rng_pptr++] ^= (a >> 8) & 255;
    rng_pool[rng_pptr++] ^= (a >> 16) & 255;
    rng_pool[rng_pptr++] ^= (a >> 24) & 255;
    if (rng_pptr >= rng_psize) { rng_pptr -= rng_psize }
}

function rng_seed_time() { rng_seed_int(new Date().getTime()) }
if (rng_pool == null) {
    rng_pool = new Array();
    rng_pptr = 0;
    var t;
    if (window.crypto && window.crypto.getRandomValues) {
        var ua = new Uint8Array(32);
        window.crypto.getRandomValues(ua);
        for (t = 0; t < 32; ++t) { rng_pool[rng_pptr++] = ua[t] }
    }
    if (navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
        var z = window.crypto.random(32);
        for (t = 0; t < z.length; ++t) { rng_pool[rng_pptr++] = z.charCodeAt(t) & 255 }
    }
    while (rng_pptr < rng_psize) {
        t = Math.floor(65536 * Math.random());
        rng_pool[rng_pptr++] = t >>> 8;
        rng_pool[rng_pptr++] = t & 255
    }
    rng_pptr = 0;
    rng_seed_time()
}

function rng_get_byte() {
    if (rng_state == null) {
        rng_seed_time();
        rng_state = prng_newstate();
        rng_state.init(rng_pool);
        for (rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr) { rng_pool[rng_pptr] = 0 }
        rng_pptr = 0
    }
    return rng_state.next()
}

function rng_get_bytes(b) {
    var a;
    for (a = 0; a < b.length; ++a) { b[a] = rng_get_byte() }
}

function SecureRandom() {}
SecureRandom.prototype.nextBytes = rng_get_bytes;
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function parseBigInt(b, a) {
    return new BigInteger(b, a)
}

function linebrk(c, d) {
    var a = "";
    var b = 0;
    while (b + d < c.length) {
        a += c.substring(b, b + d) + "\n";
        b += d
    }
    return a + c.substring(b, c.length)
}

function byte2Hex(a) {
    if (a < 16) {
        return "0" + a.toString(16)
    } else {
        return a.toString(16)
    }
}

function pkcs1pad2(e, h) {
    if (h < e.length + 11) {
        alert("Message too long for RSA");
        return null
    }
    var g = new Array();
    var d = e.length - 1;
    while (d >= 0 && h > 0) {
        var f = e.charCodeAt(d--);
        if (f < 128) { g[--h] = f } else {
            if ((f > 127) && (f < 2048)) {
                g[--h] = (f & 63) | 128;
                g[--h] = (f >> 6) | 192
            } else {
                g[--h] = (f & 63) | 128;
                g[--h] = ((f >> 6) & 63) | 128;
                g[--h] = (f >> 12) | 224
            }
        }
    }
    g[--h] = 0;
    var b = new SecureRandom();
    var a = new Array();
    while (h > 2) {
        a[0] = 0;
        while (a[0] == 0) { b.nextBytes(a) }
        g[--h] = a[0]
    }
    g[--h] = 2;
    g[--h] = 0;
    return new BigInteger(g)
}

function oaep_mgf1_arr(c, a, e) {
    var b = "",
        d = 0;
    while (b.length < a) {
        b += e(String.fromCharCode.apply(String, c.concat([(d & 4278190080) >> 24, (d & 16711680) >> 16, (d & 65280) >> 8, d & 255])));
        d += 1
    }
    return b
}
var SHA1_SIZE = 20;

function oaep_pad(l, a, c) {
    if (l.length + 2 * SHA1_SIZE + 2 > a) {
        throw "Message too long for RSA"
    }
    var h = "",
        d;
    for (d = 0; d < a - l.length - 2 * SHA1_SIZE - 2; d += 1) { h += "\x00" }
    var e = rstr_sha1("") + h + "\x01" + l;
    var f = new Array(SHA1_SIZE);
    new SecureRandom().nextBytes(f);
    var g = oaep_mgf1_arr(f, e.length, c || rstr_sha1);
    var k = [];
    for (d = 0; d < e.length; d += 1) { k[d] = e.charCodeAt(d) ^ g.charCodeAt(d) }
    var j = oaep_mgf1_arr(k, f.length, rstr_sha1);
    var b = [0];
    for (d = 0; d < f.length; d += 1) { b[d + 1] = f[d] ^ j.charCodeAt(d) }
    return new BigInteger(b.concat(k))
}

function RSAKey() {
    this.n = null;
    this.e = 0;
    this.d = null;
    this.p = null;
    this.q = null;
    this.dmp1 = null;
    this.dmq1 = null;
    this.coeff = null
}

function RSASetPublic(b, a) {
    this.isPublic = true;
    if (typeof b !== "string") {
        this.n = b;
        this.e = a
    } else {
        if (b != null && a != null && b.length > 0 && a.length > 0) {
            this.n = parseBigInt(b, 16);
            this.e = parseInt(a, 16)
        } else { alert("Invalid RSA public key") }
    }
}

function RSADoPublic(a) {
    return a.modPowInt(this.e, this.n)
}

function RSAEncrypt(d) {
    var a = pkcs1pad2(d, (this.n.bitLength() + 7) >> 3);
    if (a == null) {
        return null
    }
    var e = this.doPublic(a);
    if (e == null) {
        return null
    }
    var b = e.toString(16);
    if ((b.length & 1) == 0) {
        return b
    } else {
        return "0" + b
    }
}

function RSAEncryptOAEP(e, d) {
    var a = oaep_pad(e, (this.n.bitLength() + 7) >> 3, d);
    if (a == null) {
        return null
    }
    var f = this.doPublic(a);
    if (f == null) {
        return null
    }
    var b = f.toString(16);
    if ((b.length & 1) == 0) {
        return b
    } else {
        return "0" + b
    }
}
RSAKey.prototype.doPublic = RSADoPublic;
RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;
RSAKey.prototype.encryptOAEP = RSAEncryptOAEP;
RSAKey.prototype.type = "RSA";
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function pkcs1unpad2(g, j) {
    var a = g.toByteArray();
    var f = 0;
    while (f < a.length && a[f] == 0) {++f }
    if (a.length - f != j - 1 || a[f] != 2) {
        return null
    }++f;
    while (a[f] != 0) {
        if (++f >= a.length) {
            return null
        }
    }
    var e = "";
    while (++f < a.length) {
        var h = a[f] & 255;
        if (h < 128) { e += String.fromCharCode(h) } else {
            if ((h > 191) && (h < 224)) { e += String.fromCharCode(((h & 31) << 6) | (a[f + 1] & 63));++f } else {
                e += String.fromCharCode(((h & 15) << 12) | ((a[f + 1] & 63) << 6) | (a[f + 2] & 63));
                f += 2
            }
        }
    }
    return e
}

function oaep_mgf1_str(c, a, e) {
    var b = "",
        d = 0;
    while (b.length < a) {
        b += e(c + String.fromCharCode.apply(String, [(d & 4278190080) >> 24, (d & 16711680) >> 16, (d & 65280) >> 8, d & 255]));
        d += 1
    }
    return b
}
var SHA1_SIZE = 20;

function oaep_unpad(l, b, e) {
    l = l.toByteArray();
    var f;
    for (f = 0; f < l.length; f += 1) { l[f] &= 255 }
    while (l.length < b) { l.unshift(0) }
    l = String.fromCharCode.apply(String, l);
    if (l.length < 2 * SHA1_SIZE + 2) {
        throw "Cipher too short"
    }
    var c = l.substr(1, SHA1_SIZE);
    var o = l.substr(SHA1_SIZE + 1);
    var m = oaep_mgf1_str(o, SHA1_SIZE, e || rstr_sha1);
    var h = [],
        f;
    for (f = 0; f < c.length; f += 1) { h[f] = c.charCodeAt(f) ^ m.charCodeAt(f) }
    var j = oaep_mgf1_str(String.fromCharCode.apply(String, h), l.length - SHA1_SIZE, rstr_sha1);
    var g = [];
    for (f = 0; f < o.length; f += 1) { g[f] = o.charCodeAt(f) ^ j.charCodeAt(f) }
    g = String.fromCharCode.apply(String, g);
    if (g.substr(0, SHA1_SIZE) !== rstr_sha1("")) {
        throw "Hash mismatch"
    }
    g = g.substr(SHA1_SIZE);
    var a = g.indexOf("\x01");
    var k = (a != -1) ? g.substr(0, a).lastIndexOf("\x00") : -1;
    if (k + 1 != a) {
        throw "Malformed data"
    }
    return g.substr(a + 1)
}

function RSASetPrivate(c, a, b) {
    this.isPrivate = true;
    if (typeof c !== "string") {
        this.n = c;
        this.e = a;
        this.d = b
    } else {
        if (c != null && a != null && c.length > 0 && a.length > 0) {
            this.n = parseBigInt(c, 16);
            this.e = parseInt(a, 16);
            this.d = parseBigInt(b, 16)
        } else { alert("Invalid RSA private key") }
    }
}

function RSASetPrivateEx(g, d, e, c, b, a, h, f) {
    this.isPrivate = true;
    if (g == null) {
        throw "RSASetPrivateEx N == null"
    }
    if (d == null) {
        throw "RSASetPrivateEx E == null"
    }
    if (g.length == 0) {
        throw "RSASetPrivateEx N.length == 0"
    }
    if (d.length == 0) {
        throw "RSASetPrivateEx E.length == 0"
    }
    if (g != null && d != null && g.length > 0 && d.length > 0) {
        this.n = parseBigInt(g, 16);
        this.e = parseInt(d, 16);
        this.d = parseBigInt(e, 16);
        this.p = parseBigInt(c, 16);
        this.q = parseBigInt(b, 16);
        this.dmp1 = parseBigInt(a, 16);
        this.dmq1 = parseBigInt(h, 16);
        this.coeff = parseBigInt(f, 16)
    } else { alert("Invalid RSA private key in RSASetPrivateEx") }
}

function RSAGenerate(b, i) {
    var a = new SecureRandom();
    var f = b >> 1;
    this.e = parseInt(i, 16);
    var c = new BigInteger(i, 16);
    for (;;) {
        for (;;) {
            this.p = new BigInteger(b - f, 1, a);
            if (this.p.subtract(BigInteger.ONE).gcd(c).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) {
                break
            }
        }
        for (;;) {
            this.q = new BigInteger(f, 1, a);
            if (this.q.subtract(BigInteger.ONE).gcd(c).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) {
                break
            }
        }
        if (this.p.compareTo(this.q) <= 0) {
            var h = this.p;
            this.p = this.q;
            this.q = h
        }
        var g = this.p.subtract(BigInteger.ONE);
        var d = this.q.subtract(BigInteger.ONE);
        var e = g.multiply(d);
        if (e.gcd(c).compareTo(BigInteger.ONE) == 0) {
            this.n = this.p.multiply(this.q);
            this.d = c.modInverse(e);
            this.dmp1 = this.d.mod(g);
            this.dmq1 = this.d.mod(d);
            this.coeff = this.q.modInverse(this.p);
            break
        }
    }
}

function RSADoPrivate(a) {
    if (this.p == null || this.q == null) {
        return a.modPow(this.d, this.n)
    }
    var c = a.mod(this.p).modPow(this.dmp1, this.p);
    var b = a.mod(this.q).modPow(this.dmq1, this.q);
    while (c.compareTo(b) < 0) { c = c.add(this.p) }
    return c.subtract(b).multiply(this.coeff).mod(this.p).multiply(this.q).add(b)
}

function RSADecrypt(b) {
    var d = parseBigInt(b, 16);
    var a = this.doPrivate(d);
    if (a == null) {
        return null
    }
    return pkcs1unpad2(a, (this.n.bitLength() + 7) >> 3)
}

function RSADecryptOAEP(d, b) {
    var e = parseBigInt(d, 16);
    var a = this.doPrivate(e);
    if (a == null) {
        return null
    }
    return oaep_unpad(a, (this.n.bitLength() + 7) >> 3, b)
}
RSAKey.prototype.doPrivate = RSADoPrivate;
RSAKey.prototype.setPrivate = RSASetPrivate;
RSAKey.prototype.setPrivateEx = RSASetPrivateEx;
RSAKey.prototype.generate = RSAGenerate;
RSAKey.prototype.decrypt = RSADecrypt;
RSAKey.prototype.decryptOAEP = RSADecryptOAEP;
/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
 */
function ECFieldElementFp(b, a) {
    this.x = a;
    this.q = b
}

function feFpEquals(a) {
    if (a == this) {
        return true
    }
    return (this.q.equals(a.q) && this.x.equals(a.x))
}

function feFpToBigInteger() {
    return this.x
}

function feFpNegate() {
    return new ECFieldElementFp(this.q, this.x.negate().mod(this.q))
}

function feFpAdd(a) {
    return new ECFieldElementFp(this.q, this.x.add(a.toBigInteger()).mod(this.q))
}

function feFpSubtract(a) {
    return new ECFieldElementFp(this.q, this.x.subtract(a.toBigInteger()).mod(this.q))
}

function feFpMultiply(a) {
    return new ECFieldElementFp(this.q, this.x.multiply(a.toBigInteger()).mod(this.q))
}

function feFpSquare() {
    return new ECFieldElementFp(this.q, this.x.square().mod(this.q))
}

function feFpDivide(a) {
    return new ECFieldElementFp(this.q, this.x.multiply(a.toBigInteger().modInverse(this.q)).mod(this.q))
}
ECFieldElementFp.prototype.equals = feFpEquals;
ECFieldElementFp.prototype.toBigInteger = feFpToBigInteger;
ECFieldElementFp.prototype.negate = feFpNegate;
ECFieldElementFp.prototype.add = feFpAdd;
ECFieldElementFp.prototype.subtract = feFpSubtract;
ECFieldElementFp.prototype.multiply = feFpMultiply;
ECFieldElementFp.prototype.square = feFpSquare;
ECFieldElementFp.prototype.divide = feFpDivide;

function ECPointFp(c, a, d, b) {
    this.curve = c;
    this.x = a;
    this.y = d;
    if (b == null) { this.z = BigInteger.ONE } else { this.z = b }
    this.zinv = null
}

function pointFpGetX() {
    if (this.zinv == null) { this.zinv = this.z.modInverse(this.curve.q) }
    return this.curve.fromBigInteger(this.x.toBigInteger().multiply(this.zinv).mod(this.curve.q))
}

function pointFpGetY() {
    if (this.zinv == null) { this.zinv = this.z.modInverse(this.curve.q) }
    return this.curve.fromBigInteger(this.y.toBigInteger().multiply(this.zinv).mod(this.curve.q))
}

function pointFpEquals(a) {
    if (a == this) {
        return true
    }
    if (this.isInfinity()) {
        return a.isInfinity()
    }
    if (a.isInfinity()) {
        return this.isInfinity()
    }
    var c, b;
    c = a.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(a.z)).mod(this.curve.q);
    if (!c.equals(BigInteger.ZERO)) {
        return false
    }
    b = a.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(a.z)).mod(this.curve.q);
    return b.equals(BigInteger.ZERO)
}

function pointFpIsInfinity() {
    if ((this.x == null) && (this.y == null)) {
        return true
    }
    return this.z.equals(BigInteger.ZERO) && !this.y.toBigInteger().equals(BigInteger.ZERO)
}

function pointFpNegate() {
    return new ECPointFp(this.curve, this.x, this.y.negate(), this.z)
}

function pointFpAdd(l) {
    if (this.isInfinity()) {
        return l
    }
    if (l.isInfinity()) {
        return this
    }
    var p = l.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(l.z)).mod(this.curve.q);
    var o = l.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(l.z)).mod(this.curve.q);
    if (BigInteger.ZERO.equals(o)) {
        if (BigInteger.ZERO.equals(p)) {
            return this.twice()
        }
        return this.curve.getInfinity()
    }
    var j = new BigInteger("3");
    var e = this.x.toBigInteger();
    var n = this.y.toBigInteger();
    var c = l.x.toBigInteger();
    var k = l.y.toBigInteger();
    var m = o.square();
    var i = m.multiply(o);
    var d = e.multiply(m);
    var g = p.square().multiply(this.z);
    var a = g.subtract(d.shiftLeft(1)).multiply(l.z).subtract(i).multiply(o).mod(this.curve.q);
    var h = d.multiply(j).multiply(p).subtract(n.multiply(i)).subtract(g.multiply(p)).multiply(l.z).add(p.multiply(i)).mod(this.curve.q);
    var f = i.multiply(this.z).multiply(l.z).mod(this.curve.q);
    return new ECPointFp(this.curve, this.curve.fromBigInteger(a), this.curve.fromBigInteger(h), f)
}

function pointFpTwice() {
    if (this.isInfinity()) {
        return this
    }
    if (this.y.toBigInteger().signum() == 0) {
        return this.curve.getInfinity()
    }
    var g = new BigInteger("3");
    var c = this.x.toBigInteger();
    var h = this.y.toBigInteger();
    var e = h.multiply(this.z);
    var j = e.multiply(h).mod(this.curve.q);
    var i = this.curve.a.toBigInteger();
    var k = c.square().multiply(g);
    if (!BigInteger.ZERO.equals(i)) { k = k.add(this.z.square().multiply(i)) }
    k = k.mod(this.curve.q);
    var b = k.square().subtract(c.shiftLeft(3).multiply(j)).shiftLeft(1).multiply(e).mod(this.curve.q);
    var f = k.multiply(g).multiply(c).subtract(j.shiftLeft(1)).shiftLeft(2).multiply(j).subtract(k.square().multiply(k)).mod(this.curve.q);
    var d = e.square().multiply(e).shiftLeft(3).mod(this.curve.q);
    return new ECPointFp(this.curve, this.curve.fromBigInteger(b), this.curve.fromBigInteger(f), d)
}

function pointFpMultiply(b) {
    if (this.isInfinity()) {
        return this
    }
    if (b.signum() == 0) {
        return this.curve.getInfinity()
    }
    var g = b;
    var f = g.multiply(new BigInteger("3"));
    var l = this.negate();
    var d = this;
    var c;
    for (c = f.bitLength() - 2; c > 0; --c) {
        d = d.twice();
        var a = f.testBit(c);
        var j = g.testBit(c);
        if (a != j) { d = d.add(a ? this : l) }
    }
    return d
}

function pointFpMultiplyTwo(c, a, b) {
    var d;
    if (c.bitLength() > b.bitLength()) { d = c.bitLength() - 1 } else { d = b.bitLength() - 1 }
    var f = this.curve.getInfinity();
    var e = this.add(a);
    while (d >= 0) {
        f = f.twice();
        if (c.testBit(d)) {
            if (b.testBit(d)) { f = f.add(e) } else { f = f.add(this) }
        } else {
            if (b.testBit(d)) { f = f.add(a) }
        }--d
    }
    return f
}
ECPointFp.prototype.getX = pointFpGetX;
ECPointFp.prototype.getY = pointFpGetY;
ECPointFp.prototype.equals = pointFpEquals;
ECPointFp.prototype.isInfinity = pointFpIsInfinity;
ECPointFp.prototype.negate = pointFpNegate;
ECPointFp.prototype.add = pointFpAdd;
ECPointFp.prototype.twice = pointFpTwice;
ECPointFp.prototype.multiply = pointFpMultiply;
ECPointFp.prototype.multiplyTwo = pointFpMultiplyTwo;

function ECCurveFp(e, d, c) {
    this.q = e;
    this.a = this.fromBigInteger(d);
    this.b = this.fromBigInteger(c);
    this.infinity = new ECPointFp(this, null, null)
}

function curveFpGetQ() {
    return this.q
}

function curveFpGetA() {
    return this.a
}

function curveFpGetB() {
    return this.b
}

function curveFpEquals(a) {
    if (a == this) {
        return true
    }
    return (this.q.equals(a.q) && this.a.equals(a.a) && this.b.equals(a.b))
}

function curveFpGetInfinity() {
    return this.infinity
}

function curveFpFromBigInteger(a) {
    return new ECFieldElementFp(this.q, a)
}

function curveFpDecodePointHex(d) {
    switch (parseInt(d.substr(0, 2), 16)) {
        case 0:
            return this.infinity;
        case 2:
        case 3:
            return null;
        case 4:
        case 6:
        case 7:
            var a = (d.length - 2) / 2;
            var c = d.substr(2, a);
            var b = d.substr(a + 2, a);
            return new ECPointFp(this, this.fromBigInteger(new BigInteger(c, 16)), this.fromBigInteger(new BigInteger(b, 16)));
        default:
            return null
    }
}
ECCurveFp.prototype.getQ = curveFpGetQ;
ECCurveFp.prototype.getA = curveFpGetA;
ECCurveFp.prototype.getB = curveFpGetB;
ECCurveFp.prototype.equals = curveFpEquals;
ECCurveFp.prototype.getInfinity = curveFpGetInfinity;
ECCurveFp.prototype.fromBigInteger = curveFpFromBigInteger;
ECCurveFp.prototype.decodePointHex = curveFpDecodePointHex;
/*! (c) Stefan Thomas | https://github.com/bitcoinjs/bitcoinjs-lib
 */
ECFieldElementFp.prototype.getByteLength = function() {
    return Math.floor((this.toBigInteger().bitLength() + 7) / 8)
};
ECPointFp.prototype.getEncoded = function(c) {
    var d = function(h, f) {
        var g = h.toByteArrayUnsigned();
        if (f < g.length) { g = g.slice(g.length - f) } else {
            while (f > g.length) { g.unshift(0) }
        }
        return g
    };
    var a = this.getX().toBigInteger();
    var e = this.getY().toBigInteger();
    var b = d(a, 32);
    if (c) {
        if (e.isEven()) { b.unshift(2) } else { b.unshift(3) }
    } else {
        b.unshift(4);
        b = b.concat(d(e, 32))
    }
    return b
};
ECPointFp.decodeFrom = function(g, c) {
    var f = c[0];
    var e = c.length - 1;
    var d = c.slice(1, 1 + e / 2);
    var b = c.slice(1 + e / 2, 1 + e);
    d.unshift(0);
    b.unshift(0);
    var a = new BigInteger(d);
    var h = new BigInteger(b);
    return new ECPointFp(g, g.fromBigInteger(a), g.fromBigInteger(h))
};
ECPointFp.decodeFromHex = function(g, c) {
    var f = c.substr(0, 2);
    var e = c.length - 2;
    var d = c.substr(2, e / 2);
    var b = c.substr(2 + e / 2, e / 2);
    var a = new BigInteger(d, 16);
    var h = new BigInteger(b, 16);
    return new ECPointFp(g, g.fromBigInteger(a), g.fromBigInteger(h))
};
ECPointFp.prototype.add2D = function(c) {
    if (this.isInfinity()) {
        return c
    }
    if (c.isInfinity()) {
        return this
    }
    if (this.x.equals(c.x)) {
        if (this.y.equals(c.y)) {
            return this.twice()
        }
        return this.curve.getInfinity()
    }
    var g = c.x.subtract(this.x);
    var e = c.y.subtract(this.y);
    var a = e.divide(g);
    var d = a.square().subtract(this.x).subtract(c.x);
    var f = a.multiply(this.x.subtract(d)).subtract(this.y);
    return new ECPointFp(this.curve, d, f)
};
ECPointFp.prototype.twice2D = function() {
    if (this.isInfinity()) {
        return this
    }
    if (this.y.toBigInteger().signum() == 0) {
        return this.curve.getInfinity()
    }
    var b = this.curve.fromBigInteger(BigInteger.valueOf(2));
    var e = this.curve.fromBigInteger(BigInteger.valueOf(3));
    var a = this.x.square().multiply(e).add(this.curve.a).divide(this.y.multiply(b));
    var c = a.square().subtract(this.x.multiply(b));
    var d = a.multiply(this.x.subtract(c)).subtract(this.y);
    return new ECPointFp(this.curve, c, d)
};
ECPointFp.prototype.multiply2D = function(b) {
    if (this.isInfinity()) {
        return this
    }
    if (b.signum() == 0) {
        return this.curve.getInfinity()
    }
    var g = b;
    var f = g.multiply(new BigInteger("3"));
    var l = this.negate();
    var d = this;
    var c;
    for (c = f.bitLength() - 2; c > 0; --c) {
        d = d.twice();
        var a = f.testBit(c);
        var j = g.testBit(c);
        if (a != j) { d = d.add2D(a ? this : l) }
    }
    return d
};
ECPointFp.prototype.isOnCurve = function() {
    var d = this.getX().toBigInteger();
    var i = this.getY().toBigInteger();
    var f = this.curve.getA().toBigInteger();
    var c = this.curve.getB().toBigInteger();
    var h = this.curve.getQ();
    var e = i.multiply(i).mod(h);
    var g = d.multiply(d).multiply(d).add(f.multiply(d)).add(c).mod(h);
    return e.equals(g)
};
ECPointFp.prototype.toString = function() {
    return "(" + this.getX().toBigInteger().toString() + "," + this.getY().toBigInteger().toString() + ")"
};
ECPointFp.prototype.validate = function() {
    var c = this.curve.getQ();
    if (this.isInfinity()) {
        throw new Error("Point is at infinity.")
    }
    var a = this.getX().toBigInteger();
    var b = this.getY().toBigInteger();
    if (a.compareTo(BigInteger.ONE) < 0 || a.compareTo(c.subtract(BigInteger.ONE)) > 0) {
        throw new Error("x coordinate out of bounds")
    }
    if (b.compareTo(BigInteger.ONE) < 0 || b.compareTo(c.subtract(BigInteger.ONE)) > 0) {
        throw new Error("y coordinate out of bounds")
    }
    if (!this.isOnCurve()) {
        throw new Error("Point is not on the curve.")
    }
    if (this.multiply(c).isInfinity()) {
        throw new Error("Point is not a scalar multiple of G.")
    }
    return true
};
/*! Mike Samuel (c) 2009 | code.google.com/p/json-sans-eval
 */
var jsonParse = (function() {
    var e = "(?:-?\\b(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\\b)";
    var j = '(?:[^\\0-\\x08\\x0a-\\x1f"\\\\]|\\\\(?:["/\\\\bfnrt]|u[0-9A-Fa-f]{4}))';
    var i = '(?:"' + j + '*")';
    var d = new RegExp("(?:false|true|null|[\\{\\}\\[\\]]|" + e + "|" + i + ")", "g");
    var k = new RegExp("\\\\(?:([^u])|u(.{4}))", "g");
    var g = { '"': '"', "/": "/", "\\": "\\", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

    function h(l, m, n) {
        return m ? g[m] : String.fromCharCode(parseInt(n, 16))
    }
    var c = new String("");
    var a = "\\";
    var f = { "{": Object, "[": Array };
    var b = Object.hasOwnProperty;
    return function(u, q) {
        var p = u.match(d);
        var x;
        var v = p[0];
        var l = false;
        if ("{" === v) { x = {} } else {
            if ("[" === v) { x = [] } else {
                x = [];
                l = true
            }
        }
        var t;
        var r = [x];
        for (var o = 1 - l, m = p.length; o < m; ++o) {
            v = p[o];
            var w;
            switch (v.charCodeAt(0)) {
                default: w = r[0];w[t || w.length] = +(v);t = void 0;
                break;
                case 34:
                        v = v.substring(1, v.length - 1);
                    if (v.indexOf(a) !== -1) { v = v.replace(k, h) }
                    w = r[0];
                    if (!t) {
                        if (w instanceof Array) { t = w.length } else {
                            t = v || c;
                            break
                        }
                    }
                    w[t] = v;t = void 0;
                    break;
                case 91:
                        w = r[0];r.unshift(w[t || w.length] = []);t = void 0;
                    break;
                case 93:
                        r.shift();
                    break;
                case 102:
                        w = r[0];w[t || w.length] = false;t = void 0;
                    break;
                case 110:
                        w = r[0];w[t || w.length] = null;t = void 0;
                    break;
                case 116:
                        w = r[0];w[t || w.length] = true;t = void 0;
                    break;
                case 123:
                        w = r[0];r.unshift(w[t || w.length] = {});t = void 0;
                    break;
                case 125:
                        r.shift();
                    break
            }
        }
        if (l) {
            if (r.length !== 1) {
                throw new Error()
            }
            x = x[0]
        } else {
            if (r.length) {
                throw new Error()
            }
        }
        if (q) {
            var s = function(C, B) {
                var D = C[B];
                if (D && typeof D === "object") {
                    var n = null;
                    for (var z in D) {
                        if (b.call(D, z) && D !== C) {
                            var y = s(D, z);
                            if (y !== void 0) { D[z] = y } else {
                                if (!n) { n = [] }
                                n.push(z)
                            }
                        }
                    }
                    if (n) {
                        for (var A = n.length; --A >= 0;) { delete D[n[A]] }
                    }
                }
                return q.call(C, B, D)
            };
            x = s({ "": x }, "")
        }
        return x
    }
})();
/*! asn1-1.0.9.js (c) 2013-2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
if (typeof KJUR == "undefined" || !KJUR) { KJUR = {} }
if (typeof KJUR.asn1 == "undefined" || !KJUR.asn1) { KJUR.asn1 = {} }
KJUR.asn1.ASN1Util = new function() {
    this.integerToByteHex = function(a) {
        var b = a.toString(16);
        if ((b.length % 2) == 1) { b = "0" + b }
        return b
    };
    this.bigIntToMinTwosComplementsHex = function(j) {
        var f = j.toString(16);
        if (f.substr(0, 1) != "-") {
            if (f.length % 2 == 1) { f = "0" + f } else {
                if (!f.match(/^[0-7]/)) { f = "00" + f }
            }
        } else {
            var a = f.substr(1);
            var e = a.length;
            if (e % 2 == 1) { e += 1 } else {
                if (!f.match(/^[0-7]/)) { e += 2 }
            }
            var g = "";
            for (var d = 0; d < e; d++) { g += "f" }
            var c = new BigInteger(g, 16);
            var b = c.xor(j).add(BigInteger.ONE);
            f = b.toString(16).replace(/^-/, "")
        }
        return f
    };
    this.getPEMStringFromHex = function(a, b) {
        var c = KJUR.asn1;
        var f = CryptoJS.enc.Hex.parse(a);
        var d = CryptoJS.enc.Base64.stringify(f);
        var e = d.replace(/(.{64})/g, "$1\r\n");
        e = e.replace(/\r\n$/, "");
        return "-----BEGIN " + b + "-----\r\n" + e + "\r\n-----END " + b + "-----\r\n"
    };
    this.newObject = function(b) {
        var g = KJUR.asn1;
        var k = Object.keys(b);
        if (k.length != 1) {
            throw "key of param shall be only one."
        }
        var j = k[0];
        if (":bool:int:bitstr:octstr:null:oid:enum:utf8str:numstr:prnstr:telstr:ia5str:utctime:gentime:seq:set:tag:".indexOf(":" + j + ":") == -1) {
            throw "undefined key: " + j
        }
        if (j == "bool") {
            return new g.DERBoolean(b[j])
        }
        if (j == "int") {
            return new g.DERInteger(b[j])
        }
        if (j == "bitstr") {
            return new g.DERBitString(b[j])
        }
        if (j == "octstr") {
            return new g.DEROctetString(b[j])
        }
        if (j == "null") {
            return new g.DERNull(b[j])
        }
        if (j == "oid") {
            return new g.DERObjectIdentifier(b[j])
        }
        if (j == "enum") {
            return new g.DEREnumerated(b[j])
        }
        if (j == "utf8str") {
            return new g.DERUTF8String(b[j])
        }
        if (j == "numstr") {
            return new g.DERNumericString(b[j])
        }
        if (j == "prnstr") {
            return new g.DERPrintableString(b[j])
        }
        if (j == "telstr") {
            return new g.DERTeletexString(b[j])
        }
        if (j == "ia5str") {
            return new g.DERIA5String(b[j])
        }
        if (j == "utctime") {
            return new g.DERUTCTime(b[j])
        }
        if (j == "gentime") {
            return new g.DERGeneralizedTime(b[j])
        }
        if (j == "seq") {
            var m = b[j];
            var h = [];
            for (var e = 0; e < m.length; e++) {
                var l = g.ASN1Util.newObject(m[e]);
                h.push(l)
            }
            return new g.DERSequence({ array: h })
        }
        if (j == "set") {
            var m = b[j];
            var h = [];
            for (var e = 0; e < m.length; e++) {
                var l = g.ASN1Util.newObject(m[e]);
                h.push(l)
            }
            return new g.DERSet({ array: h })
        }
        if (j == "tag") {
            var c = b[j];
            if (Object.prototype.toString.call(c) === "[object Array]" && c.length == 3) {
                var d = g.ASN1Util.newObject(c[2]);
                return new g.DERTaggedObject({ tag: c[0], explicit: c[1], obj: d })
            } else {
                var f = {};
                if (c.explicit !== undefined) { f.explicit = c.explicit }
                if (c.tag !== undefined) { f.tag = c.tag }
                if (c.obj === undefined) {
                    throw "obj shall be specified for 'tag'."
                }
                f.obj = g.ASN1Util.newObject(c.obj);
                return new g.DERTaggedObject(f)
            }
        }
    };
    this.jsonToASN1HEX = function(b) {
        var a = this.newObject(b);
        return a.getEncodedHex()
    }
};
KJUR.asn1.ASN1Util.oidHexToInt = function(a) {
    var j = "";
    var k = parseInt(a.substr(0, 2), 16);
    var d = Math.floor(k / 40);
    var c = k % 40;
    var j = d + "." + c;
    var e = "";
    for (var f = 2; f < a.length; f += 2) {
        var g = parseInt(a.substr(f, 2), 16);
        var h = ("00000000" + g.toString(2)).slice(-8);
        e = e + h.substr(1, 7);
        if (h.substr(0, 1) == "0") {
            var b = new BigInteger(e, 2);
            j = j + "." + b.toString(10);
            e = ""
        }
    }
    return j
};
KJUR.asn1.ASN1Util.oidIntToHex = function(f) {
    var e = function(a) {
        var k = a.toString(16);
        if (k.length == 1) { k = "0" + k }
        return k
    };
    var d = function(o) {
        var n = "";
        var k = new BigInteger(o, 10);
        var a = k.toString(2);
        var l = 7 - a.length % 7;
        if (l == 7) { l = 0 }
        var q = "";
        for (var m = 0; m < l; m++) { q += "0" }
        a = q + a;
        for (var m = 0; m < a.length - 1; m += 7) {
            var p = a.substr(m, 7);
            if (m != a.length - 7) { p = "1" + p }
            n += e(parseInt(p, 2))
        }
        return n
    };
    if (!f.match(/^[0-9.]+$/)) {
        throw "malformed oid string: " + f
    }
    var g = "";
    var b = f.split(".");
    var j = parseInt(b[0]) * 40 + parseInt(b[1]);
    g += e(j);
    b.splice(0, 2);
    for (var c = 0; c < b.length; c++) { g += d(b[c]) }
    return g
};
KJUR.asn1.ASN1Object = function() {
    var c = true;
    var b = null;
    var d = "00";
    var e = "00";
    var a = "";
    this.getLengthHexFromValue = function() {
        if (typeof this.hV == "undefined" || this.hV == null) {
            throw "this.hV is null or undefined."
        }
        if (this.hV.length % 2 == 1) {
            throw "value hex must be even length: n=" + a.length + ",v=" + this.hV
        }
        var i = this.hV.length / 2;
        var h = i.toString(16);
        if (h.length % 2 == 1) { h = "0" + h }
        if (i < 128) {
            return h
        } else {
            var g = h.length / 2;
            if (g > 15) {
                throw "ASN.1 length too long to represent by 8x: n = " + i.toString(16)
            }
            var f = 128 + g;
            return f.toString(16) + h
        }
    };
    this.getEncodedHex = function() {
        if (this.hTLV == null || this.isModified) {
            this.hV = this.getFreshValueHex();
            this.hL = this.getLengthHexFromValue();
            this.hTLV = this.hT + this.hL + this.hV;
            this.isModified = false
        }
        return this.hTLV
    };
    this.getValueHex = function() {
        this.getEncodedHex();
        return this.hV
    };
    this.getFreshValueHex = function() {
        return ""
    }
};
KJUR.asn1.DERAbstractString = function(c) {
    KJUR.asn1.DERAbstractString.superclass.constructor.call(this);
    var b = null;
    var a = null;
    this.getString = function() {
        return this.s
    };
    this.setString = function(d) {
        this.hTLV = null;
        this.isModified = true;
        this.s = d;
        this.hV = stohex(this.s)
    };
    this.setStringHex = function(d) {
        this.hTLV = null;
        this.isModified = true;
        this.s = null;
        this.hV = d
    };
    this.getFreshValueHex = function() {
        return this.hV
    };
    if (typeof c != "undefined") {
        if (typeof c == "string") { this.setString(c) } else {
            if (typeof c.str != "undefined") { this.setString(c.str) } else {
                if (typeof c.hex != "undefined") { this.setStringHex(c.hex) }
            }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERAbstractString, KJUR.asn1.ASN1Object);
KJUR.asn1.DERAbstractTime = function(c) {
    KJUR.asn1.DERAbstractTime.superclass.constructor.call(this);
    var b = null;
    var a = null;
    this.localDateToUTC = function(f) {
        utc = f.getTime() + (f.getTimezoneOffset() * 60000);
        var e = new Date(utc);
        return e
    };
    this.formatDate = function(m, o, e) {
        var g = this.zeroPadding;
        var n = this.localDateToUTC(m);
        var p = String(n.getFullYear());
        if (o == "utc") { p = p.substr(2, 2) }
        var l = g(String(n.getMonth() + 1), 2);
        var q = g(String(n.getDate()), 2);
        var h = g(String(n.getHours()), 2);
        var i = g(String(n.getMinutes()), 2);
        var j = g(String(n.getSeconds()), 2);
        var r = p + l + q + h + i + j;
        if (e === true) {
            var f = n.getMilliseconds();
            if (f != 0) {
                var k = g(String(f), 3);
                k = k.replace(/[0]+$/, "");
                r = r + "." + k
            }
        }
        return r + "Z"
    };
    this.zeroPadding = function(e, d) {
        if (e.length >= d) {
            return e
        }
        return new Array(d - e.length + 1).join("0") + e
    };
    this.getString = function() {
        return this.s
    };
    this.setString = function(d) {
        this.hTLV = null;
        this.isModified = true;
        this.s = d;
        this.hV = stohex(d)
    };
    this.setByDateValue = function(h, j, e, d, f, g) {
        var i = new Date(Date.UTC(h, j - 1, e, d, f, g, 0));
        this.setByDate(i)
    };
    this.getFreshValueHex = function() {
        return this.hV
    }
};
YAHOO.lang.extend(KJUR.asn1.DERAbstractTime, KJUR.asn1.ASN1Object);
KJUR.asn1.DERAbstractStructured = function(b) {
    KJUR.asn1.DERAbstractString.superclass.constructor.call(this);
    var a = null;
    this.setByASN1ObjectArray = function(c) {
        this.hTLV = null;
        this.isModified = true;
        this.asn1Array = c
    };
    this.appendASN1Object = function(c) {
        this.hTLV = null;
        this.isModified = true;
        this.asn1Array.push(c)
    };
    this.asn1Array = new Array();
    if (typeof b != "undefined") {
        if (typeof b.array != "undefined") { this.asn1Array = b.array }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERAbstractStructured, KJUR.asn1.ASN1Object);
KJUR.asn1.DERBoolean = function() {
    KJUR.asn1.DERBoolean.superclass.constructor.call(this);
    this.hT = "01";
    this.hTLV = "0101ff"
};
YAHOO.lang.extend(KJUR.asn1.DERBoolean, KJUR.asn1.ASN1Object);
KJUR.asn1.DERInteger = function(a) {
    KJUR.asn1.DERInteger.superclass.constructor.call(this);
    this.hT = "02";
    this.setByBigInteger = function(b) {
        this.hTLV = null;
        this.isModified = true;
        this.hV = KJUR.asn1.ASN1Util.bigIntToMinTwosComplementsHex(b)
    };
    this.setByInteger = function(c) {
        var b = new BigInteger(String(c), 10);
        this.setByBigInteger(b)
    };
    this.setValueHex = function(b) { this.hV = b };
    this.getFreshValueHex = function() {
        return this.hV
    };
    if (typeof a != "undefined") {
        if (typeof a.bigint != "undefined") { this.setByBigInteger(a.bigint) } else {
            if (typeof a["int"] != "undefined") { this.setByInteger(a["int"]) } else {
                if (typeof a == "number") { this.setByInteger(a) } else {
                    if (typeof a.hex != "undefined") { this.setValueHex(a.hex) }
                }
            }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERInteger, KJUR.asn1.ASN1Object);
KJUR.asn1.DERBitString = function(a) {
    KJUR.asn1.DERBitString.superclass.constructor.call(this);
    this.hT = "03";
    this.setHexValueIncludingUnusedBits = function(b) {
        this.hTLV = null;
        this.isModified = true;
        this.hV = b
    };
    this.setUnusedBitsAndHexValue = function(b, d) {
        if (b < 0 || 7 < b) {
            throw "unused bits shall be from 0 to 7: u = " + b
        }
        var c = "0" + b;
        this.hTLV = null;
        this.isModified = true;
        this.hV = c + d
    };
    this.setByBinaryString = function(e) {
        e = e.replace(/0+$/, "");
        var f = 8 - e.length % 8;
        if (f == 8) { f = 0 }
        for (var g = 0; g <= f; g++) { e += "0" }
        var j = "";
        for (var g = 0; g < e.length - 1; g += 8) {
            var d = e.substr(g, 8);
            var c = parseInt(d, 2).toString(16);
            if (c.length == 1) { c = "0" + c }
            j += c
        }
        this.hTLV = null;
        this.isModified = true;
        this.hV = "0" + f + j
    };
    this.setByBooleanArray = function(d) {
        var c = "";
        for (var b = 0; b < d.length; b++) {
            if (d[b] == true) { c += "1" } else { c += "0" }
        }
        this.setByBinaryString(c)
    };
    this.newFalseArray = function(d) {
        var b = new Array(d);
        for (var c = 0; c < d; c++) { b[c] = false }
        return b
    };
    this.getFreshValueHex = function() {
        return this.hV
    };
    if (typeof a != "undefined") {
        if (typeof a == "string" && a.toLowerCase().match(/^[0-9a-f]+$/)) { this.setHexValueIncludingUnusedBits(a) } else {
            if (typeof a.hex != "undefined") { this.setHexValueIncludingUnusedBits(a.hex) } else {
                if (typeof a.bin != "undefined") { this.setByBinaryString(a.bin) } else {
                    if (typeof a.array != "undefined") { this.setByBooleanArray(a.array) }
                }
            }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERBitString, KJUR.asn1.ASN1Object);
KJUR.asn1.DEROctetString = function(a) {
    KJUR.asn1.DEROctetString.superclass.constructor.call(this, a);
    this.hT = "04"
};
YAHOO.lang.extend(KJUR.asn1.DEROctetString, KJUR.asn1.DERAbstractString);
KJUR.asn1.DERNull = function() {
    KJUR.asn1.DERNull.superclass.constructor.call(this);
    this.hT = "05";
    this.hTLV = "0500"
};
YAHOO.lang.extend(KJUR.asn1.DERNull, KJUR.asn1.ASN1Object);
KJUR.asn1.DERObjectIdentifier = function(c) {
    var b = function(d) {
        var e = d.toString(16);
        if (e.length == 1) { e = "0" + e }
        return e
    };
    var a = function(k) {
        var j = "";
        var e = new BigInteger(k, 10);
        var d = e.toString(2);
        var f = 7 - d.length % 7;
        if (f == 7) { f = 0 }
        var m = "";
        for (var g = 0; g < f; g++) { m += "0" }
        d = m + d;
        for (var g = 0; g < d.length - 1; g += 7) {
            var l = d.substr(g, 7);
            if (g != d.length - 7) { l = "1" + l }
            j += b(parseInt(l, 2))
        }
        return j
    };
    KJUR.asn1.DERObjectIdentifier.superclass.constructor.call(this);
    this.hT = "06";
    this.setValueHex = function(d) {
        this.hTLV = null;
        this.isModified = true;
        this.s = null;
        this.hV = d
    };
    this.setValueOidString = function(f) {
        if (!f.match(/^[0-9.]+$/)) {
            throw "malformed oid string: " + f
        }
        var g = "";
        var d = f.split(".");
        var j = parseInt(d[0]) * 40 + parseInt(d[1]);
        g += b(j);
        d.splice(0, 2);
        for (var e = 0; e < d.length; e++) { g += a(d[e]) }
        this.hTLV = null;
        this.isModified = true;
        this.s = null;
        this.hV = g
    };
    this.setValueName = function(e) {
        if (typeof KJUR.asn1.x509.OID.name2oidList[e] != "undefined") {
            var d = KJUR.asn1.x509.OID.name2oidList[e];
            this.setValueOidString(d)
        } else {
            throw "DERObjectIdentifier oidName undefined: " + e
        }
    };
    this.getFreshValueHex = function() {
        return this.hV
    };
    if (typeof c != "undefined") {
        if (typeof c == "string" && c.match(/^[0-2].[0-9.]+$/)) { this.setValueOidString(c) } else {
            if (KJUR.asn1.x509.OID.name2oidList[c] !== undefined) { this.setValueOidString(KJUR.asn1.x509.OID.name2oidList[c]) } else {
                if (typeof c.oid != "undefined") { this.setValueOidString(c.oid) } else {
                    if (typeof c.hex != "undefined") { this.setValueHex(c.hex) } else {
                        if (typeof c.name != "undefined") { this.setValueName(c.name) }
                    }
                }
            }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERObjectIdentifier, KJUR.asn1.ASN1Object);
KJUR.asn1.DEREnumerated = function(a) {
    KJUR.asn1.DEREnumerated.superclass.constructor.call(this);
    this.hT = "0a";
    this.setByBigInteger = function(b) {
        this.hTLV = null;
        this.isModified = true;
        this.hV = KJUR.asn1.ASN1Util.bigIntToMinTwosComplementsHex(b)
    };
    this.setByInteger = function(c) {
        var b = new BigInteger(String(c), 10);
        this.setByBigInteger(b)
    };
    this.setValueHex = function(b) { this.hV = b };
    this.getFreshValueHex = function() {
        return this.hV
    };
    if (typeof a != "undefined") {
        if (typeof a["int"] != "undefined") { this.setByInteger(a["int"]) } else {
            if (typeof a == "number") { this.setByInteger(a) } else {
                if (typeof a.hex != "undefined") { this.setValueHex(a.hex) }
            }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DEREnumerated, KJUR.asn1.ASN1Object);
KJUR.asn1.DERUTF8String = function(a) {
    KJUR.asn1.DERUTF8String.superclass.constructor.call(this, a);
    this.hT = "0c"
};
YAHOO.lang.extend(KJUR.asn1.DERUTF8String, KJUR.asn1.DERAbstractString);
KJUR.asn1.DERNumericString = function(a) {
    KJUR.asn1.DERNumericString.superclass.constructor.call(this, a);
    this.hT = "12"
};
YAHOO.lang.extend(KJUR.asn1.DERNumericString, KJUR.asn1.DERAbstractString);
KJUR.asn1.DERPrintableString = function(a) {
    KJUR.asn1.DERPrintableString.superclass.constructor.call(this, a);
    this.hT = "13"
};
YAHOO.lang.extend(KJUR.asn1.DERPrintableString, KJUR.asn1.DERAbstractString);
KJUR.asn1.DERTeletexString = function(a) {
    KJUR.asn1.DERTeletexString.superclass.constructor.call(this, a);
    this.hT = "14"
};
YAHOO.lang.extend(KJUR.asn1.DERTeletexString, KJUR.asn1.DERAbstractString);
KJUR.asn1.DERIA5String = function(a) {
    KJUR.asn1.DERIA5String.superclass.constructor.call(this, a);
    this.hT = "16"
};
YAHOO.lang.extend(KJUR.asn1.DERIA5String, KJUR.asn1.DERAbstractString);
KJUR.asn1.DERUTCTime = function(a) {
    KJUR.asn1.DERUTCTime.superclass.constructor.call(this, a);
    this.hT = "17";
    this.setByDate = function(b) {
        this.hTLV = null;
        this.isModified = true;
        this.date = b;
        this.s = this.formatDate(this.date, "utc");
        this.hV = stohex(this.s)
    };
    this.getFreshValueHex = function() {
        if (typeof this.date == "undefined" && typeof this.s == "undefined") {
            this.date = new Date();
            this.s = this.formatDate(this.date, "utc");
            this.hV = stohex(this.s)
        }
        return this.hV
    };
    if (a !== undefined) {
        if (a.str !== undefined) { this.setString(a.str) } else {
            if (typeof a == "string" && a.match(/^[0-9]{12}Z$/)) { this.setString(a) } else {
                if (a.hex !== undefined) { this.setStringHex(a.hex) } else {
                    if (a.date !== undefined) { this.setByDate(a.date) }
                }
            }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERUTCTime, KJUR.asn1.DERAbstractTime);
KJUR.asn1.DERGeneralizedTime = function(a) {
    KJUR.asn1.DERGeneralizedTime.superclass.constructor.call(this, a);
    this.hT = "18";
    this.withMillis = false;
    this.setByDate = function(b) {
        this.hTLV = null;
        this.isModified = true;
        this.date = b;
        this.s = this.formatDate(this.date, "gen", this.withMillis);
        this.hV = stohex(this.s)
    };
    this.getFreshValueHex = function() {
        if (this.date === undefined && this.s === undefined) {
            this.date = new Date();
            this.s = this.formatDate(this.date, "gen", this.withMillis);
            this.hV = stohex(this.s)
        }
        return this.hV
    };
    if (a !== undefined) {
        if (a.str !== undefined) { this.setString(a.str) } else {
            if (typeof a == "string" && a.match(/^[0-9]{14}Z$/)) { this.setString(a) } else {
                if (a.hex !== undefined) { this.setStringHex(a.hex) } else {
                    if (a.date !== undefined) { this.setByDate(a.date) }
                }
            }
        }
        if (a.millis === true) { this.withMillis = true }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERGeneralizedTime, KJUR.asn1.DERAbstractTime);
KJUR.asn1.DERSequence = function(a) {
    KJUR.asn1.DERSequence.superclass.constructor.call(this, a);
    this.hT = "30";
    this.getFreshValueHex = function() {
        var c = "";
        for (var b = 0; b < this.asn1Array.length; b++) {
            var d = this.asn1Array[b];
            c += d.getEncodedHex()
        }
        this.hV = c;
        return this.hV
    }
};
YAHOO.lang.extend(KJUR.asn1.DERSequence, KJUR.asn1.DERAbstractStructured);
KJUR.asn1.DERSet = function(a) {
    KJUR.asn1.DERSet.superclass.constructor.call(this, a);
    this.hT = "31";
    this.sortFlag = true;
    this.getFreshValueHex = function() {
        var b = new Array();
        for (var c = 0; c < this.asn1Array.length; c++) {
            var d = this.asn1Array[c];
            b.push(d.getEncodedHex())
        }
        if (this.sortFlag == true) { b.sort() }
        this.hV = b.join("");
        return this.hV
    };
    if (typeof a != "undefined") {
        if (typeof a.sortflag != "undefined" && a.sortflag == false) { this.sortFlag = false }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERSet, KJUR.asn1.DERAbstractStructured);
KJUR.asn1.DERTaggedObject = function(a) {
    KJUR.asn1.DERTaggedObject.superclass.constructor.call(this);
    this.hT = "a0";
    this.hV = "";
    this.isExplicit = true;
    this.asn1Object = null;
    this.setASN1Object = function(b, c, d) {
        this.hT = c;
        this.isExplicit = b;
        this.asn1Object = d;
        if (this.isExplicit) {
            this.hV = this.asn1Object.getEncodedHex();
            this.hTLV = null;
            this.isModified = true
        } else {
            this.hV = null;
            this.hTLV = d.getEncodedHex();
            this.hTLV = this.hTLV.replace(/^../, c);
            this.isModified = false
        }
    };
    this.getFreshValueHex = function() {
        return this.hV
    };
    if (typeof a != "undefined") {
        if (typeof a.tag != "undefined") { this.hT = a.tag }
        if (typeof a.explicit != "undefined") { this.isExplicit = a.explicit }
        if (typeof a.obj != "undefined") {
            this.asn1Object = a.obj;
            this.setASN1Object(this.isExplicit, this.hT, this.asn1Object)
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.DERTaggedObject, KJUR.asn1.ASN1Object);
/*! asn1hex-1.1.6.js (c) 2012-2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
var ASN1HEX = new function() {
    this.getByteLengthOfL_AtObj = function(b, c) {
        if (b.substring(c + 2, c + 3) != "8") {
            return 1
        }
        var a = parseInt(b.substring(c + 3, c + 4));
        if (a == 0) {
            return -1
        }
        if (0 < a && a < 10) {
            return a + 1
        }
        return -2
    };
    this.getHexOfL_AtObj = function(b, c) {
        var a = this.getByteLengthOfL_AtObj(b, c);
        if (a < 1) {
            return ""
        }
        return b.substring(c + 2, c + 2 + a * 2)
    };
    this.getIntOfL_AtObj = function(c, d) {
        var b = this.getHexOfL_AtObj(c, d);
        if (b == "") {
            return -1
        }
        var a;
        if (parseInt(b.substring(0, 1)) < 8) { a = new BigInteger(b, 16) } else { a = new BigInteger(b.substring(2), 16) }
        return a.intValue()
    };
    this.getStartPosOfV_AtObj = function(b, c) {
        var a = this.getByteLengthOfL_AtObj(b, c);
        if (a < 0) {
            return a
        }
        return c + (a + 1) * 2
    };
    this.getHexOfV_AtObj = function(c, d) {
        var b = this.getStartPosOfV_AtObj(c, d);
        var a = this.getIntOfL_AtObj(c, d);
        return c.substring(b, b + a * 2)
    };
    this.getHexOfTLV_AtObj = function(c, e) {
        var b = c.substr(e, 2);
        var d = this.getHexOfL_AtObj(c, e);
        var a = this.getHexOfV_AtObj(c, e);
        return b + d + a
    };
    this.getPosOfNextSibling_AtObj = function(c, d) {
        var b = this.getStartPosOfV_AtObj(c, d);
        var a = this.getIntOfL_AtObj(c, d);
        return b + a * 2
    };
    this.getPosArrayOfChildren_AtObj = function(f, j) {
        var c = new Array();
        var i = this.getStartPosOfV_AtObj(f, j);
        c.push(i);
        var b = this.getIntOfL_AtObj(f, j);
        var g = i;
        var d = 0;
        while (1) {
            var e = this.getPosOfNextSibling_AtObj(f, g);
            if (e == null || (e - i >= (b * 2))) {
                break
            }
            if (d >= 200) {
                break
            }
            c.push(e);
            g = e;
            d++
        }
        return c
    };
    this.getNthChildIndex_AtObj = function(d, b, e) {
        var c = this.getPosArrayOfChildren_AtObj(d, b);
        return c[e]
    };
    this.getDecendantIndexByNthList = function(e, d, c) {
        if (c.length == 0) {
            return d
        }
        var f = c.shift();
        var b = this.getPosArrayOfChildren_AtObj(e, d);
        return this.getDecendantIndexByNthList(e, b[f], c)
    };
    this.getDecendantHexTLVByNthList = function(d, c, b) {
        var a = this.getDecendantIndexByNthList(d, c, b);
        return this.getHexOfTLV_AtObj(d, a)
    };
    this.getDecendantHexVByNthList = function(d, c, b) {
        var a = this.getDecendantIndexByNthList(d, c, b);
        return this.getHexOfV_AtObj(d, a)
    }
};
ASN1HEX.getVbyList = function(d, c, b, e) {
    var a = this.getDecendantIndexByNthList(d, c, b);
    if (a === undefined) {
        throw "can't find nthList object"
    }
    if (e !== undefined) {
        if (d.substr(a, 2) != e) {
            throw "checking tag doesn't match: " + d.substr(a, 2) + "!=" + e
        }
    }
    return this.getHexOfV_AtObj(d, a)
};
ASN1HEX.hextooidstr = function(e) {
    var h = function(b, a) {
        if (b.length >= a) {
            return b
        }
        return new Array(a - b.length + 1).join("0") + b
    };
    var l = [];
    var o = e.substr(0, 2);
    var f = parseInt(o, 16);
    l[0] = new String(Math.floor(f / 40));
    l[1] = new String(f % 40);
    var m = e.substr(2);
    var k = [];
    for (var g = 0; g < m.length / 2; g++) { k.push(parseInt(m.substr(g * 2, 2), 16)) }
    var j = [];
    var d = "";
    for (var g = 0; g < k.length; g++) {
        if (k[g] & 128) { d = d + h((k[g] & 127).toString(2), 7) } else {
            d = d + h((k[g] & 127).toString(2), 7);
            j.push(new String(parseInt(d, 2)));
            d = ""
        }
    }
    var n = l.join(".");
    if (j.length > 0) { n = n + "." + j.join(".") }
    return n
};
ASN1HEX.dump = function(e, c, k, g) {
    var o = function(w, i) {
        if (w.length <= i * 2) {
            return w
        } else {
            var v = w.substr(0, i) + "..(total " + w.length / 2 + "bytes).." + w.substr(w.length - i, i);
            return v
        }
    };
    if (c === undefined) { c = { ommit_long_octet: 32 } }
    if (k === undefined) { k = 0 }
    if (g === undefined) { g = "" }
    var r = c.ommit_long_octet;
    if (e.substr(k, 2) == "01") {
        var h = ASN1HEX.getHexOfV_AtObj(e, k);
        if (h == "00") {
            return g + "BOOLEAN FALSE\n"
        } else {
            return g + "BOOLEAN TRUE\n"
        }
    }
    if (e.substr(k, 2) == "02") {
        var h = ASN1HEX.getHexOfV_AtObj(e, k);
        return g + "INTEGER " + o(h, r) + "\n"
    }
    if (e.substr(k, 2) == "03") {
        var h = ASN1HEX.getHexOfV_AtObj(e, k);
        return g + "BITSTRING " + o(h, r) + "\n"
    }
    if (e.substr(k, 2) == "04") {
        var h = ASN1HEX.getHexOfV_AtObj(e, k);
        if (ASN1HEX.isASN1HEX(h)) {
            var j = g + "OCTETSTRING, encapsulates\n";
            j = j + ASN1HEX.dump(h, c, 0, g + "  ");
            return j
        } else {
            return g + "OCTETSTRING " + o(h, r) + "\n"
        }
    }
    if (e.substr(k, 2) == "05") {
        return g + "NULL\n"
    }
    if (e.substr(k, 2) == "06") {
        var l = ASN1HEX.getHexOfV_AtObj(e, k);
        var a = KJUR.asn1.ASN1Util.oidHexToInt(l);
        var n = KJUR.asn1.x509.OID.oid2name(a);
        var b = a.replace(/\./g, " ");
        if (n != "") {
            return g + "ObjectIdentifier " + n + " (" + b + ")\n"
        } else {
            return g + "ObjectIdentifier (" + b + ")\n"
        }
    }
    if (e.substr(k, 2) == "0c") {
        return g + "UTF8String '" + hextoutf8(ASN1HEX.getHexOfV_AtObj(e, k)) + "'\n"
    }
    if (e.substr(k, 2) == "13") {
        return g + "PrintableString '" + hextoutf8(ASN1HEX.getHexOfV_AtObj(e, k)) + "'\n"
    }
    if (e.substr(k, 2) == "14") {
        return g + "TeletexString '" + hextoutf8(ASN1HEX.getHexOfV_AtObj(e, k)) + "'\n"
    }
    if (e.substr(k, 2) == "16") {
        return g + "IA5String '" + hextoutf8(ASN1HEX.getHexOfV_AtObj(e, k)) + "'\n"
    }
    if (e.substr(k, 2) == "17") {
        return g + "UTCTime " + hextoutf8(ASN1HEX.getHexOfV_AtObj(e, k)) + "\n"
    }
    if (e.substr(k, 2) == "18") {
        return g + "GeneralizedTime " + hextoutf8(ASN1HEX.getHexOfV_AtObj(e, k)) + "\n"
    }
    if (e.substr(k, 2) == "30") {
        if (e.substr(k, 4) == "3000") {
            return g + "SEQUENCE {}\n"
        }
        var j = g + "SEQUENCE\n";
        var d = ASN1HEX.getPosArrayOfChildren_AtObj(e, k);
        var f = c;
        if ((d.length == 2 || d.length == 3) && e.substr(d[0], 2) == "06" && e.substr(d[d.length - 1], 2) == "04") {
            var t = ASN1HEX.getHexOfV_AtObj(e, d[0]);
            var a = KJUR.asn1.ASN1Util.oidHexToInt(t);
            var n = KJUR.asn1.x509.OID.oid2name(a);
            var p = JSON.parse(JSON.stringify(c));
            p.x509ExtName = n;
            f = p
        }
        for (var q = 0; q < d.length; q++) { j = j + ASN1HEX.dump(e, f, d[q], g + "  ") }
        return j
    }
    if (e.substr(k, 2) == "31") {
        var j = g + "SET\n";
        var d = ASN1HEX.getPosArrayOfChildren_AtObj(e, k);
        for (var q = 0; q < d.length; q++) { j = j + ASN1HEX.dump(e, c, d[q], g + "  ") }
        return j
    }
    var u = parseInt(e.substr(k, 2), 16);
    if ((u & 128) != 0) {
        var m = u & 31;
        if ((u & 32) != 0) {
            var j = g + "[" + m + "]\n";
            var d = ASN1HEX.getPosArrayOfChildren_AtObj(e, k);
            for (var q = 0; q < d.length; q++) { j = j + ASN1HEX.dump(e, c, d[q], g + "  ") }
            return j
        } else {
            var h = ASN1HEX.getHexOfV_AtObj(e, k);
            if (h.substr(0, 8) == "68747470") { h = hextoutf8(h) }
            if (c.x509ExtName === "subjectAltName" && m == 2) { h = hextoutf8(h) }
            var j = g + "[" + m + "] " + h + "\n";
            return j
        }
    }
    return g + "UNKNOWN(" + e.substr(k, 2) + ") " + ASN1HEX.getHexOfV_AtObj(e, k) + "\n"
};
ASN1HEX.isASN1HEX = function(d) {
    if (d.length % 2 == 1) {
        return false
    }
    var c = ASN1HEX.getIntOfL_AtObj(d, 0);
    var b = d.substr(0, 2);
    var e = ASN1HEX.getHexOfL_AtObj(d, 0);
    var a = d.length - b.length - e.length;
    if (a == c * 2) {
        return true
    }
    return false
};
/*! asn1x509-1.0.13.js (c) 2013-2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
if (typeof KJUR == "undefined" || !KJUR) { KJUR = {} }
if (typeof KJUR.asn1 == "undefined" || !KJUR.asn1) { KJUR.asn1 = {} }
if (typeof KJUR.asn1.x509 == "undefined" || !KJUR.asn1.x509) { KJUR.asn1.x509 = {} }
KJUR.asn1.x509.Certificate = function(g) {
    KJUR.asn1.x509.Certificate.superclass.constructor.call(this);
    var b = null;
    var d = null;
    var f = null;
    var c = null;
    var a = null;
    var e = null;
    this.setRsaPrvKeyByPEMandPass = function(i, k) {
        var h = PKCS5PKEY.getDecryptedKeyHex(i, k);
        var j = new RSAKey();
        j.readPrivateKeyFromASN1HexString(h);
        this.prvKey = j
    };
    this.sign = function() {
        this.asn1SignatureAlg = this.asn1TBSCert.asn1SignatureAlg;
        sig = new KJUR.crypto.Signature({ alg: "SHA1withRSA" });
        sig.init(this.prvKey);
        sig.updateHex(this.asn1TBSCert.getEncodedHex());
        this.hexSig = sig.sign();
        this.asn1Sig = new KJUR.asn1.DERBitString({ hex: "00" + this.hexSig });
        var h = new KJUR.asn1.DERSequence({ array: [this.asn1TBSCert, this.asn1SignatureAlg, this.asn1Sig] });
        this.hTLV = h.getEncodedHex();
        this.isModified = false
    };
    this.setSignatureHex = function(h) {
        this.asn1SignatureAlg = this.asn1TBSCert.asn1SignatureAlg;
        this.hexSig = h;
        this.asn1Sig = new KJUR.asn1.DERBitString({ hex: "00" + this.hexSig });
        var i = new KJUR.asn1.DERSequence({ array: [this.asn1TBSCert, this.asn1SignatureAlg, this.asn1Sig] });
        this.hTLV = i.getEncodedHex();
        this.isModified = false
    };
    this.getEncodedHex = function() {
        if (this.isModified == false && this.hTLV != null) {
            return this.hTLV
        }
        throw "not signed yet"
    };
    this.getPEMString = function() {
        var j = this.getEncodedHex();
        var h = CryptoJS.enc.Hex.parse(j);
        var i = CryptoJS.enc.Base64.stringify(h);
        var k = i.replace(/(.{64})/g, "$1\r\n");
        return "-----BEGIN CERTIFICATE-----\r\n" + k + "\r\n-----END CERTIFICATE-----\r\n"
    };
    if (typeof g != "undefined") {
        if (typeof g.tbscertobj != "undefined") { this.asn1TBSCert = g.tbscertobj }
        if (typeof g.prvkeyobj != "undefined") { this.prvKey = g.prvkeyobj } else {
            if (typeof g.rsaprvkey != "undefined") { this.prvKey = g.rsaprvkey } else {
                if ((typeof g.rsaprvpem != "undefined") && (typeof g.rsaprvpas != "undefined")) { this.setRsaPrvKeyByPEMandPass(g.rsaprvpem, g.rsaprvpas) }
            }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.Certificate, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.TBSCertificate = function(a) {
    KJUR.asn1.x509.TBSCertificate.superclass.constructor.call(this);
    this._initialize = function() {
        this.asn1Array = new Array();
        this.asn1Version = new KJUR.asn1.DERTaggedObject({ obj: new KJUR.asn1.DERInteger({ "int": 2 }) });
        this.asn1SerialNumber = null;
        this.asn1SignatureAlg = null;
        this.asn1Issuer = null;
        this.asn1NotBefore = null;
        this.asn1NotAfter = null;
        this.asn1Subject = null;
        this.asn1SubjPKey = null;
        this.extensionsArray = new Array()
    };
    this.setSerialNumberByParam = function(b) { this.asn1SerialNumber = new KJUR.asn1.DERInteger(b) };
    this.setSignatureAlgByParam = function(b) { this.asn1SignatureAlg = new KJUR.asn1.x509.AlgorithmIdentifier(b) };
    this.setIssuerByParam = function(b) { this.asn1Issuer = new KJUR.asn1.x509.X500Name(b) };
    this.setNotBeforeByParam = function(b) { this.asn1NotBefore = new KJUR.asn1.x509.Time(b) };
    this.setNotAfterByParam = function(b) { this.asn1NotAfter = new KJUR.asn1.x509.Time(b) };
    this.setSubjectByParam = function(b) { this.asn1Subject = new KJUR.asn1.x509.X500Name(b) };
    this.setSubjectPublicKeyByParam = function(b) { this.asn1SubjPKey = new KJUR.asn1.x509.SubjectPublicKeyInfo(b) };
    this.setSubjectPublicKeyByGetKey = function(c) {
        var b = KEYUTIL.getKey(c);
        this.asn1SubjPKey = new KJUR.asn1.x509.SubjectPublicKeyInfo(b)
    };
    this.appendExtension = function(b) { this.extensionsArray.push(b) };
    this.appendExtensionByName = function(d, b) {
        if (d.toLowerCase() == "basicconstraints") {
            var c = new KJUR.asn1.x509.BasicConstraints(b);
            this.appendExtension(c)
        } else {
            if (d.toLowerCase() == "keyusage") {
                var c = new KJUR.asn1.x509.KeyUsage(b);
                this.appendExtension(c)
            } else {
                if (d.toLowerCase() == "crldistributionpoints") {
                    var c = new KJUR.asn1.x509.CRLDistributionPoints(b);
                    this.appendExtension(c)
                } else {
                    if (d.toLowerCase() == "extkeyusage") {
                        var c = new KJUR.asn1.x509.ExtKeyUsage(b);
                        this.appendExtension(c)
                    } else {
                        if (d.toLowerCase() == "authoritykeyidentifier") {
                            var c = new KJUR.asn1.x509.AuthorityKeyIdentifier(b);
                            this.appendExtension(c)
                        } else {
                            throw "unsupported extension name: " + d
                        }
                    }
                }
            }
        }
    };
    this.getEncodedHex = function() {
        if (this.asn1NotBefore == null || this.asn1NotAfter == null) {
            throw "notBefore and/or notAfter not set"
        }
        var c = new KJUR.asn1.DERSequence({ array: [this.asn1NotBefore, this.asn1NotAfter] });
        this.asn1Array = new Array();
        this.asn1Array.push(this.asn1Version);
        this.asn1Array.push(this.asn1SerialNumber);
        this.asn1Array.push(this.asn1SignatureAlg);
        this.asn1Array.push(this.asn1Issuer);
        this.asn1Array.push(c);
        this.asn1Array.push(this.asn1Subject);
        this.asn1Array.push(this.asn1SubjPKey);
        if (this.extensionsArray.length > 0) {
            var d = new KJUR.asn1.DERSequence({ array: this.extensionsArray });
            var b = new KJUR.asn1.DERTaggedObject({ explicit: true, tag: "a3", obj: d });
            this.asn1Array.push(b)
        }
        var e = new KJUR.asn1.DERSequence({ array: this.asn1Array });
        this.hTLV = e.getEncodedHex();
        this.isModified = false;
        return this.hTLV
    };
    this._initialize()
};
YAHOO.lang.extend(KJUR.asn1.x509.TBSCertificate, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.Extension = function(b) {
    KJUR.asn1.x509.Extension.superclass.constructor.call(this);
    var a = null;
    this.getEncodedHex = function() {
        var f = new KJUR.asn1.DERObjectIdentifier({ oid: this.oid });
        var e = new KJUR.asn1.DEROctetString({ hex: this.getExtnValueHex() });
        var d = new Array();
        d.push(f);
        if (this.critical) { d.push(new KJUR.asn1.DERBoolean()) }
        d.push(e);
        var c = new KJUR.asn1.DERSequence({ array: d });
        return c.getEncodedHex()
    };
    this.critical = false;
    if (typeof b != "undefined") {
        if (typeof b.critical != "undefined") { this.critical = b.critical }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.Extension, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.KeyUsage = function(a) {
    KJUR.asn1.x509.KeyUsage.superclass.constructor.call(this, a);
    this.getExtnValueHex = function() {
        return this.asn1ExtnValue.getEncodedHex()
    };
    this.oid = "2.5.29.15";
    if (typeof a != "undefined") {
        if (typeof a.bin != "undefined") { this.asn1ExtnValue = new KJUR.asn1.DERBitString(a) }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.KeyUsage, KJUR.asn1.x509.Extension);
KJUR.asn1.x509.BasicConstraints = function(c) {
    KJUR.asn1.x509.BasicConstraints.superclass.constructor.call(this, c);
    var a = false;
    var b = -1;
    this.getExtnValueHex = function() {
        var e = new Array();
        if (this.cA) { e.push(new KJUR.asn1.DERBoolean()) }
        if (this.pathLen > -1) { e.push(new KJUR.asn1.DERInteger({ "int": this.pathLen })) }
        var d = new KJUR.asn1.DERSequence({ array: e });
        this.asn1ExtnValue = d;
        return this.asn1ExtnValue.getEncodedHex()
    };
    this.oid = "2.5.29.19";
    this.cA = false;
    this.pathLen = -1;
    if (typeof c != "undefined") {
        if (typeof c.cA != "undefined") { this.cA = c.cA }
        if (typeof c.pathLen != "undefined") { this.pathLen = c.pathLen }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.BasicConstraints, KJUR.asn1.x509.Extension);
KJUR.asn1.x509.CRLDistributionPoints = function(a) {
    KJUR.asn1.x509.CRLDistributionPoints.superclass.constructor.call(this, a);
    this.getExtnValueHex = function() {
        return this.asn1ExtnValue.getEncodedHex()
    };
    this.setByDPArray = function(b) { this.asn1ExtnValue = new KJUR.asn1.DERSequence({ array: b }) };
    this.setByOneURI = function(e) {
        var b = new KJUR.asn1.x509.GeneralNames([{ uri: e }]);
        var d = new KJUR.asn1.x509.DistributionPointName(b);
        var c = new KJUR.asn1.x509.DistributionPoint({ dpobj: d });
        this.setByDPArray([c])
    };
    this.oid = "2.5.29.31";
    if (typeof a != "undefined") {
        if (typeof a.array != "undefined") { this.setByDPArray(a.array) } else {
            if (typeof a.uri != "undefined") { this.setByOneURI(a.uri) }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.CRLDistributionPoints, KJUR.asn1.x509.Extension);
KJUR.asn1.x509.ExtKeyUsage = function(a) {
    KJUR.asn1.x509.ExtKeyUsage.superclass.constructor.call(this, a);
    this.setPurposeArray = function(b) {
        this.asn1ExtnValue = new KJUR.asn1.DERSequence();
        for (var c = 0; c < b.length; c++) {
            var d = new KJUR.asn1.DERObjectIdentifier(b[c]);
            this.asn1ExtnValue.appendASN1Object(d)
        }
    };
    this.getExtnValueHex = function() {
        return this.asn1ExtnValue.getEncodedHex()
    };
    this.oid = "2.5.29.37";
    if (typeof a != "undefined") {
        if (typeof a.array != "undefined") { this.setPurposeArray(a.array) }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.ExtKeyUsage, KJUR.asn1.x509.Extension);
KJUR.asn1.x509.AuthorityKeyIdentifier = function(a) {
    KJUR.asn1.x509.AuthorityKeyIdentifier.superclass.constructor.call(this, a);
    this.asn1KID = null;
    this.asn1CertIssuer = null;
    this.asn1CertSN = null;
    this.getExtnValueHex = function() {
        var c = new Array();
        if (this.asn1KID) { c.push(new KJUR.asn1.DERTaggedObject({ explicit: false, tag: "80", obj: this.asn1KID })) }
        if (this.asn1CertIssuer) { c.push(new KJUR.asn1.DERTaggedObject({ explicit: false, tag: "a1", obj: this.asn1CertIssuer })) }
        if (this.asn1CertSN) { c.push(new KJUR.asn1.DERTaggedObject({ explicit: false, tag: "82", obj: this.asn1CertSN })) }
        var b = new KJUR.asn1.DERSequence({ array: c });
        this.asn1ExtnValue = b;
        return this.asn1ExtnValue.getEncodedHex()
    };
    this.setKIDByParam = function(b) { this.asn1KID = new KJUR.asn1.DEROctetString(b) };
    this.setCertIssuerByParam = function(b) { this.asn1CertIssuer = new KJUR.asn1.x509.X500Name(b) };
    this.setCertSNByParam = function(b) { this.asn1CertSN = new KJUR.asn1.DERInteger(b) };
    this.oid = "2.5.29.35";
    if (typeof a != "undefined") {
        if (typeof a.kid != "undefined") { this.setKIDByParam(a.kid) }
        if (typeof a.issuer != "undefined") { this.setCertIssuerByParam(a.issuer) }
        if (typeof a.sn != "undefined") { this.setCertSNByParam(a.sn) }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.AuthorityKeyIdentifier, KJUR.asn1.x509.Extension);
KJUR.asn1.x509.CRL = function(f) {
    KJUR.asn1.x509.CRL.superclass.constructor.call(this);
    var a = null;
    var c = null;
    var e = null;
    var b = null;
    var d = null;
    this.setRsaPrvKeyByPEMandPass = function(h, j) {
        var g = PKCS5PKEY.getDecryptedKeyHex(h, j);
        var i = new RSAKey();
        i.readPrivateKeyFromASN1HexString(g);
        this.rsaPrvKey = i
    };
    this.sign = function() {
        this.asn1SignatureAlg = this.asn1TBSCertList.asn1SignatureAlg;
        sig = new KJUR.crypto.Signature({ alg: "SHA1withRSA", prov: "cryptojs/jsrsa" });
        sig.initSign(this.rsaPrvKey);
        sig.updateHex(this.asn1TBSCertList.getEncodedHex());
        this.hexSig = sig.sign();
        this.asn1Sig = new KJUR.asn1.DERBitString({ hex: "00" + this.hexSig });
        var g = new KJUR.asn1.DERSequence({ array: [this.asn1TBSCertList, this.asn1SignatureAlg, this.asn1Sig] });
        this.hTLV = g.getEncodedHex();
        this.isModified = false
    };
    this.getEncodedHex = function() {
        if (this.isModified == false && this.hTLV != null) {
            return this.hTLV
        }
        throw "not signed yet"
    };
    this.getPEMString = function() {
        var i = this.getEncodedHex();
        var g = CryptoJS.enc.Hex.parse(i);
        var h = CryptoJS.enc.Base64.stringify(g);
        var j = h.replace(/(.{64})/g, "$1\r\n");
        return "-----BEGIN X509 CRL-----\r\n" + j + "\r\n-----END X509 CRL-----\r\n"
    };
    if (typeof f != "undefined") {
        if (typeof f.tbsobj != "undefined") { this.asn1TBSCertList = f.tbsobj }
        if (typeof f.rsaprvkey != "undefined") { this.rsaPrvKey = f.rsaprvkey }
        if ((typeof f.rsaprvpem != "undefined") && (typeof f.rsaprvpas != "undefined")) { this.setRsaPrvKeyByPEMandPass(f.rsaprvpem, f.rsaprvpas) }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.CRL, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.TBSCertList = function(b) {
    KJUR.asn1.x509.TBSCertList.superclass.constructor.call(this);
    var a = null;
    this.setSignatureAlgByParam = function(c) { this.asn1SignatureAlg = new KJUR.asn1.x509.AlgorithmIdentifier(c) };
    this.setIssuerByParam = function(c) { this.asn1Issuer = new KJUR.asn1.x509.X500Name(c) };
    this.setThisUpdateByParam = function(c) { this.asn1ThisUpdate = new KJUR.asn1.x509.Time(c) };
    this.setNextUpdateByParam = function(c) { this.asn1NextUpdate = new KJUR.asn1.x509.Time(c) };
    this.addRevokedCert = function(c, d) {
        var f = {};
        if (c != undefined && c != null) { f.sn = c }
        if (d != undefined && d != null) { f.time = d }
        var e = new KJUR.asn1.x509.CRLEntry(f);
        this.aRevokedCert.push(e)
    };
    this.getEncodedHex = function() {
        this.asn1Array = new Array();
        if (this.asn1Version != null) { this.asn1Array.push(this.asn1Version) }
        this.asn1Array.push(this.asn1SignatureAlg);
        this.asn1Array.push(this.asn1Issuer);
        this.asn1Array.push(this.asn1ThisUpdate);
        if (this.asn1NextUpdate != null) { this.asn1Array.push(this.asn1NextUpdate) }
        if (this.aRevokedCert.length > 0) {
            var c = new KJUR.asn1.DERSequence({ array: this.aRevokedCert });
            this.asn1Array.push(c)
        }
        var d = new KJUR.asn1.DERSequence({ array: this.asn1Array });
        this.hTLV = d.getEncodedHex();
        this.isModified = false;
        return this.hTLV
    };
    this._initialize = function() {
        this.asn1Version = null;
        this.asn1SignatureAlg = null;
        this.asn1Issuer = null;
        this.asn1ThisUpdate = null;
        this.asn1NextUpdate = null;
        this.aRevokedCert = new Array()
    };
    this._initialize()
};
YAHOO.lang.extend(KJUR.asn1.x509.TBSCertList, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.CRLEntry = function(c) {
    KJUR.asn1.x509.CRLEntry.superclass.constructor.call(this);
    var b = null;
    var a = null;
    this.setCertSerial = function(d) { this.sn = new KJUR.asn1.DERInteger(d) };
    this.setRevocationDate = function(d) { this.time = new KJUR.asn1.x509.Time(d) };
    this.getEncodedHex = function() {
        var d = new KJUR.asn1.DERSequence({ array: [this.sn, this.time] });
        this.TLV = d.getEncodedHex();
        return this.TLV
    };
    if (typeof c != "undefined") {
        if (typeof c.time != "undefined") { this.setRevocationDate(c.time) }
        if (typeof c.sn != "undefined") { this.setCertSerial(c.sn) }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.CRLEntry, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.X500Name = function(b) {
    KJUR.asn1.x509.X500Name.superclass.constructor.call(this);
    this.asn1Array = new Array();
    this.setByString = function(c) {
        var d = c.split("/");
        d.shift();
        for (var e = 0; e < d.length; e++) { this.asn1Array.push(new KJUR.asn1.x509.RDN({ str: d[e] })) }
    };
    this.setByObject = function(e) {
        for (var c in e) {
            if (e.hasOwnProperty(c)) {
                var d = new KJUR.asn1.x509.RDN({ str: c + "=" + e[c] });
                this.asn1Array ? this.asn1Array.push(d) : this.asn1Array = [d]
            }
        }
    };
    this.getEncodedHex = function() {
        if (typeof this.hTLV == "string") {
            return this.hTLV
        }
        var c = new KJUR.asn1.DERSequence({ array: this.asn1Array });
        this.hTLV = c.getEncodedHex();
        return this.hTLV
    };
    if (typeof b != "undefined") {
        if (typeof b.str != "undefined") { this.setByString(b.str) } else {
            if (typeof b === "object") { this.setByObject(b) }
        }
        if (typeof b.certissuer != "undefined") {
            var a = new X509();
            a.hex = X509.pemToHex(b.certissuer);
            this.hTLV = a.getIssuerHex()
        }
        if (typeof b.certsubject != "undefined") {
            var a = new X509();
            a.hex = X509.pemToHex(b.certsubject);
            this.hTLV = a.getSubjectHex()
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.X500Name, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.RDN = function(a) {
    KJUR.asn1.x509.RDN.superclass.constructor.call(this);
    this.asn1Array = new Array();
    this.addByString = function(b) { this.asn1Array.push(new KJUR.asn1.x509.AttributeTypeAndValue({ str: b })) };
    this.getEncodedHex = function() {
        var b = new KJUR.asn1.DERSet({ array: this.asn1Array });
        this.TLV = b.getEncodedHex();
        return this.TLV
    };
    if (typeof a != "undefined") {
        if (typeof a.str != "undefined") { this.addByString(a.str) }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.RDN, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.AttributeTypeAndValue = function(b) {
    KJUR.asn1.x509.AttributeTypeAndValue.superclass.constructor.call(this);
    var d = null;
    var c = null;
    var a = "utf8";
    this.setByString = function(e) {
        if (e.match(/^([^=]+)=(.+)$/)) { this.setByAttrTypeAndValueStr(RegExp.$1, RegExp.$2) } else {
            throw "malformed attrTypeAndValueStr: " + e
        }
    };
    this.setByAttrTypeAndValueStr = function(g, f) {
        this.typeObj = KJUR.asn1.x509.OID.atype2obj(g);
        var e = a;
        if (g == "C") { e = "prn" }
        this.valueObj = this.getValueObj(e, f)
    };
    this.getValueObj = function(f, e) {
        if (f == "utf8") {
            return new KJUR.asn1.DERUTF8String({ str: e })
        }
        if (f == "prn") {
            return new KJUR.asn1.DERPrintableString({ str: e })
        }
        if (f == "tel") {
            return new KJUR.asn1.DERTeletexString({ str: e })
        }
        if (f == "ia5") {
            return new KJUR.asn1.DERIA5String({ str: e })
        }
        throw "unsupported directory string type: type=" + f + " value=" + e
    };
    this.getEncodedHex = function() {
        var e = new KJUR.asn1.DERSequence({ array: [this.typeObj, this.valueObj] });
        this.TLV = e.getEncodedHex();
        return this.TLV
    };
    if (typeof b != "undefined") {
        if (typeof b.str != "undefined") { this.setByString(b.str) }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.AttributeTypeAndValue, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.SubjectPublicKeyInfo = function(d) {
    KJUR.asn1.x509.SubjectPublicKeyInfo.superclass.constructor.call(this);
    var b = null;
    var c = null;
    var a = null;
    this.setRSAKey = function(e) {
        if (!RSAKey.prototype.isPrototypeOf(e)) {
            throw "argument is not RSAKey instance"
        }
        this.rsaKey = e;
        var g = new KJUR.asn1.DERInteger({ bigint: e.n });
        var f = new KJUR.asn1.DERInteger({ "int": e.e });
        var i = new KJUR.asn1.DERSequence({ array: [g, f] });
        var h = i.getEncodedHex();
        this.asn1AlgId = new KJUR.asn1.x509.AlgorithmIdentifier({ name: "rsaEncryption" });
        this.asn1SubjPKey = new KJUR.asn1.DERBitString({ hex: "00" + h })
    };
    this.setRSAPEM = function(g) {
        if (g.match(/-----BEGIN PUBLIC KEY-----/)) {
            var n = g;
            n = n.replace(/^-----[^-]+-----/, "");
            n = n.replace(/-----[^-]+-----\s*$/, "");
            var m = n.replace(/\s+/g, "");
            var f = CryptoJS.enc.Base64.parse(m);
            var i = CryptoJS.enc.Hex.stringify(f);
            var k = _rsapem_getHexValueArrayOfChildrenFromHex(i);
            var h = k[1];
            var l = h.substr(2);
            var e = _rsapem_getHexValueArrayOfChildrenFromHex(l);
            var j = new RSAKey();
            j.setPublic(e[0], e[1]);
            this.setRSAKey(j)
        } else {
            throw "key not supported"
        }
    };
    this.getASN1Object = function() {
        if (this.asn1AlgId == null || this.asn1SubjPKey == null) {
            throw "algId and/or subjPubKey not set"
        }
        var e = new KJUR.asn1.DERSequence({ array: [this.asn1AlgId, this.asn1SubjPKey] });
        return e
    };
    this.getEncodedHex = function() {
        var e = this.getASN1Object();
        this.hTLV = e.getEncodedHex();
        return this.hTLV
    };
    this._setRSAKey = function(e) {
        var g = KJUR.asn1.ASN1Util.newObject({ seq: [{ "int": { bigint: e.n } }, { "int": { "int": e.e } }] });
        var f = g.getEncodedHex();
        this.asn1AlgId = new KJUR.asn1.x509.AlgorithmIdentifier({ name: "rsaEncryption" });
        this.asn1SubjPKey = new KJUR.asn1.DERBitString({ hex: "00" + f })
    };
    this._setEC = function(e) {
        var f = new KJUR.asn1.DERObjectIdentifier({ name: e.curveName });
        this.asn1AlgId = new KJUR.asn1.x509.AlgorithmIdentifier({ name: "ecPublicKey", asn1params: f });
        this.asn1SubjPKey = new KJUR.asn1.DERBitString({ hex: "00" + e.pubKeyHex })
    };
    this._setDSA = function(e) {
        var f = new KJUR.asn1.ASN1Util.newObject({ seq: [{ "int": { bigint: e.p } }, { "int": { bigint: e.q } }, { "int": { bigint: e.g } }] });
        this.asn1AlgId = new KJUR.asn1.x509.AlgorithmIdentifier({ name: "dsa", asn1params: f });
        var g = new KJUR.asn1.DERInteger({ bigint: e.y });
        this.asn1SubjPKey = new KJUR.asn1.DERBitString({ hex: "00" + g.getEncodedHex() })
    };
    if (typeof d != "undefined") {
        if (typeof RSAKey != "undefined" && d instanceof RSAKey) { this._setRSAKey(d) } else {
            if (typeof KJUR.crypto.ECDSA != "undefined" && d instanceof KJUR.crypto.ECDSA) { this._setEC(d) } else {
                if (typeof KJUR.crypto.DSA != "undefined" && d instanceof KJUR.crypto.DSA) { this._setDSA(d) } else {
                    if (typeof d.rsakey != "undefined") { this.setRSAKey(d.rsakey) } else {
                        if (typeof d.rsapem != "undefined") { this.setRSAPEM(d.rsapem) }
                    }
                }
            }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.SubjectPublicKeyInfo, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.Time = function(c) {
    KJUR.asn1.x509.Time.superclass.constructor.call(this);
    var b = null;
    var a = null;
    this.setTimeParams = function(d) { this.timeParams = d };
    this.getEncodedHex = function() {
        var d = null;
        if (this.timeParams != null) {
            if (this.type == "utc") { d = new KJUR.asn1.DERUTCTime(this.timeParams) } else { d = new KJUR.asn1.DERGeneralizedTime(this.timeParams) }
        } else {
            if (this.type == "utc") { d = new KJUR.asn1.DERUTCTime() } else { d = new KJUR.asn1.DERGeneralizedTime() }
        }
        this.TLV = d.getEncodedHex();
        return this.TLV
    };
    this.type = "utc";
    if (typeof c != "undefined") {
        if (typeof c.type != "undefined") { this.type = c.type } else {
            if (typeof c.str != "undefined") {
                if (c.str.match(/^[0-9]{12}Z$/)) { this.type = "utc" }
                if (c.str.match(/^[0-9]{14}Z$/)) { this.type = "gen" }
            }
        }
        this.timeParams = c
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.Time, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.AlgorithmIdentifier = function(e) {
    KJUR.asn1.x509.AlgorithmIdentifier.superclass.constructor.call(this);
    var a = null;
    var d = null;
    var b = null;
    var c = false;
    this.getEncodedHex = function() {
        if (this.nameAlg == null && this.asn1Alg == null) {
            throw "algorithm not specified"
        }
        if (this.nameAlg != null && this.asn1Alg == null) { this.asn1Alg = KJUR.asn1.x509.OID.name2obj(this.nameAlg) }
        var f = [this.asn1Alg];
        if (!this.paramEmpty) { f.push(this.asn1Params) }
        var g = new KJUR.asn1.DERSequence({ array: f });
        this.hTLV = g.getEncodedHex();
        return this.hTLV
    };
    if (typeof e != "undefined") {
        if (typeof e.name != "undefined") { this.nameAlg = e.name }
        if (typeof e.asn1params != "undefined") { this.asn1Params = e.asn1params }
        if (typeof e.paramempty != "undefined") { this.paramEmpty = e.paramempty }
    }
    if (this.asn1Params == null) { this.asn1Params = new KJUR.asn1.DERNull() }
};
YAHOO.lang.extend(KJUR.asn1.x509.AlgorithmIdentifier, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.GeneralName = function(d) {
    KJUR.asn1.x509.GeneralName.superclass.constructor.call(this);
    var c = null;
    var b = null;
    var a = { rfc822: "81", dns: "82", dn: "a4", uri: "86" };
    this.explicit = false;
    this.setByParam = function(k) {
        var j = null;
        var g = null;
        if (typeof k == "undefined") {
            return
        }
        if (typeof k.rfc822 != "undefined") {
            this.type = "rfc822";
            g = new KJUR.asn1.DERIA5String({ str: k[this.type] })
        }
        if (typeof k.dns != "undefined") {
            this.type = "dns";
            g = new KJUR.asn1.DERIA5String({ str: k[this.type] })
        }
        if (typeof k.uri != "undefined") {
            this.type = "uri";
            g = new KJUR.asn1.DERIA5String({ str: k[this.type] })
        }
        if (typeof k.certissuer != "undefined") {
            this.type = "dn";
            this.explicit = true;
            var h = k.certissuer;
            var f = null;
            if (h.match(/^[0-9A-Fa-f]+$/)) { f == h }
            if (h.indexOf("-----BEGIN ") != -1) { f = X509.pemToHex(h) }
            if (f == null) {
                throw "certissuer param not cert"
            }
            var e = new X509();
            e.hex = f;
            var i = e.getIssuerHex();
            g = new KJUR.asn1.ASN1Object();
            g.hTLV = i
        }
        if (typeof k.certsubj != "undefined") {
            this.type = "dn";
            this.explicit = true;
            var h = k.certsubj;
            var f = null;
            if (h.match(/^[0-9A-Fa-f]+$/)) { f == h }
            if (h.indexOf("-----BEGIN ") != -1) { f = X509.pemToHex(h) }
            if (f == null) {
                throw "certsubj param not cert"
            }
            var e = new X509();
            e.hex = f;
            var i = e.getSubjectHex();
            g = new KJUR.asn1.ASN1Object();
            g.hTLV = i
        }
        if (this.type == null) {
            throw "unsupported type in params=" + k
        }
        this.asn1Obj = new KJUR.asn1.DERTaggedObject({ explicit: this.explicit, tag: a[this.type], obj: g })
    };
    this.getEncodedHex = function() {
        return this.asn1Obj.getEncodedHex()
    };
    if (typeof d != "undefined") { this.setByParam(d) }
};
YAHOO.lang.extend(KJUR.asn1.x509.GeneralName, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.GeneralNames = function(b) {
    KJUR.asn1.x509.GeneralNames.superclass.constructor.call(this);
    var a = null;
    this.setByParamArray = function(e) {
        for (var c = 0; c < e.length; c++) {
            var d = new KJUR.asn1.x509.GeneralName(e[c]);
            this.asn1Array.push(d)
        }
    };
    this.getEncodedHex = function() {
        var c = new KJUR.asn1.DERSequence({ array: this.asn1Array });
        return c.getEncodedHex()
    };
    this.asn1Array = new Array();
    if (typeof b != "undefined") { this.setByParamArray(b) }
};
YAHOO.lang.extend(KJUR.asn1.x509.GeneralNames, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.DistributionPointName = function(b) {
    KJUR.asn1.x509.DistributionPointName.superclass.constructor.call(this);
    var e = null;
    var c = null;
    var a = null;
    var d = null;
    this.getEncodedHex = function() {
        if (this.type != "full") {
            throw "currently type shall be 'full': " + this.type
        }
        this.asn1Obj = new KJUR.asn1.DERTaggedObject({ explicit: false, tag: this.tag, obj: this.asn1V });
        this.hTLV = this.asn1Obj.getEncodedHex();
        return this.hTLV
    };
    if (typeof b != "undefined") {
        if (KJUR.asn1.x509.GeneralNames.prototype.isPrototypeOf(b)) {
            this.type = "full";
            this.tag = "a0";
            this.asn1V = b
        } else {
            throw "This class supports GeneralNames only as argument"
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.DistributionPointName, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.DistributionPoint = function(b) {
    KJUR.asn1.x509.DistributionPoint.superclass.constructor.call(this);
    var a = null;
    this.getEncodedHex = function() {
        var c = new KJUR.asn1.DERSequence();
        if (this.asn1DP != null) {
            var d = new KJUR.asn1.DERTaggedObject({ explicit: true, tag: "a0", obj: this.asn1DP });
            c.appendASN1Object(d)
        }
        this.hTLV = c.getEncodedHex();
        return this.hTLV
    };
    if (typeof b != "undefined") {
        if (typeof b.dpobj != "undefined") { this.asn1DP = b.dpobj }
    }
};
YAHOO.lang.extend(KJUR.asn1.x509.DistributionPoint, KJUR.asn1.ASN1Object);
KJUR.asn1.x509.OID = new function(a) {
    this.atype2oidList = {
        C: "2.5.4.6",
        O: "2.5.4.10",
        OU: "2.5.4.11",
        ST: "2.5.4.8",
        L: "2.5.4.7",
        CN: "2.5.4.3",
        DN: "2.5.4.49",
        DC: "0.9.2342.19200300.100.1.25",
    };
    this.name2oidList = { sha1: "1.3.14.3.2.26", sha256: "2.16.840.1.101.3.4.2.1", sha384: "2.16.840.1.101.3.4.2.2", sha512: "2.16.840.1.101.3.4.2.3", sha224: "2.16.840.1.101.3.4.2.4", md5: "1.2.840.113549.2.5", md2: "1.3.14.7.2.2.1", ripemd160: "1.3.36.3.2.1", MD2withRSA: "1.2.840.113549.1.1.2", MD4withRSA: "1.2.840.113549.1.1.3", MD5withRSA: "1.2.840.113549.1.1.4", SHA1withRSA: "1.2.840.113549.1.1.5", SHA224withRSA: "1.2.840.113549.1.1.14", SHA256withRSA: "1.2.840.113549.1.1.11", SHA384withRSA: "1.2.840.113549.1.1.12", SHA512withRSA: "1.2.840.113549.1.1.13", SHA1withECDSA: "1.2.840.10045.4.1", SHA224withECDSA: "1.2.840.10045.4.3.1", SHA256withECDSA: "1.2.840.10045.4.3.2", SHA384withECDSA: "1.2.840.10045.4.3.3", SHA512withECDSA: "1.2.840.10045.4.3.4", dsa: "1.2.840.10040.4.1", SHA1withDSA: "1.2.840.10040.4.3", SHA224withDSA: "2.16.840.1.101.3.4.3.1", SHA256withDSA: "2.16.840.1.101.3.4.3.2", rsaEncryption: "1.2.840.113549.1.1.1", countryName: "2.5.4.6", organization: "2.5.4.10", organizationalUnit: "2.5.4.11", stateOrProvinceName: "2.5.4.8", locality: "2.5.4.7", commonName: "2.5.4.3", subjectKeyIdentifier: "2.5.29.14", keyUsage: "2.5.29.15", subjectAltName: "2.5.29.17", basicConstraints: "2.5.29.19", nameConstraints: "2.5.29.30", cRLDistributionPoints: "2.5.29.31", certificatePolicies: "2.5.29.32", authorityKeyIdentifier: "2.5.29.35", policyConstraints: "2.5.29.36", extKeyUsage: "2.5.29.37", authorityInfoAccess: "1.3.6.1.5.5.7.1.1", anyExtendedKeyUsage: "2.5.29.37.0", serverAuth: "1.3.6.1.5.5.7.3.1", clientAuth: "1.3.6.1.5.5.7.3.2", codeSigning: "1.3.6.1.5.5.7.3.3", emailProtection: "1.3.6.1.5.5.7.3.4", timeStamping: "1.3.6.1.5.5.7.3.8", ocspSigning: "1.3.6.1.5.5.7.3.9", ecPublicKey: "1.2.840.10045.2.1", secp256r1: "1.2.840.10045.3.1.7", secp256k1: "1.3.132.0.10", secp384r1: "1.3.132.0.34", pkcs5PBES2: "1.2.840.113549.1.5.13", pkcs5PBKDF2: "1.2.840.113549.1.5.12", "des-EDE3-CBC": "1.2.840.113549.3.7", data: "1.2.840.113549.1.7.1", "signed-data": "1.2.840.113549.1.7.2", "enveloped-data": "1.2.840.113549.1.7.3", "digested-data": "1.2.840.113549.1.7.5", "encrypted-data": "1.2.840.113549.1.7.6", "authenticated-data": "1.2.840.113549.1.9.16.1.2", tstinfo: "1.2.840.113549.1.9.16.1.4", };
    this.objCache = {};
    this.name2obj = function(b) {
        if (typeof this.objCache[b] != "undefined") {
            return this.objCache[b]
        }
        if (typeof this.name2oidList[b] == "undefined") {
            throw "Name of ObjectIdentifier not defined: " + b
        }
        var c = this.name2oidList[b];
        var d = new KJUR.asn1.DERObjectIdentifier({ oid: c });
        this.objCache[b] = d;
        return d
    };
    this.atype2obj = function(b) {
        if (typeof this.objCache[b] != "undefined") {
            return this.objCache[b]
        }
        if (typeof this.atype2oidList[b] == "undefined") {
            throw "AttributeType name undefined: " + b
        }
        var c = this.atype2oidList[b];
        var d = new KJUR.asn1.DERObjectIdentifier({ oid: c });
        this.objCache[b] = d;
        return d
    }
};
KJUR.asn1.x509.OID.oid2name = function(b) {
    var c = KJUR.asn1.x509.OID.name2oidList;
    for (var a in c) {
        if (c[a] == b) {
            return a
        }
    }
    return ""
};
KJUR.asn1.x509.OID.name2oid = function(a) {
    var b = KJUR.asn1.x509.OID.name2oidList;
    if (b[a] === undefined) {
        return ""
    }
    return b[a]
};
KJUR.asn1.x509.X509Util = new function() {
    this.getPKCS8PubKeyPEMfromRSAKey = function(i) {
        var h = null;
        var f = KJUR.asn1.ASN1Util.bigIntToMinTwosComplementsHex(i.n);
        var j = KJUR.asn1.ASN1Util.integerToByteHex(i.e);
        var a = new KJUR.asn1.DERInteger({ hex: f });
        var g = new KJUR.asn1.DERInteger({ hex: j });
        var l = new KJUR.asn1.DERSequence({ array: [a, g] });
        var c = l.getEncodedHex();
        var d = new KJUR.asn1.x509.AlgorithmIdentifier({ name: "rsaEncryption" });
        var b = new KJUR.asn1.DERBitString({ hex: "00" + c });
        var k = new KJUR.asn1.DERSequence({ array: [d, b] });
        var e = k.getEncodedHex();
        var h = KJUR.asn1.ASN1Util.getPEMStringFromHex(e, "PUBLIC KEY");
        return h
    }
};
KJUR.asn1.x509.X509Util.newCertPEM = function(f) {
    var c = KJUR.asn1.x509;
    var e = new c.TBSCertificate();
    if (f.serial !== undefined) { e.setSerialNumberByParam(f.serial) } else {
        throw "serial number undefined."
    }
    if (typeof f.sigalg.name == "string") { e.setSignatureAlgByParam(f.sigalg) } else {
        throw "unproper signature algorithm name"
    }
    if (f.issuer !== undefined) { e.setIssuerByParam(f.issuer) } else {
        throw "issuer name undefined."
    }
    if (f.notbefore !== undefined) { e.setNotBeforeByParam(f.notbefore) } else {
        throw "notbefore undefined."
    }
    if (f.notafter !== undefined) { e.setNotAfterByParam(f.notafter) } else {
        throw "notafter undefined."
    }
    if (f.subject !== undefined) { e.setSubjectByParam(f.subject) } else {
        throw "subject name undefined."
    }
    if (f.sbjpubkey !== undefined) { e.setSubjectPublicKeyByGetKey(f.sbjpubkey) } else {
        throw "subject public key undefined."
    }
    if (f.ext !== undefined && f.ext.length !== undefined) {
        for (var b = 0; b < f.ext.length; b++) {
            for (key in f.ext[b]) { e.appendExtensionByName(key, f.ext[b][key]) }
        }
    }
    if (f.cakey === undefined && f.sighex === undefined) {
        throw "param cakey and sighex undefined."
    }
    var d = null;
    var a = null;
    if (f.cakey) {
        d = KEYUTIL.getKey.apply(null, f.cakey);
        a = new c.Certificate({ tbscertobj: e, prvkeyobj: d });
        a.sign()
    }
    if (f.sighex) {
        a = new c.Certificate({ tbscertobj: e });
        a.setSignatureHex(f.sighex)
    }
    return a.getPEMString()
};
/*! asn1cms-1.0.2.js (c) 2013-2014 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
if (typeof KJUR == "undefined" || !KJUR) { KJUR = {} }
if (typeof KJUR.asn1 == "undefined" || !KJUR.asn1) { KJUR.asn1 = {} }
if (typeof KJUR.asn1.cms == "undefined" || !KJUR.asn1.cms) { KJUR.asn1.cms = {} }
KJUR.asn1.cms.Attribute = function(b) {
    KJUR.asn1.cms.Attribute.superclass.constructor.call(this);
    var a = [];
    this.getEncodedHex = function() {
        var f, e, c;
        f = new KJUR.asn1.DERObjectIdentifier({ oid: this.attrTypeOid });
        e = new KJUR.asn1.DERSet({ array: this.valueList });
        try { e.getEncodedHex() } catch (d) {
            throw "fail valueSet.getEncodedHex in Attribute(1)/" + d
        }
        c = new KJUR.asn1.DERSequence({ array: [f, e] });
        try { this.hTLV = c.getEncodedHex() } catch (d) {
            throw "failed seq.getEncodedHex in Attribute(2)/" + d
        }
        return this.hTLV
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.Attribute, KJUR.asn1.ASN1Object);
KJUR.asn1.cms.ContentType = function(b) {
    KJUR.asn1.cms.ContentType.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.3";
    var a = null;
    if (typeof b != "undefined") {
        var a = new KJUR.asn1.DERObjectIdentifier(b);
        this.valueList = [a]
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.ContentType, KJUR.asn1.cms.Attribute);
KJUR.asn1.cms.MessageDigest = function(e) {
    KJUR.asn1.cms.MessageDigest.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.4";
    if (typeof e != "undefined") {
        if (e.eciObj instanceof KJUR.asn1.cms.EncapsulatedContentInfo && typeof e.hashAlg == "string") {
            var b = e.eciObj.eContentValueHex;
            var a = e.hashAlg;
            var c = KJUR.crypto.Util.hashHex(b, a);
            var d = new KJUR.asn1.DEROctetString({ hex: c });
            d.getEncodedHex();
            this.valueList = [d]
        } else {
            var d = new KJUR.asn1.DEROctetString(e);
            d.getEncodedHex();
            this.valueList = [d]
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.MessageDigest, KJUR.asn1.cms.Attribute);
KJUR.asn1.cms.SigningTime = function(c) {
    KJUR.asn1.cms.SigningTime.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.5";
    if (typeof c != "undefined") {
        var a = new KJUR.asn1.x509.Time(c);
        try { a.getEncodedHex() } catch (b) {
            throw "SigningTime.getEncodedHex() failed/" + b
        }
        this.valueList = [a]
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.SigningTime, KJUR.asn1.cms.Attribute);
KJUR.asn1.cms.SigningCertificate = function(d) {
    KJUR.asn1.cms.SigningCertificate.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.16.2.12";
    var a = KJUR.asn1;
    var c = KJUR.asn1.cms;
    var b = KJUR.crypto;
    this.setCerts = function(l) {
        var j = [];
        for (var h = 0; h < l.length; h++) {
            var f = KEYUTIL.getHexFromPEM(l[h]);
            var e = b.Util.hashHex(f, "sha1");
            var m = new a.DEROctetString({ hex: e });
            m.getEncodedHex();
            var k = new c.IssuerAndSerialNumber({ cert: l[h] });
            k.getEncodedHex();
            var n = new a.DERSequence({ array: [m, k] });
            n.getEncodedHex();
            j.push(n)
        }
        var g = new a.DERSequence({ array: j });
        g.getEncodedHex();
        this.valueList = [g]
    };
    if (typeof d != "undefined") {
        if (typeof d.array == "object") { this.setCerts(d.array) }
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.SigningCertificate, KJUR.asn1.cms.Attribute);
KJUR.asn1.cms.SigningCertificateV2 = function(e) {
    KJUR.asn1.cms.SigningCertificateV2.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.16.2.47";
    var b = KJUR.asn1;
    var f = KJUR.asn1.x509;
    var d = KJUR.asn1.cms;
    var c = KJUR.crypto;
    this.setCerts = function(p, h) {
        var n = [];
        for (var l = 0; l < p.length; l++) {
            var j = KEYUTIL.getHexFromPEM(p[l]);
            var r = [];
            if (h != "sha256") { r.push(new f.AlgorithmIdentifier({ name: h })) }
            var g = c.Util.hashHex(j, h);
            var q = new b.DEROctetString({ hex: g });
            q.getEncodedHex();
            r.push(q);
            var m = new d.IssuerAndSerialNumber({ cert: p[l] });
            m.getEncodedHex();
            r.push(m);
            var o = new b.DERSequence({ array: r });
            o.getEncodedHex();
            n.push(o)
        }
        var k = new b.DERSequence({ array: n });
        k.getEncodedHex();
        this.valueList = [k]
    };
    if (typeof e != "undefined") {
        if (typeof e.array == "object") {
            var a = "sha256";
            if (typeof e.hashAlg == "string") { a = e.hashAlg }
            this.setCerts(e.array, a)
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.SigningCertificateV2, KJUR.asn1.cms.Attribute);
KJUR.asn1.cms.IssuerAndSerialNumber = function(c) {
    KJUR.asn1.cms.IssuerAndSerialNumber.superclass.constructor.call(this);
    var e = null;
    var b = null;
    var a = KJUR.asn1;
    var d = a.x509;
    this.setByCertPEM = function(i) {
        var g = KEYUTIL.getHexFromPEM(i);
        var f = new X509();
        f.hex = g;
        var j = f.getIssuerHex();
        this.dIssuer = new d.X500Name();
        this.dIssuer.hTLV = j;
        var h = f.getSerialNumberHex();
        this.dSerial = new a.DERInteger({ hex: h })
    };
    this.getEncodedHex = function() {
        var f = new KJUR.asn1.DERSequence({ array: [this.dIssuer, this.dSerial] });
        this.hTLV = f.getEncodedHex();
        return this.hTLV
    };
    if (typeof c != "undefined") {
        if (typeof c == "string" && c.indexOf("-----BEGIN ") != -1) { this.setByCertPEM(c) }
        if (c.issuer && c.serial) {
            if (c.issuer instanceof KJUR.asn1.x509.X500Name) { this.dIssuer = c.issuer } else { this.dIssuer = new KJUR.asn1.x509.X500Name(c.issuer) }
            if (c.serial instanceof KJUR.asn1.DERInteger) { this.dSerial = c.serial } else { this.dSerial = new KJUR.asn1.DERInteger(c.serial) }
        }
        if (typeof c.cert == "string") { this.setByCertPEM(c.cert) }
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.IssuerAndSerialNumber, KJUR.asn1.ASN1Object);
KJUR.asn1.cms.AttributeList = function(a) {
    KJUR.asn1.cms.AttributeList.superclass.constructor.call(this);
    this.list = new Array();
    this.sortFlag = true;
    this.add = function(b) {
        if (b instanceof KJUR.asn1.cms.Attribute) { this.list.push(b) }
    };
    this.length = function() {
        return this.list.length
    };
    this.clear = function() {
        this.list = new Array();
        this.hTLV = null;
        this.hV = null
    };
    this.getEncodedHex = function() {
        if (typeof this.hTLV == "string") {
            return this.hTLV
        }
        var b = new KJUR.asn1.DERSet({ array: this.list, sortflag: this.sortFlag });
        this.hTLV = b.getEncodedHex();
        return this.hTLV
    };
    if (typeof a != "undefined") {
        if (typeof a.sortflag != "undefined" && a.sortflag == false) { this.sortFlag = false }
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.AttributeList, KJUR.asn1.ASN1Object);
KJUR.asn1.cms.SignerInfo = function(c) {
    KJUR.asn1.cms.SignerInfo.superclass.constructor.call(this);
    var a = KJUR.asn1;
    var b = KJUR.asn1.cms;
    var d = KJUR.asn1.x509;
    this.dCMSVersion = new a.DERInteger({ "int": 1 });
    this.dSignerIdentifier = null;
    this.dDigestAlgorithm = null;
    this.dSignedAttrs = new b.AttributeList();
    this.dSigAlg = null;
    this.dSig = null;
    this.dUnsignedAttrs = new b.AttributeList();
    this.setSignerIdentifier = function(f) {
        if (typeof f == "string" && f.indexOf("CERTIFICATE") != -1 && f.indexOf("BEGIN") != -1 && f.indexOf("END") != -1) {
            var e = f;
            this.dSignerIdentifier = new b.IssuerAndSerialNumber({ cert: f })
        }
    };
    this.setForContentAndHash = function(e) {
        if (typeof e != "undefined") {
            if (e.eciObj instanceof KJUR.asn1.cms.EncapsulatedContentInfo) {
                this.dSignedAttrs.add(new b.ContentType({ oid: "1.2.840.113549.1.7.1" }));
                this.dSignedAttrs.add(new b.MessageDigest({ eciObj: e.eciObj, hashAlg: e.hashAlg }))
            }
            if (typeof e.sdObj != "undefined" && e.sdObj instanceof KJUR.asn1.cms.SignedData) {
                if (e.sdObj.digestAlgNameList.join(":").indexOf(e.hashAlg) == -1) { e.sdObj.digestAlgNameList.push(e.hashAlg) }
            }
            if (typeof e.hashAlg == "string") { this.dDigestAlgorithm = new d.AlgorithmIdentifier({ name: e.hashAlg }) }
        }
    };
    this.sign = function(j, f) {
        this.dSigAlg = new d.AlgorithmIdentifier({ name: f });
        var g = this.dSignedAttrs.getEncodedHex();
        var e = KEYUTIL.getKey(j);
        var i = new KJUR.crypto.Signature({ alg: f });
        i.init(e);
        i.updateHex(g);
        var h = i.sign();
        this.dSig = new a.DEROctetString({ hex: h })
    };
    this.addUnsigned = function(e) {
        this.hTLV = null;
        this.dUnsignedAttrs.hTLV = null;
        this.dUnsignedAttrs.add(e)
    };
    this.getEncodedHex = function() {
        if (this.dSignedAttrs instanceof KJUR.asn1.cms.AttributeList && this.dSignedAttrs.length() == 0) {
            throw "SignedAttrs length = 0 (empty)"
        }
        var e = new a.DERTaggedObject({ obj: this.dSignedAttrs, tag: "a0", explicit: false });
        var h = null;
        if (this.dUnsignedAttrs.length() > 0) { h = new a.DERTaggedObject({ obj: this.dUnsignedAttrs, tag: "a1", explicit: false }) }
        var g = [this.dCMSVersion, this.dSignerIdentifier, this.dDigestAlgorithm, e, this.dSigAlg, this.dSig, ];
        if (h != null) { g.push(h) }
        var f = new a.DERSequence({ array: g });
        this.hTLV = f.getEncodedHex();
        return this.hTLV
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.SignerInfo, KJUR.asn1.ASN1Object);
KJUR.asn1.cms.EncapsulatedContentInfo = function(c) {
    KJUR.asn1.cms.EncapsulatedContentInfo.superclass.constructor.call(this);
    var a = KJUR.asn1;
    var b = KJUR.asn1.cms;
    var d = KJUR.asn1.x509;
    this.dEContentType = new a.DERObjectIdentifier({ name: "data" });
    this.dEContent = null;
    this.isDetached = false;
    this.eContentValueHex = null;
    this.setContentType = function(e) {
        if (e.match(/^[0-2][.][0-9.]+$/)) { this.dEContentType = new a.DERObjectIdentifier({ oid: e }) } else { this.dEContentType = new a.DERObjectIdentifier({ name: e }) }
    };
    this.setContentValue = function(e) {
        if (typeof e != "undefined") {
            if (typeof e.hex == "string") { this.eContentValueHex = e.hex } else {
                if (typeof e.str == "string") { this.eContentValueHex = utf8tohex(e.str) }
            }
        }
    };
    this.setContentValueHex = function(e) { this.eContentValueHex = e };
    this.setContentValueStr = function(e) { this.eContentValueHex = utf8tohex(e) };
    this.getEncodedHex = function() {
        if (typeof this.eContentValueHex != "string") {
            throw "eContentValue not yet set"
        }
        var g = new a.DEROctetString({ hex: this.eContentValueHex });
        this.dEContent = new a.DERTaggedObject({ obj: g, tag: "a0", explicit: true });
        var e = [this.dEContentType];
        if (!this.isDetached) { e.push(this.dEContent) }
        var f = new a.DERSequence({ array: e });
        this.hTLV = f.getEncodedHex();
        return this.hTLV
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.EncapsulatedContentInfo, KJUR.asn1.ASN1Object);
KJUR.asn1.cms.ContentInfo = function(c) {
    KJUR.asn1.cms.ContentInfo.superclass.constructor.call(this);
    var a = KJUR.asn1;
    var b = KJUR.asn1.cms;
    var d = KJUR.asn1.x509;
    this.dContentType = null;
    this.dContent = null;
    this.setContentType = function(e) {
        if (typeof e == "string") { this.dContentType = d.OID.name2obj(e) }
    };
    this.getEncodedHex = function() {
        var f = new a.DERTaggedObject({ obj: this.dContent, tag: "a0", explicit: true });
        var e = new a.DERSequence({ array: [this.dContentType, f] });
        this.hTLV = e.getEncodedHex();
        return this.hTLV
    };
    if (typeof c != "undefined") {
        if (c.type) { this.setContentType(c.type) }
        if (c.obj && c.obj instanceof a.ASN1Object) { this.dContent = c.obj }
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.ContentInfo, KJUR.asn1.ASN1Object);
KJUR.asn1.cms.SignedData = function(c) {
    KJUR.asn1.cms.SignedData.superclass.constructor.call(this);
    var a = KJUR.asn1;
    var b = KJUR.asn1.cms;
    var d = KJUR.asn1.x509;
    this.dCMSVersion = new a.DERInteger({ "int": 1 });
    this.dDigestAlgs = null;
    this.digestAlgNameList = [];
    this.dEncapContentInfo = new b.EncapsulatedContentInfo();
    this.dCerts = null;
    this.certificateList = [];
    this.crlList = [];
    this.signerInfoList = [new b.SignerInfo()];
    this.addCertificatesByPEM = function(e) {
        var f = KEYUTIL.getHexFromPEM(e);
        var g = new a.ASN1Object();
        g.hTLV = f;
        this.certificateList.push(g)
    };
    this.getEncodedHex = function() {
        if (typeof this.hTLV == "string") {
            return this.hTLV
        }
        if (this.dDigestAlgs == null) {
            var k = [];
            for (var j = 0; j < this.digestAlgNameList.length; j++) {
                var h = this.digestAlgNameList[j];
                var m = new d.AlgorithmIdentifier({ name: h });
                k.push(m)
            }
            this.dDigestAlgs = new a.DERSet({ array: k })
        }
        var e = [this.dCMSVersion, this.dDigestAlgs, this.dEncapContentInfo];
        if (this.dCerts == null) {
            if (this.certificateList.length > 0) {
                var l = new a.DERSet({ array: this.certificateList });
                this.dCerts = new a.DERTaggedObject({ obj: l, tag: "a0", explicit: false })
            }
        }
        if (this.dCerts != null) { e.push(this.dCerts) }
        var g = new a.DERSet({ array: this.signerInfoList });
        e.push(g);
        var f = new a.DERSequence({ array: e });
        this.hTLV = f.getEncodedHex();
        return this.hTLV
    };
    this.getContentInfo = function() {
        this.getEncodedHex();
        var e = new b.ContentInfo({ type: "signed-data", obj: this });
        return e
    };
    this.getContentInfoEncodedHex = function() {
        var e = this.getContentInfo();
        var f = e.getEncodedHex();
        return f
    };
    this.getPEM = function() {
        var e = this.getContentInfoEncodedHex();
        var f = a.ASN1Util.getPEMStringFromHex(e, "CMS");
        return f
    }
};
YAHOO.lang.extend(KJUR.asn1.cms.SignedData, KJUR.asn1.ASN1Object);
KJUR.asn1.cms.CMSUtil = new function() {};
KJUR.asn1.cms.CMSUtil.newSignedData = function(a) {
    var h = KJUR.asn1.cms;
    var g = KJUR.asn1.cades;
    var f = new h.SignedData();
    f.dEncapContentInfo.setContentValue(a.content);
    if (typeof a.certs == "object") {
        for (var b = 0; b < a.certs.length; b++) { f.addCertificatesByPEM(a.certs[b]) }
    }
    f.signerInfoList = [];
    for (var b = 0; b < a.signerInfos.length; b++) {
        var d = a.signerInfos[b];
        var c = new h.SignerInfo();
        c.setSignerIdentifier(d.signerCert);
        c.setForContentAndHash({ sdObj: f, eciObj: f.dEncapContentInfo, hashAlg: d.hashAlg });
        for (attrName in d.sAttr) {
            var j = d.sAttr[attrName];
            if (attrName == "SigningTime") {
                var e = new h.SigningTime(j);
                c.dSignedAttrs.add(e)
            }
            if (attrName == "SigningCertificate") {
                var e = new h.SigningCertificate(j);
                c.dSignedAttrs.add(e)
            }
            if (attrName == "SigningCertificateV2") {
                var e = new h.SigningCertificateV2(j);
                c.dSignedAttrs.add(e)
            }
            if (attrName == "SignaturePolicyIdentifier") {
                var e = new g.SignaturePolicyIdentifier(j);
                c.dSignedAttrs.add(e)
            }
        }
        c.sign(d.signerPrvKey, d.sigAlg);
        f.signerInfoList.push(c)
    }
    return f
};
/*! asn1tsp-1.0.1.js (c) 2014 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
if (typeof KJUR == "undefined" || !KJUR) { KJUR = {} }
if (typeof KJUR.asn1 == "undefined" || !KJUR.asn1) { KJUR.asn1 = {} }
if (typeof KJUR.asn1.tsp == "undefined" || !KJUR.asn1.tsp) { KJUR.asn1.tsp = {} }
KJUR.asn1.tsp.Accuracy = function(b) {
    KJUR.asn1.tsp.Accuracy.superclass.constructor.call(this);
    var a = KJUR.asn1;
    this.seconds = null;
    this.millis = null;
    this.micros = null;
    this.getEncodedHex = function() {
        var e = null;
        var g = null;
        var i = null;
        var c = [];
        if (this.seconds != null) {
            e = new a.DERInteger({ "int": this.seconds });
            c.push(e)
        }
        if (this.millis != null) {
            var h = new a.DERInteger({ "int": this.millis });
            g = new a.DERTaggedObject({ obj: h, tag: "80", explicit: false });
            c.push(g)
        }
        if (this.micros != null) {
            var f = new a.DERInteger({ "int": this.micros });
            i = new a.DERTaggedObject({ obj: f, tag: "81", explicit: false });
            c.push(i)
        }
        var d = new a.DERSequence({ array: c });
        this.hTLV = d.getEncodedHex();
        return this.hTLV
    };
    if (typeof b != "undefined") {
        if (typeof b.seconds == "number") { this.seconds = b.seconds }
        if (typeof b.millis == "number") { this.millis = b.millis }
        if (typeof b.micros == "number") { this.micros = b.micros }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.Accuracy, KJUR.asn1.ASN1Object);
KJUR.asn1.tsp.MessageImprint = function(b) {
    KJUR.asn1.tsp.MessageImprint.superclass.constructor.call(this);
    var a = KJUR.asn1;
    var c = KJUR.asn1.x509;
    this.dHashAlg = null;
    this.dHashValue = null;
    this.getEncodedHex = function() {
        if (typeof this.hTLV == "string") {
            return this.hTLV
        }
        var d = new a.DERSequence({ array: [this.dHashAlg, this.dHashValue] });
        return d.getEncodedHex()
    };
    if (typeof b != "undefined") {
        if (typeof b.hashAlg == "string") { this.dHashAlg = new c.AlgorithmIdentifier({ name: b.hashAlg }) }
        if (typeof b.hashValue == "string") { this.dHashValue = new a.DEROctetString({ hex: b.hashValue }) }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.MessageImprint, KJUR.asn1.ASN1Object);
KJUR.asn1.tsp.TimeStampReq = function(c) {
    KJUR.asn1.tsp.TimeStampReq.superclass.constructor.call(this);
    var a = KJUR.asn1;
    var b = KJUR.asn1.tsp;
    this.dVersion = new a.DERInteger({ "int": 1 });
    this.dMessageImprint = null;
    this.dPolicy = null;
    this.dNonce = null;
    this.certReq = true;
    this.setMessageImprint = function(d) {
        if (d instanceof KJUR.asn1.tsp.MessageImprint) {
            this.dMessageImprint = d;
            return
        }
        if (typeof d == "object") { this.dMessageImprint = new b.MessageImprint(d) }
    };
    this.getEncodedHex = function() {
        if (this.dMessageImprint == null) {
            throw "messageImprint shall be specified"
        }
        var d = [this.dVersion, this.dMessageImprint];
        if (this.dPolicy != null) { d.push(this.dPolicy) }
        if (this.dNonce != null) { d.push(this.dNonce) }
        if (this.certReq) { d.push(new a.DERBoolean()) }
        var e = new a.DERSequence({ array: d });
        this.hTLV = e.getEncodedHex();
        return this.hTLV
    };
    if (typeof c != "undefined") {
        if (typeof c.mi == "object") { this.setMessageImprint(c.mi) }
        if (typeof c.policy == "object") { this.dPolicy = new a.DERObjectIdentifier(c.policy) }
        if (typeof c.nonce == "object") { this.dNonce = new a.DERInteger(c.nonce) }
        if (typeof c.certreq == "boolean") { this.certReq = c.certreq }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.TimeStampReq, KJUR.asn1.ASN1Object);
KJUR.asn1.tsp.TSTInfo = function(c) {
    KJUR.asn1.tsp.TSTInfo.superclass.constructor.call(this);
    var a = KJUR.asn1;
    var d = KJUR.asn1.x509;
    var b = KJUR.asn1.tsp;
    this.dVersion = new a.DERInteger({ "int": 1 });
    this.dPolicy = null;
    this.dMessageImprint = null;
    this.dSerialNumber = null;
    this.dGenTime = null;
    this.dAccuracy = null;
    this.dOrdering = null;
    this.dNonce = null;
    this.dTsa = null;
    this.getEncodedHex = function() {
        var e = [this.dVersion];
        if (this.dPolicy == null) {
            throw "policy shall be specified."
        }
        e.push(this.dPolicy);
        if (this.dMessageImprint == null) {
            throw "messageImprint shall be specified."
        }
        e.push(this.dMessageImprint);
        if (this.dSerialNumber == null) {
            throw "serialNumber shall be specified."
        }
        e.push(this.dSerialNumber);
        if (this.dGenTime == null) {
            throw "genTime shall be specified."
        }
        e.push(this.dGenTime);
        if (this.dAccuracy != null) { e.push(this.dAccuracy) }
        if (this.dOrdering != null) { e.push(this.dOrdering) }
        if (this.dNonce != null) { e.push(this.dNonce) }
        if (this.dTsa != null) { e.push(this.dTsa) }
        var f = new a.DERSequence({ array: e });
        this.hTLV = f.getEncodedHex();
        return this.hTLV
    };
    if (typeof c != "undefined") {
        if (typeof c.policy == "string") {
            if (!c.policy.match(/^[0-9.]+$/)) {
                throw "policy shall be oid like 0.1.4.134"
            }
            this.dPolicy = new a.DERObjectIdentifier({ oid: c.policy })
        }
        if (typeof c.messageImprint != "undefined") { this.dMessageImprint = new b.MessageImprint(c.messageImprint) }
        if (typeof c.serialNumber != "undefined") { this.dSerialNumber = new a.DERInteger(c.serialNumber) }
        if (typeof c.genTime != "undefined") { this.dGenTime = new a.DERGeneralizedTime(c.genTime) }
        if (typeof c.accuracy != "undefind") { this.dAccuracy = new b.Accuracy(c.accuracy) }
        if (typeof c.ordering != "undefined" && c.ordering == true) { this.dOrdering = new a.DERBoolean() }
        if (typeof c.nonce != "undefined") { this.dNonce = new a.DERInteger(c.nonce) }
        if (typeof c.tsa != "undefined") { this.dTsa = new d.X500Name(c.tsa) }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.TSTInfo, KJUR.asn1.ASN1Object);
KJUR.asn1.tsp.TimeStampResp = function(c) {
    KJUR.asn1.tsp.TimeStampResp.superclass.constructor.call(this);
    var a = KJUR.asn1;
    var b = KJUR.asn1.tsp;
    this.dStatus = null;
    this.dTST = null;
    this.getEncodedHex = function() {
        if (this.dStatus == null) {
            throw "status shall be specified"
        }
        var d = [this.dStatus];
        if (this.dTST != null) { d.push(this.dTST) }
        var e = new a.DERSequence({ array: d });
        this.hTLV = e.getEncodedHex();
        return this.hTLV
    };
    if (typeof c != "undefined") {
        if (typeof c.status == "object") { this.dStatus = new b.PKIStatusInfo(c.status) }
        if (typeof c.tst != "undefined" && c.tst instanceof KJUR.asn1.ASN1Object) { this.dTST = c.tst.getContentInfo() }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.TimeStampResp, KJUR.asn1.ASN1Object);
KJUR.asn1.tsp.PKIStatusInfo = function(c) {
    KJUR.asn1.tsp.PKIStatusInfo.superclass.constructor.call(this);
    var a = KJUR.asn1;
    var b = KJUR.asn1.tsp;
    this.dStatus = null;
    this.dStatusString = null;
    this.dFailureInfo = null;
    this.getEncodedHex = function() {
        if (this.dStatus == null) {
            throw "status shall be specified"
        }
        var d = [this.dStatus];
        if (this.dStatusString != null) { d.push(this.dStatusString) }
        if (this.dFailureInfo != null) { d.push(this.dFailureInfo) }
        var e = new a.DERSequence({ array: d });
        this.hTLV = e.getEncodedHex();
        return this.hTLV
    };
    if (typeof c != "undefined") {
        if (typeof c.status == "object") { this.dStatus = new b.PKIStatus(c.status) }
        if (typeof c.statstr == "object") { this.dStatusString = new b.PKIFreeText({ array: c.statstr }) }
        if (typeof c.failinfo == "object") { this.dFailureInfo = new b.PKIFailureInfo(c.failinfo) }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.PKIStatusInfo, KJUR.asn1.ASN1Object);
KJUR.asn1.tsp.PKIStatus = function(e) {
    KJUR.asn1.tsp.PKIStatus.superclass.constructor.call(this);
    var a = KJUR.asn1;
    var b = KJUR.asn1.tsp;
    var d = null;
    this.getEncodedHex = function() {
        this.hTLV = this.dStatus.getEncodedHex();
        return this.hTLV
    };
    if (typeof e != "undefined") {
        if (typeof e.name != "undefined") {
            var c = b.PKIStatus.valueList;
            if (typeof c[e.name] == "undefined") {
                throw "name undefined: " + e.name
            }
            this.dStatus = new a.DERInteger({ "int": c[e.name] })
        } else { this.dStatus = new a.DERInteger(e) }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.PKIStatus, KJUR.asn1.ASN1Object);
KJUR.asn1.tsp.PKIStatus.valueList = { granted: 0, grantedWithMods: 1, rejection: 2, waiting: 3, revocationWarning: 4, revocationNotification: 5 };
KJUR.asn1.tsp.PKIFreeText = function(b) {
    KJUR.asn1.tsp.PKIFreeText.superclass.constructor.call(this);
    var a = KJUR.asn1;
    this.textList = [];
    this.getEncodedHex = function() {
        var c = [];
        for (var e = 0; e < this.textList.length; e++) { c.push(new a.DERUTF8String({ str: this.textList[e] })) }
        var d = new a.DERSequence({ array: c });
        this.hTLV = d.getEncodedHex();
        return this.hTLV
    };
    if (typeof b != "undefined") {
        if (typeof b.array == "object") { this.textList = b.array }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.PKIFreeText, KJUR.asn1.ASN1Object);
KJUR.asn1.tsp.PKIFailureInfo = function(d) {
    KJUR.asn1.tsp.PKIFailureInfo.superclass.constructor.call(this);
    var a = KJUR.asn1;
    var b = KJUR.asn1.tsp;
    this.value = null;
    this.getEncodedHex = function() {
        if (this.value == null) {
            throw "value shall be specified"
        }
        var e = new Number(this.value).toString(2);
        var f = new a.DERBitString();
        f.setByBinaryString(e);
        this.hTLV = f.getEncodedHex();
        return this.hTLV
    };
    if (typeof d != "undefined") {
        if (typeof d.name == "string") {
            var c = b.PKIFailureInfo.valueList;
            if (typeof c[d.name] == "undefined") {
                throw "name undefined: " + d.name
            }
            this.value = c[d.name]
        } else {
            if (typeof d["int"] == "number") { this.value = d["int"] }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.tsp.PKIFailureInfo, KJUR.asn1.ASN1Object);
KJUR.asn1.tsp.PKIFailureInfo.valueList = { badAlg: 0, badRequest: 2, badDataFormat: 5, timeNotAvailable: 14, unacceptedPolicy: 15, unacceptedExtension: 16, addInfoNotAvailable: 17, systemFailure: 25 };
KJUR.asn1.tsp.AbstractTSAAdapter = function(a) {
    this.getTSTHex = function(c, b) {
        throw "not implemented yet"
    }
};
KJUR.asn1.tsp.SimpleTSAAdapter = function(a) {
    KJUR.asn1.tsp.SimpleTSAAdapter.superclass.constructor.call(this);
    this.params = null;
    this.serial = 0;
    this.getTSTHex = function(c, b) {
        var e = KJUR.crypto.Util.hashHex(c, b);
        this.params.tstInfo.messageImprint = { hashAlg: b, hashValue: e };
        this.params.tstInfo.serialNumber = { "int": this.serial++ };
        var d = Math.floor(Math.random() * 1000000000);
        this.params.tstInfo.nonce = { "int": d };
        var f = KJUR.asn1.tsp.TSPUtil.newTimeStampToken(this.params);
        return f.getContentInfoEncodedHex()
    };
    if (typeof a != "undefined") { this.params = a }
};
YAHOO.lang.extend(KJUR.asn1.tsp.SimpleTSAAdapter, KJUR.asn1.tsp.AbstractTSAAdapter);
KJUR.asn1.tsp.FixedTSAAdapter = function(a) {
    KJUR.asn1.tsp.FixedTSAAdapter.superclass.constructor.call(this);
    this.params = null;
    this.getTSTHex = function(c, b) {
        var d = KJUR.crypto.Util.hashHex(c, b);
        this.params.tstInfo.messageImprint = { hashAlg: b, hashValue: d };
        var e = KJUR.asn1.tsp.TSPUtil.newTimeStampToken(this.params);
        return e.getContentInfoEncodedHex()
    };
    if (typeof a != "undefined") { this.params = a }
};
YAHOO.lang.extend(KJUR.asn1.tsp.FixedTSAAdapter, KJUR.asn1.tsp.AbstractTSAAdapter);
KJUR.asn1.tsp.TSPUtil = new function() {};
KJUR.asn1.tsp.TSPUtil.newTimeStampToken = function(b) {
    var j = KJUR.asn1.cms;
    var a = KJUR.asn1.tsp;
    var g = new j.SignedData();
    var e = new a.TSTInfo(b.tstInfo);
    var f = e.getEncodedHex();
    g.dEncapContentInfo.setContentValue({ hex: f });
    g.dEncapContentInfo.setContentType("tstinfo");
    if (typeof b.certs == "object") {
        for (var c = 0; c < b.certs.length; c++) { g.addCertificatesByPEM(b.certs[c]) }
    }
    var d = g.signerInfoList[0];
    d.setSignerIdentifier(b.signerCert);
    d.setForContentAndHash({ sdObj: g, eciObj: g.dEncapContentInfo, hashAlg: b.hashAlg });
    var h = new j.SigningCertificate({ array: [b.signerCert] });
    d.dSignedAttrs.add(h);
    d.sign(b.signerPrvKey, b.sigAlg);
    return g
};
KJUR.asn1.tsp.TSPUtil.parseTimeStampReq = function(d) {
    var f = {};
    f.certreq = false;
    var h = ASN1HEX.getPosArrayOfChildren_AtObj(d, 0);
    if (h.length < 2) {
        throw "TimeStampReq must have at least 2 items"
    }
    var c = ASN1HEX.getHexOfTLV_AtObj(d, h[1]);
    f.mi = KJUR.asn1.tsp.TSPUtil.parseMessageImprint(c);
    for (var e = 2; e < h.length; e++) {
        var b = h[e];
        var a = d.substr(b, 2);
        if (a == "06") {
            var g = ASN1HEX.getHexOfV_AtObj(d, b);
            f.policy = ASN1HEX.hextooidstr(g)
        }
        if (a == "02") { f.nonce = ASN1HEX.getHexOfV_AtObj(d, b) }
        if (a == "01") { f.certreq = true }
    }
    return f
};
KJUR.asn1.tsp.TSPUtil.parseMessageImprint = function(c) {
    var h = {};
    if (c.substr(0, 2) != "30") {
        throw "head of messageImprint hex shall be '30'"
    }
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(c, 0);
    var i = ASN1HEX.getDecendantIndexByNthList(c, 0, [0, 0]);
    var d = ASN1HEX.getHexOfV_AtObj(c, i);
    var e = ASN1HEX.hextooidstr(d);
    var g = KJUR.asn1.x509.OID.oid2name(e);
    if (g == "") {
        throw "hashAlg name undefined: " + e
    }
    var b = g;
    var f = ASN1HEX.getDecendantIndexByNthList(c, 0, [1]);
    h.hashAlg = b;
    h.hashValue = ASN1HEX.getHexOfV_AtObj(c, f);
    return h
};
/*! asn1cades-1.0.0.js (c) 2013-2014 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
if (typeof KJUR == "undefined" || !KJUR) { KJUR = {} }
if (typeof KJUR.asn1 == "undefined" || !KJUR.asn1) { KJUR.asn1 = {} }
if (typeof KJUR.asn1.cades == "undefined" || !KJUR.asn1.cades) { KJUR.asn1.cades = {} }
KJUR.asn1.cades.SignaturePolicyIdentifier = function(e) {
    KJUR.asn1.cades.SignaturePolicyIdentifier.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.16.2.15";
    var b = KJUR.asn1;
    var d = KJUR.asn1.cades;
    if (typeof e != "undefined") {
        if (typeof e.oid == "string" && typeof e.hash == "object") {
            var f = new b.DERObjectIdentifier({ oid: e.oid });
            var a = new d.OtherHashAlgAndValue(e.hash);
            var c = new b.DERSequence({ array: [f, a] });
            this.valueList = [c]
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cades.SignaturePolicyIdentifier, KJUR.asn1.cms.Attribute);
KJUR.asn1.cades.OtherHashAlgAndValue = function(b) {
    KJUR.asn1.cades.OtherHashAlgAndValue.superclass.constructor.call(this);
    var a = KJUR.asn1;
    var c = KJUR.asn1.x509;
    this.dAlg = null;
    this.dHash = null;
    this.getEncodedHex = function() {
        var d = new a.DERSequence({ array: [this.dAlg, this.dHash] });
        this.hTLV = d.getEncodedHex();
        return this.hTLV
    };
    if (typeof b != "undefined") {
        if (typeof b.alg == "string" && typeof b.hash == "string") {
            this.dAlg = new c.AlgorithmIdentifier({ name: b.alg });
            this.dHash = new a.DEROctetString({ hex: b.hash })
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cades.OtherHashAlgAndValue, KJUR.asn1.ASN1Object);
KJUR.asn1.cades.SignatureTimeStamp = function(c) {
    KJUR.asn1.cades.SignatureTimeStamp.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.16.2.14";
    this.tstHex = null;
    var a = KJUR.asn1;
    if (typeof c != "undefined") {
        if (typeof c.res != "undefined") {
            if (typeof c.res == "string" && c.res.match(/^[0-9A-Fa-f]+$/)) {} else {
                if (c.res instanceof KJUR.asn1.ASN1Object) {} else {
                    throw "res param shall be ASN1Object or hex string"
                }
            }
        }
        if (typeof c.tst != "undefined") {
            if (typeof c.tst == "string" && c.tst.match(/^[0-9A-Fa-f]+$/)) {
                var b = new a.ASN1Object();
                this.tstHex = c.tst;
                b.hTLV = this.tstHex;
                b.getEncodedHex();
                this.valueList = [b]
            } else {
                if (c.tst instanceof KJUR.asn1.ASN1Object) {} else {
                    throw "tst param shall be ASN1Object or hex string"
                }
            }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cades.SignatureTimeStamp, KJUR.asn1.cms.Attribute);
KJUR.asn1.cades.CompleteCertificateRefs = function(c) {
    KJUR.asn1.cades.CompleteCertificateRefs.superclass.constructor.call(this);
    this.attrTypeOid = "1.2.840.113549.1.9.16.2.21";
    var a = KJUR.asn1;
    var b = KJUR.asn1.cades;
    this.setByArray = function(d) {
        this.valueList = [];
        for (var e = 0; e < d.length; e++) {
            var f = new b.OtherCertID(d[e]);
            this.valueList.push(f)
        }
    };
    if (typeof c != "undefined") {
        if (typeof c == "object" && typeof c.length == "number") { this.setByArray(c) }
    }
};
YAHOO.lang.extend(KJUR.asn1.cades.CompleteCertificateRefs, KJUR.asn1.cms.Attribute);
KJUR.asn1.cades.OtherCertID = function(d) {
    KJUR.asn1.cades.OtherCertID.superclass.constructor.call(this);
    var a = KJUR.asn1;
    var c = KJUR.asn1.cms;
    var b = KJUR.asn1.cades;
    this.hasIssuerSerial = true;
    this.dOtherCertHash = null;
    this.dIssuerSerial = null;
    this.setByCertPEM = function(e) {
        this.dOtherCertHash = new b.OtherHash(e);
        if (this.hasIssuerSerial) { this.dIssuerSerial = new c.IssuerAndSerialNumber(e) }
    };
    this.getEncodedHex = function() {
        if (this.hTLV != null) {
            return this.hTLV
        }
        if (this.dOtherCertHash == null) {
            throw "otherCertHash not set"
        }
        var e = [this.dOtherCertHash];
        if (this.dIssuerSerial != null) { e.push(this.dIssuerSerial) }
        var f = new a.DERSequence({ array: e });
        this.hTLV = f.getEncodedHex();
        return this.hTLV
    };
    if (typeof d != "undefined") {
        if (typeof d == "string" && d.indexOf("-----BEGIN ") != -1) { this.setByCertPEM(d) }
        if (typeof d == "object") {
            if (d.hasis === false) { this.hasIssuerSerial = false }
            if (typeof d.cert == "string") { this.setByCertPEM(d.cert) }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cades.OtherCertID, KJUR.asn1.ASN1Object);
KJUR.asn1.cades.OtherHash = function(c) {
    KJUR.asn1.cades.OtherHash.superclass.constructor.call(this);
    var a = KJUR.asn1;
    var b = KJUR.asn1.cades;
    this.alg = "sha256";
    this.dOtherHash = null;
    this.setByCertPEM = function(d) {
        if (d.indexOf("-----BEGIN ") == -1) {
            throw "certPEM not to seem PEM format"
        }
        var e = X509.pemToHex(d);
        var f = KJUR.crypto.Util.hashHex(e, this.alg);
        this.dOtherHash = new b.OtherHashAlgAndValue({ alg: this.alg, hash: f })
    };
    this.getEncodedHex = function() {
        if (this.dOtherHash == null) {
            throw "OtherHash not set"
        }
        return this.dOtherHash.getEncodedHex()
    };
    if (typeof c != "undefined") {
        if (typeof c == "string") {
            if (c.indexOf("-----BEGIN ") != -1) { this.setByCertPEM(c) } else {
                if (c.match(/^[0-9A-Fa-f]+$/)) { this.dOtherHash = new a.DEROctetString({ hex: c }) } else {
                    throw "unsupported string value for params"
                }
            }
        } else {
            if (typeof c == "object") {
                if (typeof c.cert == "string") {
                    if (typeof c.alg == "string") { this.alg = c.alg }
                    this.setByCertPEM(c.cert)
                } else { this.dOtherHash = new b.OtherHashAlgAndValue(c) }
            }
        }
    }
};
YAHOO.lang.extend(KJUR.asn1.cades.OtherHash, KJUR.asn1.ASN1Object);
KJUR.asn1.cades.CAdESUtil = new function() {};
KJUR.asn1.cades.CAdESUtil.addSigTS = function(c, b, a) {};
KJUR.asn1.cades.CAdESUtil.parseSignedDataForAddingUnsigned = function(d) {
    var q = KJUR.asn1;
    var p = KJUR.asn1.cms;
    var c = KJUR.asn1.cades.CAdESUtil;
    var a = {};
    if (ASN1HEX.getDecendantHexTLVByNthList(d, 0, [0]) != "06092a864886f70d010702") {
        throw "hex is not CMS SignedData"
    }
    var s = ASN1HEX.getDecendantIndexByNthList(d, 0, [1, 0]);
    var b = ASN1HEX.getPosArrayOfChildren_AtObj(d, s);
    if (b.length < 4) {
        throw "num of SignedData elem shall be 4 at least"
    }
    var f = b.shift();
    a.version = ASN1HEX.getHexOfTLV_AtObj(d, f);
    var l = b.shift();
    a.algs = ASN1HEX.getHexOfTLV_AtObj(d, l);
    var m = b.shift();
    a.encapcontent = ASN1HEX.getHexOfTLV_AtObj(d, m);
    a.certs = null;
    a.revs = null;
    a.si = [];
    var n = b.shift();
    if (d.substr(n, 2) == "a0") {
        a.certs = ASN1HEX.getHexOfTLV_AtObj(d, n);
        n = b.shift()
    }
    if (d.substr(n, 2) == "a1") {
        a.revs = ASN1HEX.getHexOfTLV_AtObj(d, n);
        n = b.shift()
    }
    var k = n;
    if (d.substr(k, 2) != "31") {
        throw "Can't find signerInfos"
    }
    var j = ASN1HEX.getPosArrayOfChildren_AtObj(d, k);
    for (var h = 0; h < j.length; h++) {
        var o = j[h];
        var e = c.parseSignerInfoForAddingUnsigned(d, o, h);
        a.si[h] = e
    }
    var g = null;
    a.obj = new p.SignedData();
    g = new q.ASN1Object();
    g.hTLV = a.version;
    a.obj.dCMSVersion = g;
    g = new q.ASN1Object();
    g.hTLV = a.algs;
    a.obj.dDigestAlgs = g;
    g = new q.ASN1Object();
    g.hTLV = a.encapcontent;
    a.obj.dEncapContentInfo = g;
    g = new q.ASN1Object();
    g.hTLV = a.certs;
    a.obj.dCerts = g;
    a.obj.signerInfoList = [];
    for (var h = 0; h < a.si.length; h++) { a.obj.signerInfoList.push(a.si[h].obj) }
    return a
};
KJUR.asn1.cades.CAdESUtil.parseSignerInfoForAddingUnsigned = function(d, k, a) {
    var m = KJUR.asn1;
    var l = KJUR.asn1.cms;
    var b = {};
    var e = ASN1HEX.getPosArrayOfChildren_AtObj(d, k);
    if (e.length != 6) {
        throw "not supported items for SignerInfo (!=6)"
    }
    var f = e.shift();
    b.version = ASN1HEX.getHexOfTLV_AtObj(d, f);
    var n = e.shift();
    b.si = ASN1HEX.getHexOfTLV_AtObj(d, n);
    var h = e.shift();
    b.digalg = ASN1HEX.getHexOfTLV_AtObj(d, h);
    var c = e.shift();
    b.sattrs = ASN1HEX.getHexOfTLV_AtObj(d, c);
    var i = e.shift();
    b.sigalg = ASN1HEX.getHexOfTLV_AtObj(d, i);
    var j = e.shift();
    b.sig = ASN1HEX.getHexOfTLV_AtObj(d, j);
    b.sigval = ASN1HEX.getHexOfV_AtObj(d, j);
    var g = null;
    b.obj = new l.SignerInfo();
    g = new m.ASN1Object();
    g.hTLV = b.version;
    b.obj.dCMSVersion = g;
    g = new m.ASN1Object();
    g.hTLV = b.si;
    b.obj.dSignerIdentifier = g;
    g = new m.ASN1Object();
    g.hTLV = b.digalg;
    b.obj.dDigestAlgorithm = g;
    g = new m.ASN1Object();
    g.hTLV = b.sattrs;
    b.obj.dSignedAttrs = g;
    g = new m.ASN1Object();
    g.hTLV = b.sigalg;
    b.obj.dSigAlg = g;
    g = new m.ASN1Object();
    g.hTLV = b.sig;
    b.obj.dSig = g;
    b.obj.dUnsignedAttrs = new l.AttributeList();
    return b
};
/*! asn1csr-1.0.0.js (c) 2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
if (typeof KJUR.asn1.csr == "undefined" || !KJUR.asn1.csr) { KJUR.asn1.csr = {} }
KJUR.asn1.csr.CertificationRequest = function(f) {
    KJUR.asn1.csr.CertificationRequest.superclass.constructor.call(this);
    var b = null;
    var d = null;
    var e = null;
    var c = null;
    var a = null;
    this.sign = function(i, h) {
        if (this.prvKey == null) { this.prvKey = h }
        this.asn1SignatureAlg = new KJUR.asn1.x509.AlgorithmIdentifier({ name: i });
        sig = new KJUR.crypto.Signature({ alg: i });
        sig.initSign(this.prvKey);
        sig.updateHex(this.asn1CSRInfo.getEncodedHex());
        this.hexSig = sig.sign();
        this.asn1Sig = new KJUR.asn1.DERBitString({ hex: "00" + this.hexSig });
        var g = new KJUR.asn1.DERSequence({ array: [this.asn1CSRInfo, this.asn1SignatureAlg, this.asn1Sig] });
        this.hTLV = g.getEncodedHex();
        this.isModified = false
    };
    this.getPEMString = function() {
        var g = KJUR.asn1.ASN1Util.getPEMStringFromHex(this.getEncodedHex(), "CERTIFICATE REQUEST");
        return g
    };
    this.getEncodedHex = function() {
        if (this.isModified == false && this.hTLV != null) {
            return this.hTLV
        }
        throw "not signed yet"
    };
    if (typeof f != "undefined") {
        if (typeof f.csrinfo != "undefined") { this.asn1CSRInfo = f.csrinfo }
    }
};
YAHOO.lang.extend(KJUR.asn1.csr.CertificationRequest, KJUR.asn1.ASN1Object);
KJUR.asn1.csr.CertificationRequestInfo = function(a) {
    KJUR.asn1.csr.CertificationRequestInfo.superclass.constructor.call(this);
    this._initialize = function() {
        this.asn1Array = new Array();
        this.asn1Version = new KJUR.asn1.DERInteger({ "int": 0 });
        this.asn1Subject = null;
        this.asn1SubjPKey = null;
        this.extensionsArray = new Array()
    };
    this.setSubjectByParam = function(b) { this.asn1Subject = new KJUR.asn1.x509.X500Name(b) };
    this.setSubjectPublicKeyByGetKey = function(c) {
        var b = KEYUTIL.getKey(c);
        this.asn1SubjPKey = new KJUR.asn1.x509.SubjectPublicKeyInfo(b)
    };
    this.getEncodedHex = function() {
        this.asn1Array = new Array();
        this.asn1Array.push(this.asn1Version);
        this.asn1Array.push(this.asn1Subject);
        this.asn1Array.push(this.asn1SubjPKey);
        var c = new KJUR.asn1.DERSequence({ array: this.extensionsArray });
        var b = new KJUR.asn1.DERTaggedObject({ explicit: false, tag: "a0", obj: c });
        this.asn1Array.push(b);
        var d = new KJUR.asn1.DERSequence({ array: this.asn1Array });
        this.hTLV = d.getEncodedHex();
        this.isModified = false;
        return this.hTLV
    };
    this._initialize()
};
YAHOO.lang.extend(KJUR.asn1.csr.CertificationRequestInfo, KJUR.asn1.ASN1Object);
KJUR.asn1.csr.CSRUtil = new function() {};
KJUR.asn1.csr.CSRUtil.newCSRPEM = function(f) {
    var c = KJUR.asn1.csr;
    if (f.subject === undefined) {
        throw "parameter subject undefined"
    }
    if (f.sbjpubkey === undefined) {
        throw "parameter sbjpubkey undefined"
    }
    if (f.sigalg === undefined) {
        throw "parameter sigalg undefined"
    }
    if (f.sbjprvkey === undefined) {
        throw "parameter sbjpubkey undefined"
    }
    var b = new c.CertificationRequestInfo();
    b.setSubjectByParam(f.subject);
    b.setSubjectPublicKeyByGetKey(f.sbjpubkey);
    var d = new c.CertificationRequest({ csrinfo: b });
    var a = KEYUTIL.getKey(f.sbjprvkey);
    d.sign(f.sigalg, a);
    var e = d.getPEMString();
    return e
};
/*! base64x-1.1.6 (c) 2012-2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
function Base64x() {}

function stoBA(d) {
    var b = new Array();
    for (var c = 0; c < d.length; c++) { b[c] = d.charCodeAt(c) }
    return b
}

function BAtos(b) {
    var d = "";
    for (var c = 0; c < b.length; c++) { d = d + String.fromCharCode(b[c]) }
    return d
}

function BAtohex(b) {
    var e = "";
    for (var d = 0; d < b.length; d++) {
        var c = b[d].toString(16);
        if (c.length == 1) { c = "0" + c }
        e = e + c
    }
    return e
}

function stohex(a) {
    return BAtohex(stoBA(a))
}

function stob64(a) {
    return hex2b64(stohex(a))
}

function stob64u(a) {
    return b64tob64u(hex2b64(stohex(a)))
}

function b64utos(a) {
    return BAtos(b64toBA(b64utob64(a)))
}

function b64tob64u(a) {
    a = a.replace(/\=/g, "");
    a = a.replace(/\+/g, "-");
    a = a.replace(/\//g, "_");
    return a
}

function b64utob64(a) {
    if (a.length % 4 == 2) { a = a + "==" } else {
        if (a.length % 4 == 3) { a = a + "=" }
    }
    a = a.replace(/-/g, "+");
    a = a.replace(/_/g, "/");
    return a
}

function hextob64u(a) {
    if (a.length % 2 == 1) { a = "0" + a }
    return b64tob64u(hex2b64(a))
}

function b64utohex(a) {
    return b64tohex(b64utob64(a))
}
var utf8tob64u, b64utoutf8;
if (typeof Buffer === "function") {
    utf8tob64u = function(a) {
        return b64tob64u(new Buffer(a, "utf8").toString("base64"))
    };
    b64utoutf8 = function(a) {
        return new Buffer(b64utob64(a), "base64").toString("utf8")
    }
} else {
    utf8tob64u = function(a) {
        return hextob64u(uricmptohex(encodeURIComponentAll(a)))
    };
    b64utoutf8 = function(a) {
        return decodeURIComponent(hextouricmp(b64utohex(a)))
    }
}

function utf8tob64(a) {
    return hex2b64(uricmptohex(encodeURIComponentAll(a)))
}

function b64toutf8(a) {
    return decodeURIComponent(hextouricmp(b64tohex(a)))
}

function utf8tohex(a) {
    return uricmptohex(encodeURIComponentAll(a))
}

function hextoutf8(a) {
    return decodeURIComponent(hextouricmp(a))
}

function hextorstr(c) {
    var b = "";
    for (var a = 0; a < c.length - 1; a += 2) { b += String.fromCharCode(parseInt(c.substr(a, 2), 16)) }
    return b
}

function rstrtohex(c) {
    var a = "";
    for (var b = 0; b < c.length; b++) { a += ("0" + c.charCodeAt(b).toString(16)).slice(-2) }
    return a
}

function hextob64(a) {
    return hex2b64(a)
}

function hextob64nl(b) {
    var a = hextob64(b);
    var c = a.replace(/(.{64})/g, "$1\r\n");
    c = c.replace(/\r\n$/, "");
    return c
}

function b64nltohex(b) {
    var a = b.replace(/[^0-9A-Za-z\/+=]*/g, "");
    var c = b64tohex(a);
    return c
}

function uricmptohex(a) {
    return a.replace(/%/g, "")
}

function hextouricmp(a) {
    return a.replace(/(..)/g, "%$1")
}

function encodeURIComponentAll(a) {
    var d = encodeURIComponent(a);
    var b = "";
    for (var c = 0; c < d.length; c++) {
        if (d[c] == "%") {
            b = b + d.substr(c, 3);
            c = c + 2
        } else { b = b + "%" + stohex(d[c]) }
    }
    return b
}

function newline_toUnix(a) {
    a = a.replace(/\r\n/mg, "\n");
    return a
}

function newline_toDos(a) {
    a = a.replace(/\r\n/mg, "\n");
    a = a.replace(/\n/mg, "\r\n");
    return a
}

function intarystrtohex(b) {
    b = b.replace(/^\s*\[\s*/, "");
    b = b.replace(/\s*\]\s*$/, "");
    b = b.replace(/\s*/g, "");
    try {
        var c = b.split(/,/).map(function(g, e, h) {
            var f = parseInt(g);
            if (f < 0 || 255 < f) {
                throw "integer not in range 0-255"
            }
            var d = ("00" + f.toString(16)).slice(-2);
            return d
        }).join("");
        return c
    } catch (a) {
        throw "malformed integer array string: " + a
    }
}
var strdiffidx = function(c, a) {
    var d = c.length;
    if (c.length > a.length) { d = a.length }
    for (var b = 0; b < d; b++) {
        if (c.charCodeAt(b) != a.charCodeAt(b)) {
            return b
        }
    }
    if (c.length != a.length) {
        return d
    }
    return -1
};
/*! crypto-1.1.8.js (c) 2013-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
if (typeof KJUR == "undefined" || !KJUR) { KJUR = {} }
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) { KJUR.crypto = {} }
KJUR.crypto.Util = new function() {
    this.DIGESTINFOHEAD = { sha1: "3021300906052b0e03021a05000414", sha224: "302d300d06096086480165030402040500041c", sha256: "3031300d060960864801650304020105000420", sha384: "3041300d060960864801650304020205000430", sha512: "3051300d060960864801650304020305000440", md2: "3020300c06082a864886f70d020205000410", md5: "3020300c06082a864886f70d020505000410", ripemd160: "3021300906052b2403020105000414", };
    this.DEFAULTPROVIDER = { md5: "cryptojs", sha1: "cryptojs", sha224: "cryptojs", sha256: "cryptojs", sha384: "cryptojs", sha512: "cryptojs", ripemd160: "cryptojs", hmacmd5: "cryptojs", hmacsha1: "cryptojs", hmacsha224: "cryptojs", hmacsha256: "cryptojs", hmacsha384: "cryptojs", hmacsha512: "cryptojs", hmacripemd160: "cryptojs", MD5withRSA: "cryptojs/jsrsa", SHA1withRSA: "cryptojs/jsrsa", SHA224withRSA: "cryptojs/jsrsa", SHA256withRSA: "cryptojs/jsrsa", SHA384withRSA: "cryptojs/jsrsa", SHA512withRSA: "cryptojs/jsrsa", RIPEMD160withRSA: "cryptojs/jsrsa", MD5withECDSA: "cryptojs/jsrsa", SHA1withECDSA: "cryptojs/jsrsa", SHA224withECDSA: "cryptojs/jsrsa", SHA256withECDSA: "cryptojs/jsrsa", SHA384withECDSA: "cryptojs/jsrsa", SHA512withECDSA: "cryptojs/jsrsa", RIPEMD160withECDSA: "cryptojs/jsrsa", SHA1withDSA: "cryptojs/jsrsa", SHA224withDSA: "cryptojs/jsrsa", SHA256withDSA: "cryptojs/jsrsa", MD5withRSAandMGF1: "cryptojs/jsrsa", SHA1withRSAandMGF1: "cryptojs/jsrsa", SHA224withRSAandMGF1: "cryptojs/jsrsa", SHA256withRSAandMGF1: "cryptojs/jsrsa", SHA384withRSAandMGF1: "cryptojs/jsrsa", SHA512withRSAandMGF1: "cryptojs/jsrsa", RIPEMD160withRSAandMGF1: "cryptojs/jsrsa", };
    this.CRYPTOJSMESSAGEDIGESTNAME = { md5: CryptoJS.algo.MD5, sha1: CryptoJS.algo.SHA1, sha224: CryptoJS.algo.SHA224, sha256: CryptoJS.algo.SHA256, sha384: CryptoJS.algo.SHA384, sha512: CryptoJS.algo.SHA512, ripemd160: CryptoJS.algo.RIPEMD160 };
    this.getDigestInfoHex = function(a, b) {
        if (typeof this.DIGESTINFOHEAD[b] == "undefined") {
            throw "alg not supported in Util.DIGESTINFOHEAD: " + b
        }
        return this.DIGESTINFOHEAD[b] + a
    };
    this.getPaddedDigestInfoHex = function(h, a, j) {
        var c = this.getDigestInfoHex(h, a);
        var d = j / 4;
        if (c.length + 22 > d) {
            throw "key is too short for SigAlg: keylen=" + j + "," + a
        }
        var b = "0001";
        var k = "00" + c;
        var g = "";
        var l = d - b.length - k.length;
        for (var f = 0; f < l; f += 2) { g += "ff" }
        var e = b + g + k;
        return e
    };
    this.hashString = function(a, c) {
        var b = new KJUR.crypto.MessageDigest({ alg: c });
        return b.digestString(a)
    };
    this.hashHex = function(b, c) {
        var a = new KJUR.crypto.MessageDigest({ alg: c });
        return a.digestHex(b)
    };
    this.sha1 = function(a) {
        var b = new KJUR.crypto.MessageDigest({ alg: "sha1", prov: "cryptojs" });
        return b.digestString(a)
    };
    this.sha256 = function(a) {
        var b = new KJUR.crypto.MessageDigest({ alg: "sha256", prov: "cryptojs" });
        return b.digestString(a)
    };
    this.sha256Hex = function(a) {
        var b = new KJUR.crypto.MessageDigest({ alg: "sha256", prov: "cryptojs" });
        return b.digestHex(a)
    };
    this.sha512 = function(a) {
        var b = new KJUR.crypto.MessageDigest({ alg: "sha512", prov: "cryptojs" });
        return b.digestString(a)
    };
    this.sha512Hex = function(a) {
        var b = new KJUR.crypto.MessageDigest({ alg: "sha512", prov: "cryptojs" });
        return b.digestHex(a)
    };
    this.md5 = function(a) {
        var b = new KJUR.crypto.MessageDigest({ alg: "md5", prov: "cryptojs" });
        return b.digestString(a)
    };
    this.ripemd160 = function(a) {
        var b = new KJUR.crypto.MessageDigest({ alg: "ripemd160", prov: "cryptojs" });
        return b.digestString(a)
    };
    this.getCryptoJSMDByName = function(a) {}
};
KJUR.crypto.MessageDigest = function(c) {
    var b = null;
    var a = null;
    var d = null;
    this.setAlgAndProvider = function(g, f) {
        if (g != null && f === undefined) { f = KJUR.crypto.Util.DEFAULTPROVIDER[g] }
        if (":md5:sha1:sha224:sha256:sha384:sha512:ripemd160:".indexOf(g) != -1 && f == "cryptojs") {
            try { this.md = KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[g].create() } catch (e) {
                throw "setAlgAndProvider hash alg set fail alg=" + g + "/" + e
            }
            this.updateString = function(h) { this.md.update(h) };
            this.updateHex = function(h) {
                var i = CryptoJS.enc.Hex.parse(h);
                this.md.update(i)
            };
            this.digest = function() {
                var h = this.md.finalize();
                return h.toString(CryptoJS.enc.Hex)
            };
            this.digestString = function(h) {
                this.updateString(h);
                return this.digest()
            };
            this.digestHex = function(h) {
                this.updateHex(h);
                return this.digest()
            }
        }
        if (":sha256:".indexOf(g) != -1 && f == "sjcl") {
            try { this.md = new sjcl.hash.sha256() } catch (e) {
                throw "setAlgAndProvider hash alg set fail alg=" + g + "/" + e
            }
            this.updateString = function(h) { this.md.update(h) };
            this.updateHex = function(i) {
                var h = sjcl.codec.hex.toBits(i);
                this.md.update(h)
            };
            this.digest = function() {
                var h = this.md.finalize();
                return sjcl.codec.hex.fromBits(h)
            };
            this.digestString = function(h) {
                this.updateString(h);
                return this.digest()
            };
            this.digestHex = function(h) {
                this.updateHex(h);
                return this.digest()
            }
        }
    };
    this.updateString = function(e) {
        throw "updateString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName
    };
    this.updateHex = function(e) {
        throw "updateHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName
    };
    this.digest = function() {
        throw "digest() not supported for this alg/prov: " + this.algName + "/" + this.provName
    };
    this.digestString = function(e) {
        throw "digestString(str) not supported for this alg/prov: " + this.algName + "/" + this.provName
    };
    this.digestHex = function(e) {
        throw "digestHex(hex) not supported for this alg/prov: " + this.algName + "/" + this.provName
    };
    if (c !== undefined) {
        if (c.alg !== undefined) {
            this.algName = c.alg;
            if (c.prov === undefined) { this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName] }
            this.setAlgAndProvider(this.algName, this.provName)
        }
    }
};
KJUR.crypto.Mac = function(d) {
    var f = null;
    var c = null;
    var a = null;
    var e = null;
    var b = null;
    this.setAlgAndProvider = function(k, i) {
        k = k.toLowerCase();
        if (k == null) { k = "hmacsha1" }
        k = k.toLowerCase();
        if (k.substr(0, 4) != "hmac") {
            throw "setAlgAndProvider unsupported HMAC alg: " + k
        }
        if (i === undefined) { i = KJUR.crypto.Util.DEFAULTPROVIDER[k] }
        this.algProv = k + "/" + i;
        var g = k.substr(4);
        if (":md5:sha1:sha224:sha256:sha384:sha512:ripemd160:".indexOf(g) != -1 && i == "cryptojs") {
            try {
                var j = KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME[g];
                this.mac = CryptoJS.algo.HMAC.create(j, this.pass)
            } catch (h) {
                throw "setAlgAndProvider hash alg set fail hashAlg=" + g + "/" + h
            }
            this.updateString = function(l) { this.mac.update(l) };
            this.updateHex = function(l) {
                var m = CryptoJS.enc.Hex.parse(l);
                this.mac.update(m)
            };
            this.doFinal = function() {
                var l = this.mac.finalize();
                return l.toString(CryptoJS.enc.Hex)
            };
            this.doFinalString = function(l) {
                this.updateString(l);
                return this.doFinal()
            };
            this.doFinalHex = function(l) {
                this.updateHex(l);
                return this.doFinal()
            }
        }
    };
    this.updateString = function(g) {
        throw "updateString(str) not supported for this alg/prov: " + this.algProv
    };
    this.updateHex = function(g) {
        throw "updateHex(hex) not supported for this alg/prov: " + this.algProv
    };
    this.doFinal = function() {
        throw "digest() not supported for this alg/prov: " + this.algProv
    };
    this.doFinalString = function(g) {
        throw "digestString(str) not supported for this alg/prov: " + this.algProv
    };
    this.doFinalHex = function(g) {
        throw "digestHex(hex) not supported for this alg/prov: " + this.algProv
    };
    this.setPassword = function(h) {
        if (typeof h == "string") {
            var g = h;
            if (h.length % 2 == 1 || !h.match(/^[0-9A-Fa-f]+$/)) { g = rstrtohex(h) }
            this.pass = CryptoJS.enc.Hex.parse(g);
            return
        }
        if (typeof h != "object") {
            throw "KJUR.crypto.Mac unsupported password type: " + h
        }
        var g = null;
        if (h.hex !== undefined) {
            if (h.hex.length % 2 != 0 || !h.hex.match(/^[0-9A-Fa-f]+$/)) {
                throw "Mac: wrong hex password: " + h.hex
            }
            g = h.hex
        }
        if (h.utf8 !== undefined) { g = utf8tohex(h.utf8) }
        if (h.rstr !== undefined) { g = rstrtohex(h.rstr) }
        if (h.b64 !== undefined) { g = b64tohex(h.b64) }
        if (h.b64u !== undefined) { g = b64utohex(h.b64u) }
        if (g == null) {
            throw "KJUR.crypto.Mac unsupported password type: " + h
        }
        this.pass = CryptoJS.enc.Hex.parse(g)
    };
    if (d !== undefined) {
        if (d.pass !== undefined) { this.setPassword(d.pass) }
        if (d.alg !== undefined) {
            this.algName = d.alg;
            if (d.prov === undefined) { this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName] }
            this.setAlgAndProvider(this.algName, this.provName)
        }
    }
};
KJUR.crypto.Signature = function(o) {
    var q = null;
    var n = null;
    var r = null;
    var c = null;
    var l = null;
    var d = null;
    var k = null;
    var h = null;
    var p = null;
    var e = null;
    var b = -1;
    var g = null;
    var j = null;
    var a = null;
    var i = null;
    var f = null;
    this._setAlgNames = function() {
        if (this.algName.match(/^(.+)with(.+)$/)) {
            this.mdAlgName = RegExp.$1.toLowerCase();
            this.pubkeyAlgName = RegExp.$2.toLowerCase()
        }
    };
    this._zeroPaddingOfSignature = function(x, w) {
        var v = "";
        var t = w / 4 - x.length;
        for (var u = 0; u < t; u++) { v = v + "0" }
        return v + x
    };
    this.setAlgAndProvider = function(u, t) {
        this._setAlgNames();
        if (t != "cryptojs/jsrsa") {
            throw "provider not supported: " + t
        }
        if (":md5:sha1:sha224:sha256:sha384:sha512:ripemd160:".indexOf(this.mdAlgName) != -1) {
            try { this.md = new KJUR.crypto.MessageDigest({ alg: this.mdAlgName }) } catch (s) {
                throw "setAlgAndProvider hash alg set fail alg=" + this.mdAlgName + "/" + s
            }
            this.init = function(w, x) {
                var y = null;
                try {
                    if (x === undefined) { y = KEYUTIL.getKey(w) } else { y = KEYUTIL.getKey(w, x) }
                } catch (v) {
                    throw "init failed:" + v
                }
                if (y.isPrivate === true) {
                    this.prvKey = y;
                    this.state = "SIGN"
                } else {
                    if (y.isPublic === true) {
                        this.pubKey = y;
                        this.state = "VERIFY"
                    } else {
                        throw "init failed.:" + y
                    }
                }
            };
            this.initSign = function(v) {
                if (typeof v.ecprvhex == "string" && typeof v.eccurvename == "string") {
                    this.ecprvhex = v.ecprvhex;
                    this.eccurvename = v.eccurvename
                } else { this.prvKey = v }
                this.state = "SIGN"
            };
            this.initVerifyByPublicKey = function(v) {
                if (typeof v.ecpubhex == "string" && typeof v.eccurvename == "string") {
                    this.ecpubhex = v.ecpubhex;
                    this.eccurvename = v.eccurvename
                } else {
                    if (v instanceof KJUR.crypto.ECDSA) { this.pubKey = v } else {
                        if (v instanceof RSAKey) { this.pubKey = v }
                    }
                }
                this.state = "VERIFY"
            };
            this.initVerifyByCertificatePEM = function(v) {
                var w = new X509();
                w.readCertPEM(v);
                this.pubKey = w.subjectPublicKeyRSA;
                this.state = "VERIFY"
            };
            this.updateString = function(v) { this.md.updateString(v) };
            this.updateHex = function(v) { this.md.updateHex(v) };
            this.sign = function() {
                this.sHashHex = this.md.digest();
                if (typeof this.ecprvhex != "undefined" && typeof this.eccurvename != "undefined") {
                    var v = new KJUR.crypto.ECDSA({ curve: this.eccurvename });
                    this.hSign = v.signHex(this.sHashHex, this.ecprvhex)
                } else {
                    if (this.prvKey instanceof RSAKey && this.pubkeyAlgName == "rsaandmgf1") { this.hSign = this.prvKey.signWithMessageHashPSS(this.sHashHex, this.mdAlgName, this.pssSaltLen) } else {
                        if (this.prvKey instanceof RSAKey && this.pubkeyAlgName == "rsa") { this.hSign = this.prvKey.signWithMessageHash(this.sHashHex, this.mdAlgName) } else {
                            if (this.prvKey instanceof KJUR.crypto.ECDSA) { this.hSign = this.prvKey.signWithMessageHash(this.sHashHex) } else {
                                if (this.prvKey instanceof KJUR.crypto.DSA) { this.hSign = this.prvKey.signWithMessageHash(this.sHashHex) } else {
                                    throw "Signature: unsupported public key alg: " + this.pubkeyAlgName
                                }
                            }
                        }
                    }
                }
                return this.hSign
            };
            this.signString = function(v) {
                this.updateString(v);
                return this.sign()
            };
            this.signHex = function(v) {
                this.updateHex(v);
                return this.sign()
            };
            this.verify = function(v) {
                this.sHashHex = this.md.digest();
                if (typeof this.ecpubhex != "undefined" && typeof this.eccurvename != "undefined") {
                    var w = new KJUR.crypto.ECDSA({ curve: this.eccurvename });
                    return w.verifyHex(this.sHashHex, v, this.ecpubhex)
                } else {
                    if (this.pubKey instanceof RSAKey && this.pubkeyAlgName == "rsaandmgf1") {
                        return this.pubKey.verifyWithMessageHashPSS(this.sHashHex, v, this.mdAlgName, this.pssSaltLen)
                    } else {
                        if (this.pubKey instanceof RSAKey && this.pubkeyAlgName == "rsa") {
                            return this.pubKey.verifyWithMessageHash(this.sHashHex, v)
                        } else {
                            if (this.pubKey instanceof KJUR.crypto.ECDSA) {
                                return this.pubKey.verifyWithMessageHash(this.sHashHex, v)
                            } else {
                                if (this.pubKey instanceof KJUR.crypto.DSA) {
                                    return this.pubKey.verifyWithMessageHash(this.sHashHex, v)
                                } else {
                                    throw "Signature: unsupported public key alg: " + this.pubkeyAlgName
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    this.init = function(s, t) {
        throw "init(key, pass) not supported for this alg:prov=" + this.algProvName
    };
    this.initVerifyByPublicKey = function(s) {
        throw "initVerifyByPublicKey(rsaPubKeyy) not supported for this alg:prov=" + this.algProvName
    };
    this.initVerifyByCertificatePEM = function(s) {
        throw "initVerifyByCertificatePEM(certPEM) not supported for this alg:prov=" + this.algProvName
    };
    this.initSign = function(s) {
        throw "initSign(prvKey) not supported for this alg:prov=" + this.algProvName
    };
    this.updateString = function(s) {
        throw "updateString(str) not supported for this alg:prov=" + this.algProvName
    };
    this.updateHex = function(s) {
        throw "updateHex(hex) not supported for this alg:prov=" + this.algProvName
    };
    this.sign = function() {
        throw "sign() not supported for this alg:prov=" + this.algProvName
    };
    this.signString = function(s) {
        throw "digestString(str) not supported for this alg:prov=" + this.algProvName
    };
    this.signHex = function(s) {
        throw "digestHex(hex) not supported for this alg:prov=" + this.algProvName
    };
    this.verify = function(s) {
        throw "verify(hSigVal) not supported for this alg:prov=" + this.algProvName
    };
    this.initParams = o;
    if (o !== undefined) {
        if (o.alg !== undefined) {
            this.algName = o.alg;
            if (o.prov === undefined) { this.provName = KJUR.crypto.Util.DEFAULTPROVIDER[this.algName] } else { this.provName = o.prov }
            this.algProvName = this.algName + ":" + this.provName;
            this.setAlgAndProvider(this.algName, this.provName);
            this._setAlgNames()
        }
        if (o.psssaltlen !== undefined) { this.pssSaltLen = o.psssaltlen }
        if (o.prvkeypem !== undefined) {
            if (o.prvkeypas !== undefined) {
                throw "both prvkeypem and prvkeypas parameters not supported"
            } else {
                try {
                    var q = new RSAKey();
                    q.readPrivateKeyFromPEMString(o.prvkeypem);
                    this.initSign(q)
                } catch (m) {
                    throw "fatal error to load pem private key: " + m
                }
            }
        }
    }
};
KJUR.crypto.OID = new function() { this.oidhex2name = { "2a864886f70d010101": "rsaEncryption", "2a8648ce3d0201": "ecPublicKey", "2a8648ce380401": "dsa", "2a8648ce3d030107": "secp256r1", "2b8104001f": "secp192k1", "2b81040021": "secp224r1", "2b8104000a": "secp256k1", "2b81040023": "secp521r1", "2b81040022": "secp384r1", "2a8648ce380403": "SHA1withDSA", "608648016503040301": "SHA224withDSA", "608648016503040302": "SHA256withDSA", } };
/*! ecdsa-modified-1.0.4.js (c) Stephan Thomas, Kenji Urushima | github.com/bitcoinjs/bitcoinjs-lib/blob/master/LICENSE
 */
if (typeof KJUR == "undefined" || !KJUR) { KJUR = {} }
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) { KJUR.crypto = {} }
KJUR.crypto.ECDSA = function(h) {
    var e = "secp256r1";
    var g = null;
    var b = null;
    var f = null;
    var a = new SecureRandom();
    var d = null;
    this.type = "EC";

    function c(s, o, r, n) {
        var j = Math.max(o.bitLength(), n.bitLength());
        var t = s.add2D(r);
        var q = s.curve.getInfinity();
        for (var p = j - 1; p >= 0; --p) {
            q = q.twice2D();
            q.z = BigInteger.ONE;
            if (o.testBit(p)) {
                if (n.testBit(p)) { q = q.add2D(t) } else { q = q.add2D(s) }
            } else {
                if (n.testBit(p)) { q = q.add2D(r) }
            }
        }
        return q
    }
    this.getBigRandom = function(i) {
        return new BigInteger(i.bitLength(), a).mod(i.subtract(BigInteger.ONE)).add(BigInteger.ONE)
    };
    this.setNamedCurve = function(i) {
        this.ecparams = KJUR.crypto.ECParameterDB.getByName(i);
        this.prvKeyHex = null;
        this.pubKeyHex = null;
        this.curveName = i
    };
    this.setPrivateKeyHex = function(i) {
        this.isPrivate = true;
        this.prvKeyHex = i
    };
    this.setPublicKeyHex = function(i) {
        this.isPublic = true;
        this.pubKeyHex = i
    };
    this.generateKeyPairHex = function() {
        var k = this.ecparams.n;
        var n = this.getBigRandom(k);
        var l = this.ecparams.G.multiply(n);
        var q = l.getX().toBigInteger();
        var o = l.getY().toBigInteger();
        var i = this.ecparams.keylen / 4;
        var m = ("0000000000" + n.toString(16)).slice(-i);
        var r = ("0000000000" + q.toString(16)).slice(-i);
        var p = ("0000000000" + o.toString(16)).slice(-i);
        var j = "04" + r + p;
        this.setPrivateKeyHex(m);
        this.setPublicKeyHex(j);
        return { ecprvhex: m, ecpubhex: j }
    };
    this.signWithMessageHash = function(i) {
        return this.signHex(i, this.prvKeyHex)
    };
    this.signHex = function(o, j) {
        var t = new BigInteger(j, 16);
        var l = this.ecparams.n;
        var q = new BigInteger(o, 16);
        do {
            var m = this.getBigRandom(l);
            var u = this.ecparams.G;
            var p = u.multiply(m);
            var i = p.getX().toBigInteger().mod(l)
        } while (i.compareTo(BigInteger.ZERO) <= 0);
        var v = m.modInverse(l).multiply(q.add(t.multiply(i))).mod(l);
        return KJUR.crypto.ECDSA.biRSSigToASN1Sig(i, v)
    };
    this.sign = function(m, u) {
        var q = u;
        var j = this.ecparams.n;
        var p = BigInteger.fromByteArrayUnsigned(m);
        do {
            var l = this.getBigRandom(j);
            var t = this.ecparams.G;
            var o = t.multiply(l);
            var i = o.getX().toBigInteger().mod(j)
        } while (i.compareTo(BigInteger.ZERO) <= 0);
        var v = l.modInverse(j).multiply(p.add(q.multiply(i))).mod(j);
        return this.serializeSig(i, v)
    };
    this.verifyWithMessageHash = function(j, i) {
        return this.verifyHex(j, i, this.pubKeyHex)
    };
    this.verifyHex = function(m, i, p) {
        var l, j;
        var o = KJUR.crypto.ECDSA.parseSigHex(i);
        l = o.r;
        j = o.s;
        var k;
        k = ECPointFp.decodeFromHex(this.ecparams.curve, p);
        var n = new BigInteger(m, 16);
        return this.verifyRaw(n, l, j, k)
    };
    this.verify = function(o, p, j) {
        var l, i;
        if (Bitcoin.Util.isArray(p)) {
            var n = this.parseSig(p);
            l = n.r;
            i = n.s
        } else {
            if ("object" === typeof p && p.r && p.s) {
                l = p.r;
                i = p.s
            } else {
                throw "Invalid value for signature"
            }
        }
        var k;
        if (j instanceof ECPointFp) { k = j } else {
            if (Bitcoin.Util.isArray(j)) { k = ECPointFp.decodeFrom(this.ecparams.curve, j) } else {
                throw "Invalid format for pubkey value, must be byte array or ECPointFp"
            }
        }
        var m = BigInteger.fromByteArrayUnsigned(o);
        return this.verifyRaw(m, l, i, k)
    };
    this.verifyRaw = function(o, i, w, m) {
        var l = this.ecparams.n;
        var u = this.ecparams.G;
        if (i.compareTo(BigInteger.ONE) < 0 || i.compareTo(l) >= 0) {
            return false
        }
        if (w.compareTo(BigInteger.ONE) < 0 || w.compareTo(l) >= 0) {
            return false
        }
        var p = w.modInverse(l);
        var k = o.multiply(p).mod(l);
        var j = i.multiply(p).mod(l);
        var q = u.multiply(k).add(m.multiply(j));
        var t = q.getX().toBigInteger().mod(l);
        return t.equals(i)
    };
    this.serializeSig = function(k, j) {
        var l = k.toByteArraySigned();
        var i = j.toByteArraySigned();
        var m = [];
        m.push(2);
        m.push(l.length);
        m = m.concat(l);
        m.push(2);
        m.push(i.length);
        m = m.concat(i);
        m.unshift(m.length);
        m.unshift(48);
        return m
    };
    this.parseSig = function(n) {
        var m;
        if (n[0] != 48) {
            throw new Error("Signature not a valid DERSequence")
        }
        m = 2;
        if (n[m] != 2) {
            throw new Error("First element in signature must be a DERInteger")
        }
        var l = n.slice(m + 2, m + 2 + n[m + 1]);
        m += 2 + n[m + 1];
        if (n[m] != 2) {
            throw new Error("Second element in signature must be a DERInteger")
        }
        var i = n.slice(m + 2, m + 2 + n[m + 1]);
        m += 2 + n[m + 1];
        var k = BigInteger.fromByteArrayUnsigned(l);
        var j = BigInteger.fromByteArrayUnsigned(i);
        return { r: k, s: j }
    };
    this.parseSigCompact = function(m) {
        if (m.length !== 65) {
            throw "Signature has the wrong length"
        }
        var j = m[0] - 27;
        if (j < 0 || j > 7) {
            throw "Invalid signature type"
        }
        var o = this.ecparams.n;
        var l = BigInteger.fromByteArrayUnsigned(m.slice(1, 33)).mod(o);
        var k = BigInteger.fromByteArrayUnsigned(m.slice(33, 65)).mod(o);
        return { r: l, s: k, i: j }
    };
    if (h !== undefined) {
        if (h.curve !== undefined) { this.curveName = h.curve }
    }
    if (this.curveName === undefined) { this.curveName = e }
    this.setNamedCurve(this.curveName);
    if (h !== undefined) {
        if (h.prv !== undefined) { this.setPrivateKeyHex(h.prv) }
        if (h.pub !== undefined) { this.setPublicKeyHex(h.pub) }
    }
};
KJUR.crypto.ECDSA.parseSigHex = function(a) {
    var b = KJUR.crypto.ECDSA.parseSigHexInHexRS(a);
    var d = new BigInteger(b.r, 16);
    var c = new BigInteger(b.s, 16);
    return { r: d, s: c }
};
KJUR.crypto.ECDSA.parseSigHexInHexRS = function(c) {
    if (c.substr(0, 2) != "30") {
        throw "signature is not a ASN.1 sequence"
    }
    var b = ASN1HEX.getPosArrayOfChildren_AtObj(c, 0);
    if (b.length != 2) {
        throw "number of signature ASN.1 sequence elements seem wrong"
    }
    var g = b[0];
    var f = b[1];
    if (c.substr(g, 2) != "02") {
        throw "1st item of sequene of signature is not ASN.1 integer"
    }
    if (c.substr(f, 2) != "02") {
        throw "2nd item of sequene of signature is not ASN.1 integer"
    }
    var e = ASN1HEX.getHexOfV_AtObj(c, g);
    var d = ASN1HEX.getHexOfV_AtObj(c, f);
    return { r: e, s: d }
};
KJUR.crypto.ECDSA.asn1SigToConcatSig = function(c) {
    var d = KJUR.crypto.ECDSA.parseSigHexInHexRS(c);
    var b = d.r;
    var a = d.s;
    if (b.substr(0, 2) == "00" && (((b.length / 2) * 8) % (16 * 8)) == 8) { b = b.substr(2) }
    if (a.substr(0, 2) == "00" && (((a.length / 2) * 8) % (16 * 8)) == 8) { a = a.substr(2) }
    if ((((b.length / 2) * 8) % (16 * 8)) != 0) {
        throw "unknown ECDSA sig r length error"
    }
    if ((((a.length / 2) * 8) % (16 * 8)) != 0) {
        throw "unknown ECDSA sig s length error"
    }
    return b + a
};
KJUR.crypto.ECDSA.concatSigToASN1Sig = function(a) {
    if ((((a.length / 2) * 8) % (16 * 8)) != 0) {
        throw "unknown ECDSA concatinated r-s sig  length error"
    }
    var c = a.substr(0, a.length / 2);
    var b = a.substr(a.length / 2);
    return KJUR.crypto.ECDSA.hexRSSigToASN1Sig(c, b)
};
KJUR.crypto.ECDSA.hexRSSigToASN1Sig = function(b, a) {
    var d = new BigInteger(b, 16);
    var c = new BigInteger(a, 16);
    return KJUR.crypto.ECDSA.biRSSigToASN1Sig(d, c)
};
KJUR.crypto.ECDSA.biRSSigToASN1Sig = function(e, c) {
    var b = new KJUR.asn1.DERInteger({ bigint: e });
    var a = new KJUR.asn1.DERInteger({ bigint: c });
    var d = new KJUR.asn1.DERSequence({ array: [b, a] });
    return d.getEncodedHex()
};
/*! ecparam-1.0.0.js (c) 2013 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
if (typeof KJUR == "undefined" || !KJUR) { KJUR = {} }
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) { KJUR.crypto = {} }
KJUR.crypto.ECParameterDB = new function() {
    var b = {};
    var c = {};

    function a(d) {
        return new BigInteger(d, 16)
    }
    this.getByName = function(e) {
        var d = e;
        if (typeof c[d] != "undefined") { d = c[e] }
        if (typeof b[d] != "undefined") {
            return b[d]
        }
        throw "unregistered EC curve name: " + d
    };
    this.regist = function(A, l, o, g, m, e, j, f, k, u, d, x) {
        b[A] = {};
        var s = a(o);
        var z = a(g);
        var y = a(m);
        var t = a(e);
        var w = a(j);
        var r = new ECCurveFp(s, z, y);
        var q = r.decodePointHex("04" + f + k);
        b[A]["name"] = A;
        b[A]["keylen"] = l;
        b[A]["curve"] = r;
        b[A]["G"] = q;
        b[A]["n"] = t;
        b[A]["h"] = w;
        b[A]["oid"] = d;
        b[A]["info"] = x;
        for (var v = 0; v < u.length; v++) { c[u[v]] = A }
    }
};
KJUR.crypto.ECParameterDB.regist("secp128r1", 128, "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF", "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC", "E87579C11079F43DD824993C2CEE5ED3", "FFFFFFFE0000000075A30D1B9038A115", "1", "161FF7528B899B2D0C28607CA52C5B86", "CF5AC8395BAFEB13C02DA292DDED7A83", [], "", "secp128r1 : SECG curve over a 128 bit prime field");
KJUR.crypto.ECParameterDB.regist("secp160k1", 160, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", "0", "7", "0100000000000000000001B8FA16DFAB9ACA16B6B3", "1", "3B4C382CE37AA192A4019E763036F4F5DD4D7EBB", "938CF935318FDCED6BC28286531733C3F03C4FEE", [], "", "secp160k1 : SECG curve over a 160 bit prime field");
KJUR.crypto.ECParameterDB.regist("secp160r1", 160, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC", "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45", "0100000000000000000001F4C8F927AED3CA752257", "1", "4A96B5688EF573284664698968C38BB913CBFC82", "23A628553168947D59DCC912042351377AC5FB32", [], "", "secp160r1 : SECG curve over a 160 bit prime field");
KJUR.crypto.ECParameterDB.regist("secp192k1", 192, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", "0", "3", "FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", "1", "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D", "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", []);
KJUR.crypto.ECParameterDB.regist("secp192r1", 192, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", "1", "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", []);
KJUR.crypto.ECParameterDB.regist("secp224r1", 224, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", "1", "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", []);
KJUR.crypto.ECParameterDB.regist("secp256k1", 256, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", "0", "7", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", "1", "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", []);
KJUR.crypto.ECParameterDB.regist("secp256r1", 256, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", "1", "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", ["NIST P-256", "P-256", "prime256v1"]);
KJUR.crypto.ECParameterDB.regist("secp384r1", 384, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", "1", "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", ["NIST P-384", "P-384"]);
KJUR.crypto.ECParameterDB.regist("secp521r1", 521, "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", "051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", "1", "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", ["NIST P-521", "P-521"]);
/*! dsa-modified-1.0.1.js (c) Recurity Labs GmbH, Kenji Urushimma | github.com/openpgpjs/openpgpjs/blob/master/LICENSE
 */
if (typeof KJUR == "undefined" || !KJUR) { KJUR = {} }
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) { KJUR.crypto = {} }
KJUR.crypto.DSA = function() {
    this.p = null;
    this.q = null;
    this.g = null;
    this.y = null;
    this.x = null;
    this.type = "DSA";
    this.setPrivate = function(z, w, v, A, u) {
        this.isPrivate = true;
        this.p = z;
        this.q = w;
        this.g = v;
        this.y = A;
        this.x = u
    };
    this.setPublic = function(w, v, u, z) {
        this.isPublic = true;
        this.p = w;
        this.q = v;
        this.g = u;
        this.y = z;
        this.x = null
    };
    this.signWithMessageHash = function(z) {
        var v = this.p;
        var u = this.q;
        var C = this.g;
        var D = this.y;
        var E = this.x;
        var A = z.substr(0, u.bitLength() / 4);
        var B = new BigInteger(z, 16);
        var w = n(BigInteger.ONE.add(BigInteger.ONE), u.subtract(BigInteger.ONE));
        var G = (C.modPow(w, v)).mod(u);
        var F = (w.modInverse(u).multiply(B.add(E.multiply(G)))).mod(u);
        var H = KJUR.asn1.ASN1Util.jsonToASN1HEX({ seq: [{ "int": { bigint: G } }, { "int": { bigint: F } }] });
        return H
    };
    this.verifyWithMessageHash = function(C, B) {
        var z = this.p;
        var u = this.q;
        var G = this.g;
        var H = this.y;
        var E = this.parseASN1Signature(B);
        var K = E[0];
        var J = E[1];
        var C = C.substr(0, u.bitLength() / 4);
        var D = new BigInteger(C, 16);
        if (BigInteger.ZERO.compareTo(K) > 0 || K.compareTo(u) > 0 || BigInteger.ZERO.compareTo(J) > 0 || J.compareTo(u) > 0) {
            throw "invalid DSA signature"
        }
        var I = J.modInverse(u);
        var A = D.multiply(I).mod(u);
        var v = K.multiply(I).mod(u);
        var F = G.modPow(A, z).multiply(H.modPow(v, z)).mod(z).mod(u);
        return F.compareTo(K) == 0
    };
    this.parseASN1Signature = function(u) {
        try {
            var y = new BigInteger(ASN1HEX.getVbyList(u, 0, [0], "02"), 16);
            var v = new BigInteger(ASN1HEX.getVbyList(u, 0, [1], "02"), 16);
            return [y, v]
        } catch (w) {
            throw "malformed DSA signature"
        }
    };

    function d(E, w, B, v, u, C) {
        var z = KJUR.crypto.Util.hashString(w, E.toLowerCase());
        var z = z.substr(0, u.bitLength() / 4);
        var A = new BigInteger(z, 16);
        var y = n(BigInteger.ONE.add(BigInteger.ONE), u.subtract(BigInteger.ONE));
        var F = (B.modPow(y, v)).mod(u);
        var D = (y.modInverse(u).multiply(A.add(C.multiply(F)))).mod(u);
        var G = new Array();
        G[0] = F;
        G[1] = D;
        return G
    }

    function r(v) {
        var u = openpgp.config.config.prefer_hash_algorithm;
        switch (Math.round(v.bitLength() / 8)) {
            case 20:
                if (u != 2 && u > 11 && u != 10 && u < 8) {
                    return 2
                }
                return u;
            case 28:
                if (u > 11 && u < 8) {
                    return 11
                }
                return u;
            case 32:
                if (u > 10 && u < 8) {
                    return 8
                }
                return u;
            default:
                util.print_debug("DSA select hash algorithm: returning null for an unknown length of q");
                return null
        }
    }
    this.select_hash_algorithm = r;

    function m(I, K, J, B, z, u, F, G) {
        var C = KJUR.crypto.Util.hashString(B, I.toLowerCase());
        var C = C.substr(0, u.bitLength() / 4);
        var D = new BigInteger(C, 16);
        if (BigInteger.ZERO.compareTo(K) > 0 || K.compareTo(u) > 0 || BigInteger.ZERO.compareTo(J) > 0 || J.compareTo(u) > 0) {
            util.print_error("invalid DSA Signature");
            return null
        }
        var H = J.modInverse(u);
        var A = D.multiply(H).mod(u);
        var v = K.multiply(H).mod(u);
        var E = F.modPow(A, z).multiply(G.modPow(v, z)).mod(z).mod(u);
        return E.compareTo(K) == 0
    }

    function a(z) {
        var A = new BigInteger(z, primeCenterie);
        var y = j(q, 512);
        var u = t(p, q, z);
        var v;
        do { v = new BigInteger(q.bitCount(), rand) } while (x.compareTo(BigInteger.ZERO) != 1 && x.compareTo(q) != -1);
        var w = g.modPow(x, p);
        return { x: v, q: A, p: y, g: u, y: w }
    }

    function j(y, z, w) {
        if (z % 64 != 0) {
            return false
        }
        var u;
        var v;
        do {
            u = w(bitcount, true);
            v = u.subtract(BigInteger.ONE);
            u = u.subtract(v.remainder(y))
        } while (!u.isProbablePrime(primeCenterie) || u.bitLength() != l);
        return u
    }

    function t(B, z, A, w) {
        var u = B.subtract(BigInteger.ONE);
        var y = u.divide(z);
        var v;
        do { v = w(A) } while (v.compareTo(u) != -1 && v.compareTo(BigInteger.ONE) != 1);
        return v.modPow(y, B)
    }

    function o(w, y, u) {
        var v;
        do { v = u(y, false) } while (v.compareTo(w) != -1 && v.compareTo(BigInteger.ZERO) != 1);
        return v
    }

    function i(v, w) {
        k = o(v);
        var u = g.modPow(k, w).mod(v);
        return u
    }

    function h(B, w, y, v, z, u) {
        var A = B(v);
        s = (w.modInverse(z).multiply(A.add(u.multiply(y)))).mod(z);
        return s
    }
    this.sign = d;
    this.verify = m;

    function n(w, u) {
        if (u.compareTo(w) <= 0) {
            return
        }
        var v = u.subtract(w);
        var y = e(v.bitLength());
        while (y > v) { y = e(v.bitLength()) }
        return w.add(y)
    }

    function e(w) {
        if (w < 0) {
            return null
        }
        var u = Math.floor((w + 7) / 8);
        var v = c(u);
        if (w % 8 > 0) { v = String.fromCharCode((Math.pow(2, w % 8) - 1) & v.charCodeAt(0)) + v.substring(1) }
        return new BigInteger(f(v), 16)
    }

    function c(w) {
        var u = "";
        for (var v = 0; v < w; v++) { u += String.fromCharCode(b()) }
        return u
    }

    function b() {
        var u = new Uint32Array(1);
        window.crypto.getRandomValues(u);
        return u[0] & 255
    }

    function f(y) {
        if (y == null) {
            return ""
        }
        var v = [];
        var w = y.length;
        var z = 0;
        var u;
        while (z < w) {
            u = y[z++].charCodeAt().toString(16);
            while (u.length < 2) { u = "0" + u }
            v.push("" + u)
        }
        return v.join("")
    }
    this.getRandomBigIntegerInRange = n;
    this.getRandomBigInteger = e;
    this.getRandomBytes = c
};
/*! pkcs5pkey-1.0.6.js (c) 2013-2014 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
var PKCS5PKEY = function() {
    var c = function(n, p, o) {
        return i(CryptoJS.AES, n, p, o)
    };
    var d = function(n, p, o) {
        return i(CryptoJS.TripleDES, n, p, o)
    };
    var i = function(q, v, s, o) {
        var p = CryptoJS.enc.Hex.parse(v);
        var u = CryptoJS.enc.Hex.parse(s);
        var n = CryptoJS.enc.Hex.parse(o);
        var r = {};
        r.key = u;
        r.iv = n;
        r.ciphertext = p;
        var t = q.decrypt(r, u, { iv: n });
        return CryptoJS.enc.Hex.stringify(t)
    };
    var j = function(n, p, o) {
        return e(CryptoJS.AES, n, p, o)
    };
    var m = function(n, p, o) {
        return e(CryptoJS.TripleDES, n, p, o)
    };
    var e = function(s, x, v, p) {
        var r = CryptoJS.enc.Hex.parse(x);
        var w = CryptoJS.enc.Hex.parse(v);
        var o = CryptoJS.enc.Hex.parse(p);
        var n = {};
        var u = s.encrypt(r, w, { iv: o });
        var q = CryptoJS.enc.Hex.parse(u.toString());
        var t = CryptoJS.enc.Base64.stringify(q);
        return t
    };
    var g = { "AES-256-CBC": { proc: c, eproc: j, keylen: 32, ivlen: 16 }, "AES-192-CBC": { proc: c, eproc: j, keylen: 24, ivlen: 16 }, "AES-128-CBC": { proc: c, eproc: j, keylen: 16, ivlen: 16 }, "DES-EDE3-CBC": { proc: d, eproc: m, keylen: 24, ivlen: 8 } };
    var b = function(n) {
        return g[n]["proc"]
    };
    var k = function(n) {
        var p = CryptoJS.lib.WordArray.random(n);
        var o = CryptoJS.enc.Hex.stringify(p);
        return o
    };
    var l = function(q) {
        var r = {};
        if (q.match(new RegExp("DEK-Info: ([^,]+),([0-9A-Fa-f]+)", "m"))) {
            r.cipher = RegExp.$1;
            r.ivsalt = RegExp.$2
        }
        if (q.match(new RegExp("-----BEGIN ([A-Z]+) PRIVATE KEY-----"))) { r.type = RegExp.$1 }
        var p = -1;
        var t = 0;
        if (q.indexOf("\r\n\r\n") != -1) {
            p = q.indexOf("\r\n\r\n");
            t = 2
        }
        if (q.indexOf("\n\n") != -1) {
            p = q.indexOf("\n\n");
            t = 1
        }
        var o = q.indexOf("-----END");
        if (p != -1 && o != -1) {
            var n = q.substring(p + t * 2, o - t);
            n = n.replace(/\s+/g, "");
            r.data = n
        }
        return r
    };
    var h = function(o, w, n) {
        var t = n.substring(0, 16);
        var r = CryptoJS.enc.Hex.parse(t);
        var p = CryptoJS.enc.Utf8.parse(w);
        var s = g[o]["keylen"] + g[o]["ivlen"];
        var v = "";
        var u = null;
        for (;;) {
            var q = CryptoJS.algo.MD5.create();
            if (u != null) { q.update(u) }
            q.update(p);
            q.update(r);
            u = q.finalize();
            v = v + CryptoJS.enc.Hex.stringify(u);
            if (v.length >= s * 2) {
                break
            }
        }
        var x = {};
        x.keyhex = v.substr(0, g[o]["keylen"] * 2);
        x.ivhex = v.substr(g[o]["keylen"] * 2, g[o]["ivlen"] * 2);
        return x
    };
    var a = function(n, t, p, u) {
        var q = CryptoJS.enc.Base64.parse(n);
        var o = CryptoJS.enc.Hex.stringify(q);
        var s = g[t]["proc"];
        var r = s(o, p, u);
        return r
    };
    var f = function(n, q, o, s) {
        var p = g[q]["eproc"];
        var r = p(n, o, s);
        return r
    };
    return {
        version: "1.0.5",
        getHexFromPEM: function(o, r) {
            var p = o;
            if (p.indexOf("BEGIN " + r) == -1) {
                throw "can't find PEM header: " + r
            }
            p = p.replace("-----BEGIN " + r + "-----", "");
            p = p.replace("-----END " + r + "-----", "");
            var q = p.replace(/\s+/g, "");
            var n = b64tohex(q);
            return n
        },
        getDecryptedKeyHexByKeyIV: function(o, r, q, p) {
            var n = b(r);
            return n(o, q, p)
        },
        parsePKCS5PEM: function(n) {
            return l(n)
        },
        getKeyAndUnusedIvByPasscodeAndIvsalt: function(o, n, p) {
            return h(o, n, p)
        },
        decryptKeyB64: function(n, p, o, q) {
            return a(n, p, o, q)
        },
        getDecryptedKeyHex: function(w, v) {
            var o = l(w);
            var r = o.type;
            var p = o.cipher;
            var n = o.ivsalt;
            var q = o.data;
            var u = h(p, v, n);
            var t = u.keyhex;
            var s = a(q, p, t, n);
            return s
        },
        getRSAKeyFromEncryptedPKCS5PEM: function(p, o) {
            var q = this.getDecryptedKeyHex(p, o);
            var n = new RSAKey();
            n.readPrivateKeyFromASN1HexString(q);
            return n
        },
        getEryptedPKCS5PEMFromPrvKeyHex: function(q, x, r, p) {
            var n = "";
            if (typeof r == "undefined" || r == null) { r = "AES-256-CBC" }
            if (typeof g[r] == "undefined") {
                throw "PKCS5PKEY unsupported algorithm: " + r
            }
            if (typeof p == "undefined" || p == null) {
                var t = g[r]["ivlen"];
                var s = k(t);
                p = s.toUpperCase()
            }
            var w = h(r, x, p);
            var v = w.keyhex;
            var u = f(q, r, v, p);
            var o = u.replace(/(.{64})/g, "$1\r\n");
            var n = "-----BEGIN RSA PRIVATE KEY-----\r\n";
            n += "Proc-Type: 4,ENCRYPTED\r\n";
            n += "DEK-Info: " + r + "," + p + "\r\n";
            n += "\r\n";
            n += o;
            n += "\r\n-----END RSA PRIVATE KEY-----\r\n";
            return n
        },
        getEryptedPKCS5PEMFromRSAKey: function(C, D, o, s) {
            var A = new KJUR.asn1.DERInteger({ "int": 0 });
            var v = new KJUR.asn1.DERInteger({ bigint: C.n });
            var z = new KJUR.asn1.DERInteger({ "int": C.e });
            var B = new KJUR.asn1.DERInteger({ bigint: C.d });
            var t = new KJUR.asn1.DERInteger({ bigint: C.p });
            var r = new KJUR.asn1.DERInteger({ bigint: C.q });
            var y = new KJUR.asn1.DERInteger({ bigint: C.dmp1 });
            var u = new KJUR.asn1.DERInteger({ bigint: C.dmq1 });
            var x = new KJUR.asn1.DERInteger({ bigint: C.coeff });
            var E = new KJUR.asn1.DERSequence({ array: [A, v, z, B, t, r, y, u, x] });
            var w = E.getEncodedHex();
            return this.getEryptedPKCS5PEMFromPrvKeyHex(w, D, o, s)
        },
        newEncryptedPKCS5PEM: function(n, o, r, s) {
            if (typeof o == "undefined" || o == null) { o = 1024 }
            if (typeof r == "undefined" || r == null) { r = "10001" }
            var p = new RSAKey();
            p.generate(o, r);
            var q = null;
            if (typeof s == "undefined" || s == null) { q = this.getEncryptedPKCS5PEMFromRSAKey(pkey, n) } else { q = this.getEncryptedPKCS5PEMFromRSAKey(pkey, n, s) }
            return q
        },
        getRSAKeyFromPlainPKCS8PEM: function(p) {
            if (p.match(/ENCRYPTED/)) {
                throw "pem shall be not ENCRYPTED"
            }
            var o = this.getHexFromPEM(p, "PRIVATE KEY");
            var n = this.getRSAKeyFromPlainPKCS8Hex(o);
            return n
        },
        getRSAKeyFromPlainPKCS8Hex: function(q) {
            var p = ASN1HEX.getPosArrayOfChildren_AtObj(q, 0);
            if (p.length != 3) {
                throw "outer DERSequence shall have 3 elements: " + p.length
            }
            var o = ASN1HEX.getHexOfTLV_AtObj(q, p[1]);
            if (o != "300d06092a864886f70d0101010500") {
                throw "PKCS8 AlgorithmIdentifier is not rsaEnc: " + o
            }
            var o = ASN1HEX.getHexOfTLV_AtObj(q, p[1]);
            var r = ASN1HEX.getHexOfTLV_AtObj(q, p[2]);
            var s = ASN1HEX.getHexOfV_AtObj(r, 0);
            var n = new RSAKey();
            n.readPrivateKeyFromASN1HexString(s);
            return n
        },
        parseHexOfEncryptedPKCS8: function(u) {
            var q = {};
            var p = ASN1HEX.getPosArrayOfChildren_AtObj(u, 0);
            if (p.length != 2) {
                throw "malformed format: SEQUENCE(0).items != 2: " + p.length
            }
            q.ciphertext = ASN1HEX.getHexOfV_AtObj(u, p[1]);
            var w = ASN1HEX.getPosArrayOfChildren_AtObj(u, p[0]);
            if (w.length != 2) {
                throw "malformed format: SEQUENCE(0.0).items != 2: " + w.length
            }
            if (ASN1HEX.getHexOfV_AtObj(u, w[0]) != "2a864886f70d01050d") {
                throw "this only supports pkcs5PBES2"
            }
            var n = ASN1HEX.getPosArrayOfChildren_AtObj(u, w[1]);
            if (w.length != 2) {
                throw "malformed format: SEQUENCE(0.0.1).items != 2: " + n.length
            }
            var o = ASN1HEX.getPosArrayOfChildren_AtObj(u, n[1]);
            if (o.length != 2) {
                throw "malformed format: SEQUENCE(0.0.1.1).items != 2: " + o.length
            }
            if (ASN1HEX.getHexOfV_AtObj(u, o[0]) != "2a864886f70d0307") {
                throw "this only supports TripleDES"
            }
            q.encryptionSchemeAlg = "TripleDES";
            q.encryptionSchemeIV = ASN1HEX.getHexOfV_AtObj(u, o[1]);
            var r = ASN1HEX.getPosArrayOfChildren_AtObj(u, n[0]);
            if (r.length != 2) {
                throw "malformed format: SEQUENCE(0.0.1.0).items != 2: " + r.length
            }
            if (ASN1HEX.getHexOfV_AtObj(u, r[0]) != "2a864886f70d01050c") {
                throw "this only supports pkcs5PBKDF2"
            }
            var v = ASN1HEX.getPosArrayOfChildren_AtObj(u, r[1]);
            if (v.length < 2) {
                throw "malformed format: SEQUENCE(0.0.1.0.1).items < 2: " + v.length
            }
            q.pbkdf2Salt = ASN1HEX.getHexOfV_AtObj(u, v[0]);
            var s = ASN1HEX.getHexOfV_AtObj(u, v[1]);
            try { q.pbkdf2Iter = parseInt(s, 16) } catch (t) {
                throw "malformed format pbkdf2Iter: " + s
            }
            return q
        },
        getPBKDF2KeyHexFromParam: function(s, n) {
            var r = CryptoJS.enc.Hex.parse(s.pbkdf2Salt);
            var o = s.pbkdf2Iter;
            var q = CryptoJS.PBKDF2(n, r, { keySize: 192 / 32, iterations: o });
            var p = CryptoJS.enc.Hex.stringify(q);
            return p
        },
        getPlainPKCS8HexFromEncryptedPKCS8PEM: function(v, w) {
            var p = this.getHexFromPEM(v, "ENCRYPTED PRIVATE KEY");
            var n = this.parseHexOfEncryptedPKCS8(p);
            var s = PKCS5PKEY.getPBKDF2KeyHexFromParam(n, w);
            var t = {};
            t.ciphertext = CryptoJS.enc.Hex.parse(n.ciphertext);
            var r = CryptoJS.enc.Hex.parse(s);
            var q = CryptoJS.enc.Hex.parse(n.encryptionSchemeIV);
            var u = CryptoJS.TripleDES.decrypt(t, r, { iv: q });
            var o = CryptoJS.enc.Hex.stringify(u);
            return o
        },
        getRSAKeyFromEncryptedPKCS8PEM: function(q, p) {
            var o = this.getPlainPKCS8HexFromEncryptedPKCS8PEM(q, p);
            var n = this.getRSAKeyFromPlainPKCS8Hex(o);
            return n
        },
        getKeyFromEncryptedPKCS8PEM: function(q, o) {
            var n = this.getPlainPKCS8HexFromEncryptedPKCS8PEM(q, o);
            var p = this.getKeyFromPlainPrivatePKCS8Hex(n);
            return p
        },
        parsePlainPrivatePKCS8Hex: function(q) {
            var o = {};
            o.algparam = null;
            if (q.substr(0, 2) != "30") {
                throw "malformed plain PKCS8 private key(code:001)"
            }
            var p = ASN1HEX.getPosArrayOfChildren_AtObj(q, 0);
            if (p.length != 3) {
                throw "malformed plain PKCS8 private key(code:002)"
            }
            if (q.substr(p[1], 2) != "30") {
                throw "malformed PKCS8 private key(code:003)"
            }
            var n = ASN1HEX.getPosArrayOfChildren_AtObj(q, p[1]);
            if (n.length != 2) {
                throw "malformed PKCS8 private key(code:004)"
            }
            if (q.substr(n[0], 2) != "06") {
                throw "malformed PKCS8 private key(code:005)"
            }
            o.algoid = ASN1HEX.getHexOfV_AtObj(q, n[0]);
            if (q.substr(n[1], 2) == "06") { o.algparam = ASN1HEX.getHexOfV_AtObj(q, n[1]) }
            if (q.substr(p[2], 2) != "04") {
                throw "malformed PKCS8 private key(code:006)"
            }
            o.keyidx = ASN1HEX.getStartPosOfV_AtObj(q, p[2]);
            return o
        },
        getKeyFromPlainPrivatePKCS8PEM: function(o) {
            var n = this.getHexFromPEM(o, "PRIVATE KEY");
            var p = this.getKeyFromPlainPrivatePKCS8Hex(n);
            return p
        },
        getKeyFromPlainPrivatePKCS8Hex: function(n) {
            var p = this.parsePlainPrivatePKCS8Hex(n);
            if (p.algoid == "2a864886f70d010101") {
                this.parsePrivateRawRSAKeyHexAtObj(n, p);
                var o = p.key;
                var q = new RSAKey();
                q.setPrivateEx(o.n, o.e, o.d, o.p, o.q, o.dp, o.dq, o.co);
                return q
            } else {
                if (p.algoid == "2a8648ce3d0201") {
                    this.parsePrivateRawECKeyHexAtObj(n, p);
                    if (KJUR.crypto.OID.oidhex2name[p.algparam] === undefined) {
                        throw "KJUR.crypto.OID.oidhex2name undefined: " + p.algparam
                    }
                    var r = KJUR.crypto.OID.oidhex2name[p.algparam];
                    var q = new KJUR.crypto.ECDSA({ curve: r, prv: p.key });
                    return q
                } else {
                    throw "unsupported private key algorithm"
                }
            }
        },
        getRSAKeyFromPublicPKCS8PEM: function(o) {
            var p = this.getHexFromPEM(o, "PUBLIC KEY");
            var n = this.getRSAKeyFromPublicPKCS8Hex(p);
            return n
        },
        getKeyFromPublicPKCS8PEM: function(o) {
            var p = this.getHexFromPEM(o, "PUBLIC KEY");
            var n = this.getKeyFromPublicPKCS8Hex(p);
            return n
        },
        getKeyFromPublicPKCS8Hex: function(o) {
            var n = this.parsePublicPKCS8Hex(o);
            if (n.algoid == "2a864886f70d010101") {
                var r = this.parsePublicRawRSAKeyHex(n.key);
                var p = new RSAKey();
                p.setPublic(r.n, r.e);
                return p
            } else {
                if (n.algoid == "2a8648ce3d0201") {
                    if (KJUR.crypto.OID.oidhex2name[n.algparam] === undefined) {
                        throw "KJUR.crypto.OID.oidhex2name undefined: " + n.algparam
                    }
                    var q = KJUR.crypto.OID.oidhex2name[n.algparam];
                    var p = new KJUR.crypto.ECDSA({ curve: q, pub: n.key });
                    return p
                } else {
                    throw "unsupported public key algorithm"
                }
            }
        },
        parsePublicRawRSAKeyHex: function(p) {
            var n = {};
            if (p.substr(0, 2) != "30") {
                throw "malformed RSA key(code:001)"
            }
            var o = ASN1HEX.getPosArrayOfChildren_AtObj(p, 0);
            if (o.length != 2) {
                throw "malformed RSA key(code:002)"
            }
            if (p.substr(o[0], 2) != "02") {
                throw "malformed RSA key(code:003)"
            }
            n.n = ASN1HEX.getHexOfV_AtObj(p, o[0]);
            if (p.substr(o[1], 2) != "02") {
                throw "malformed RSA key(code:004)"
            }
            n.e = ASN1HEX.getHexOfV_AtObj(p, o[1]);
            return n
        },
        parsePrivateRawRSAKeyHexAtObj: function(o, q) {
            var p = q.keyidx;
            if (o.substr(p, 2) != "30") {
                throw "malformed RSA private key(code:001)"
            }
            var n = ASN1HEX.getPosArrayOfChildren_AtObj(o, p);
            if (n.length != 9) {
                throw "malformed RSA private key(code:002)"
            }
            q.key = {};
            q.key.n = ASN1HEX.getHexOfV_AtObj(o, n[1]);
            q.key.e = ASN1HEX.getHexOfV_AtObj(o, n[2]);
            q.key.d = ASN1HEX.getHexOfV_AtObj(o, n[3]);
            q.key.p = ASN1HEX.getHexOfV_AtObj(o, n[4]);
            q.key.q = ASN1HEX.getHexOfV_AtObj(o, n[5]);
            q.key.dp = ASN1HEX.getHexOfV_AtObj(o, n[6]);
            q.key.dq = ASN1HEX.getHexOfV_AtObj(o, n[7]);
            q.key.co = ASN1HEX.getHexOfV_AtObj(o, n[8])
        },
        parsePrivateRawECKeyHexAtObj: function(o, q) {
            var p = q.keyidx;
            if (o.substr(p, 2) != "30") {
                throw "malformed ECC private key(code:001)"
            }
            var n = ASN1HEX.getPosArrayOfChildren_AtObj(o, p);
            if (n.length != 3) {
                throw "malformed ECC private key(code:002)"
            }
            if (o.substr(n[1], 2) != "04") {
                throw "malformed ECC private key(code:003)"
            }
            q.key = ASN1HEX.getHexOfV_AtObj(o, n[1])
        },
        parsePublicPKCS8Hex: function(q) {
            var o = {};
            o.algparam = null;
            var p = ASN1HEX.getPosArrayOfChildren_AtObj(q, 0);
            if (p.length != 2) {
                throw "outer DERSequence shall have 2 elements: " + p.length
            }
            var r = p[0];
            if (q.substr(r, 2) != "30") {
                throw "malformed PKCS8 public key(code:001)"
            }
            var n = ASN1HEX.getPosArrayOfChildren_AtObj(q, r);
            if (n.length != 2) {
                throw "malformed PKCS8 public key(code:002)"
            }
            if (q.substr(n[0], 2) != "06") {
                throw "malformed PKCS8 public key(code:003)"
            }
            o.algoid = ASN1HEX.getHexOfV_AtObj(q, n[0]);
            if (q.substr(n[1], 2) == "06") { o.algparam = ASN1HEX.getHexOfV_AtObj(q, n[1]) }
            if (q.substr(p[1], 2) != "03") {
                throw "malformed PKCS8 public key(code:004)"
            }
            o.key = ASN1HEX.getHexOfV_AtObj(q, p[1]).substr(2);
            return o
        },
        getRSAKeyFromPublicPKCS8Hex: function(r) {
            var q = ASN1HEX.getPosArrayOfChildren_AtObj(r, 0);
            if (q.length != 2) {
                throw "outer DERSequence shall have 2 elements: " + q.length
            }
            var p = ASN1HEX.getHexOfTLV_AtObj(r, q[0]);
            if (p != "300d06092a864886f70d0101010500") {
                throw "PKCS8 AlgorithmId is not rsaEncryption"
            }
            if (r.substr(q[1], 2) != "03") {
                throw "PKCS8 Public Key is not BITSTRING encapslated."
            }
            var t = ASN1HEX.getStartPosOfV_AtObj(r, q[1]) + 2;
            if (r.substr(t, 2) != "30") {
                throw "PKCS8 Public Key is not SEQUENCE."
            }
            var n = ASN1HEX.getPosArrayOfChildren_AtObj(r, t);
            if (n.length != 2) {
                throw "inner DERSequence shall have 2 elements: " + n.length
            }
            if (r.substr(n[0], 2) != "02") {
                throw "N is not ASN.1 INTEGER"
            }
            if (r.substr(n[1], 2) != "02") {
                throw "E is not ASN.1 INTEGER"
            }
            var u = ASN1HEX.getHexOfV_AtObj(r, n[0]);
            var s = ASN1HEX.getHexOfV_AtObj(r, n[1]);
            var o = new RSAKey();
            o.setPublic(u, s);
            return o
        },
    }
}();
/*! keyutil-1.0.12.js (c) 2013-2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
var KEYUTIL = function() {
    var d = function(p, r, q) {
        return k(CryptoJS.AES, p, r, q)
    };
    var e = function(p, r, q) {
        return k(CryptoJS.TripleDES, p, r, q)
    };
    var a = function(p, r, q) {
        return k(CryptoJS.DES, p, r, q)
    };
    var k = function(s, x, u, q) {
        var r = CryptoJS.enc.Hex.parse(x);
        var w = CryptoJS.enc.Hex.parse(u);
        var p = CryptoJS.enc.Hex.parse(q);
        var t = {};
        t.key = w;
        t.iv = p;
        t.ciphertext = r;
        var v = s.decrypt(t, w, { iv: p });
        return CryptoJS.enc.Hex.stringify(v)
    };
    var l = function(p, r, q) {
        return g(CryptoJS.AES, p, r, q)
    };
    var o = function(p, r, q) {
        return g(CryptoJS.TripleDES, p, r, q)
    };
    var f = function(p, r, q) {
        return g(CryptoJS.DES, p, r, q)
    };
    var g = function(t, y, v, q) {
        var s = CryptoJS.enc.Hex.parse(y);
        var x = CryptoJS.enc.Hex.parse(v);
        var p = CryptoJS.enc.Hex.parse(q);
        var w = t.encrypt(s, x, { iv: p });
        var r = CryptoJS.enc.Hex.parse(w.toString());
        var u = CryptoJS.enc.Base64.stringify(r);
        return u
    };
    var i = { "AES-256-CBC": { proc: d, eproc: l, keylen: 32, ivlen: 16 }, "AES-192-CBC": { proc: d, eproc: l, keylen: 24, ivlen: 16 }, "AES-128-CBC": { proc: d, eproc: l, keylen: 16, ivlen: 16 }, "DES-EDE3-CBC": { proc: e, eproc: o, keylen: 24, ivlen: 8 }, "DES-CBC": { proc: a, eproc: f, keylen: 8, ivlen: 8 } };
    var c = function(p) {
        return i[p]["proc"]
    };
    var m = function(p) {
        var r = CryptoJS.lib.WordArray.random(p);
        var q = CryptoJS.enc.Hex.stringify(r);
        return q
    };
    var n = function(t) {
        var u = {};
        if (t.match(new RegExp("DEK-Info: ([^,]+),([0-9A-Fa-f]+)", "m"))) {
            u.cipher = RegExp.$1;
            u.ivsalt = RegExp.$2
        }
        if (t.match(new RegExp("-----BEGIN ([A-Z]+) PRIVATE KEY-----"))) { u.type = RegExp.$1 }
        var r = -1;
        var v = 0;
        if (t.indexOf("\r\n\r\n") != -1) {
            r = t.indexOf("\r\n\r\n");
            v = 2
        }
        if (t.indexOf("\n\n") != -1) {
            r = t.indexOf("\n\n");
            v = 1
        }
        var q = t.indexOf("-----END");
        if (r != -1 && q != -1) {
            var p = t.substring(r + v * 2, q - v);
            p = p.replace(/\s+/g, "");
            u.data = p
        }
        return u
    };
    var j = function(q, y, p) {
        var v = p.substring(0, 16);
        var t = CryptoJS.enc.Hex.parse(v);
        var r = CryptoJS.enc.Utf8.parse(y);
        var u = i[q]["keylen"] + i[q]["ivlen"];
        var x = "";
        var w = null;
        for (;;) {
            var s = CryptoJS.algo.MD5.create();
            if (w != null) { s.update(w) }
            s.update(r);
            s.update(t);
            w = s.finalize();
            x = x + CryptoJS.enc.Hex.stringify(w);
            if (x.length >= u * 2) {
                break
            }
        }
        var z = {};
        z.keyhex = x.substr(0, i[q]["keylen"] * 2);
        z.ivhex = x.substr(i[q]["keylen"] * 2, i[q]["ivlen"] * 2);
        return z
    };
    var b = function(p, v, r, w) {
        var s = CryptoJS.enc.Base64.parse(p);
        var q = CryptoJS.enc.Hex.stringify(s);
        var u = i[v]["proc"];
        var t = u(q, r, w);
        return t
    };
    var h = function(p, s, q, u) {
        var r = i[s]["eproc"];
        var t = r(p, q, u);
        return t
    };
    return {
        version: "1.0.0",
        getHexFromPEM: function(q, u) {
            var r = q;
            if (r.indexOf("-----BEGIN ") == -1) {
                throw "can't find PEM header: " + u
            }
            if (typeof u == "string" && u != "") {
                r = r.replace("-----BEGIN " + u + "-----", "");
                r = r.replace("-----END " + u + "-----", "")
            } else {
                r = r.replace(/-----BEGIN [^-]+-----/, "");
                r = r.replace(/-----END [^-]+-----/, "")
            }
            var t = r.replace(/\s+/g, "");
            var p = b64tohex(t);
            return p
        },
        getDecryptedKeyHexByKeyIV: function(q, t, s, r) {
            var p = c(t);
            return p(q, s, r)
        },
        parsePKCS5PEM: function(p) {
            return n(p)
        },
        getKeyAndUnusedIvByPasscodeAndIvsalt: function(q, p, r) {
            return j(q, p, r)
        },
        decryptKeyB64: function(p, r, q, s) {
            return b(p, r, q, s)
        },
        getDecryptedKeyHex: function(y, x) {
            var q = n(y);
            var t = q.type;
            var r = q.cipher;
            var p = q.ivsalt;
            var s = q.data;
            var w = j(r, x, p);
            var v = w.keyhex;
            var u = b(s, r, v, p);
            return u
        },
        getRSAKeyFromEncryptedPKCS5PEM: function(r, q) {
            var s = this.getDecryptedKeyHex(r, q);
            var p = new RSAKey();
            p.readPrivateKeyFromASN1HexString(s);
            return p
        },
        getEncryptedPKCS5PEMFromPrvKeyHex: function(x, s, A, t, r) {
            var p = "";
            if (typeof t == "undefined" || t == null) { t = "AES-256-CBC" }
            if (typeof i[t] == "undefined") {
                throw "KEYUTIL unsupported algorithm: " + t
            }
            if (typeof r == "undefined" || r == null) {
                var v = i[t]["ivlen"];
                var u = m(v);
                r = u.toUpperCase()
            }
            var z = j(t, A, r);
            var y = z.keyhex;
            var w = h(s, t, y, r);
            var q = w.replace(/(.{64})/g, "$1\r\n");
            var p = "-----BEGIN " + x + " PRIVATE KEY-----\r\n";
            p += "Proc-Type: 4,ENCRYPTED\r\n";
            p += "DEK-Info: " + t + "," + r + "\r\n";
            p += "\r\n";
            p += q;
            p += "\r\n-----END " + x + " PRIVATE KEY-----\r\n";
            return p
        },
        getEncryptedPKCS5PEMFromRSAKey: function(D, E, r, t) {
            var B = new KJUR.asn1.DERInteger({ "int": 0 });
            var w = new KJUR.asn1.DERInteger({ bigint: D.n });
            var A = new KJUR.asn1.DERInteger({ "int": D.e });
            var C = new KJUR.asn1.DERInteger({ bigint: D.d });
            var u = new KJUR.asn1.DERInteger({ bigint: D.p });
            var s = new KJUR.asn1.DERInteger({ bigint: D.q });
            var z = new KJUR.asn1.DERInteger({ bigint: D.dmp1 });
            var v = new KJUR.asn1.DERInteger({ bigint: D.dmq1 });
            var y = new KJUR.asn1.DERInteger({ bigint: D.coeff });
            var F = new KJUR.asn1.DERSequence({ array: [B, w, A, C, u, s, z, v, y] });
            var x = F.getEncodedHex();
            return this.getEncryptedPKCS5PEMFromPrvKeyHex("RSA", x, E, r, t)
        },
        newEncryptedPKCS5PEM: function(p, q, t, u) {
            if (typeof q == "undefined" || q == null) { q = 1024 }
            if (typeof t == "undefined" || t == null) { t = "10001" }
            var r = new RSAKey();
            r.generate(q, t);
            var s = null;
            if (typeof u == "undefined" || u == null) { s = this.getEncryptedPKCS5PEMFromRSAKey(r, p) } else { s = this.getEncryptedPKCS5PEMFromRSAKey(r, p, u) }
            return s
        },
        getRSAKeyFromPlainPKCS8PEM: function(r) {
            if (r.match(/ENCRYPTED/)) {
                throw "pem shall be not ENCRYPTED"
            }
            var q = this.getHexFromPEM(r, "PRIVATE KEY");
            var p = this.getRSAKeyFromPlainPKCS8Hex(q);
            return p
        },
        getRSAKeyFromPlainPKCS8Hex: function(s) {
            var r = ASN1HEX.getPosArrayOfChildren_AtObj(s, 0);
            if (r.length != 3) {
                throw "outer DERSequence shall have 3 elements: " + r.length
            }
            var q = ASN1HEX.getHexOfTLV_AtObj(s, r[1]);
            if (q != "300d06092a864886f70d0101010500") {
                throw "PKCS8 AlgorithmIdentifier is not rsaEnc: " + q
            }
            var q = ASN1HEX.getHexOfTLV_AtObj(s, r[1]);
            var t = ASN1HEX.getHexOfTLV_AtObj(s, r[2]);
            var u = ASN1HEX.getHexOfV_AtObj(t, 0);
            var p = new RSAKey();
            p.readPrivateKeyFromASN1HexString(u);
            return p
        },
        parseHexOfEncryptedPKCS8: function(w) {
            var s = {};
            var r = ASN1HEX.getPosArrayOfChildren_AtObj(w, 0);
            if (r.length != 2) {
                throw "malformed format: SEQUENCE(0).items != 2: " + r.length
            }
            s.ciphertext = ASN1HEX.getHexOfV_AtObj(w, r[1]);
            var y = ASN1HEX.getPosArrayOfChildren_AtObj(w, r[0]);
            if (y.length != 2) {
                throw "malformed format: SEQUENCE(0.0).items != 2: " + y.length
            }
            if (ASN1HEX.getHexOfV_AtObj(w, y[0]) != "2a864886f70d01050d") {
                throw "this only supports pkcs5PBES2"
            }
            var p = ASN1HEX.getPosArrayOfChildren_AtObj(w, y[1]);
            if (y.length != 2) {
                throw "malformed format: SEQUENCE(0.0.1).items != 2: " + p.length
            }
            var q = ASN1HEX.getPosArrayOfChildren_AtObj(w, p[1]);
            if (q.length != 2) {
                throw "malformed format: SEQUENCE(0.0.1.1).items != 2: " + q.length
            }
            if (ASN1HEX.getHexOfV_AtObj(w, q[0]) != "2a864886f70d0307") {
                throw "this only supports TripleDES"
            }
            s.encryptionSchemeAlg = "TripleDES";
            s.encryptionSchemeIV = ASN1HEX.getHexOfV_AtObj(w, q[1]);
            var t = ASN1HEX.getPosArrayOfChildren_AtObj(w, p[0]);
            if (t.length != 2) {
                throw "malformed format: SEQUENCE(0.0.1.0).items != 2: " + t.length
            }
            if (ASN1HEX.getHexOfV_AtObj(w, t[0]) != "2a864886f70d01050c") {
                throw "this only supports pkcs5PBKDF2"
            }
            var x = ASN1HEX.getPosArrayOfChildren_AtObj(w, t[1]);
            if (x.length < 2) {
                throw "malformed format: SEQUENCE(0.0.1.0.1).items < 2: " + x.length
            }
            s.pbkdf2Salt = ASN1HEX.getHexOfV_AtObj(w, x[0]);
            var u = ASN1HEX.getHexOfV_AtObj(w, x[1]);
            try { s.pbkdf2Iter = parseInt(u, 16) } catch (v) {
                throw "malformed format pbkdf2Iter: " + u
            }
            return s
        },
        getPBKDF2KeyHexFromParam: function(u, p) {
            var t = CryptoJS.enc.Hex.parse(u.pbkdf2Salt);
            var q = u.pbkdf2Iter;
            var s = CryptoJS.PBKDF2(p, t, { keySize: 192 / 32, iterations: q });
            var r = CryptoJS.enc.Hex.stringify(s);
            return r
        },
        getPlainPKCS8HexFromEncryptedPKCS8PEM: function(x, y) {
            var r = this.getHexFromPEM(x, "ENCRYPTED PRIVATE KEY");
            var p = this.parseHexOfEncryptedPKCS8(r);
            var u = KEYUTIL.getPBKDF2KeyHexFromParam(p, y);
            var v = {};
            v.ciphertext = CryptoJS.enc.Hex.parse(p.ciphertext);
            var t = CryptoJS.enc.Hex.parse(u);
            var s = CryptoJS.enc.Hex.parse(p.encryptionSchemeIV);
            var w = CryptoJS.TripleDES.decrypt(v, t, { iv: s });
            var q = CryptoJS.enc.Hex.stringify(w);
            return q
        },
        getRSAKeyFromEncryptedPKCS8PEM: function(s, r) {
            var q = this.getPlainPKCS8HexFromEncryptedPKCS8PEM(s, r);
            var p = this.getRSAKeyFromPlainPKCS8Hex(q);
            return p
        },
        getKeyFromEncryptedPKCS8PEM: function(s, q) {
            var p = this.getPlainPKCS8HexFromEncryptedPKCS8PEM(s, q);
            var r = this.getKeyFromPlainPrivatePKCS8Hex(p);
            return r
        },
        parsePlainPrivatePKCS8Hex: function(s) {
            var q = {};
            q.algparam = null;
            if (s.substr(0, 2) != "30") {
                throw "malformed plain PKCS8 private key(code:001)"
            }
            var r = ASN1HEX.getPosArrayOfChildren_AtObj(s, 0);
            if (r.length != 3) {
                throw "malformed plain PKCS8 private key(code:002)"
            }
            if (s.substr(r[1], 2) != "30") {
                throw "malformed PKCS8 private key(code:003)"
            }
            var p = ASN1HEX.getPosArrayOfChildren_AtObj(s, r[1]);
            if (p.length != 2) {
                throw "malformed PKCS8 private key(code:004)"
            }
            if (s.substr(p[0], 2) != "06") {
                throw "malformed PKCS8 private key(code:005)"
            }
            q.algoid = ASN1HEX.getHexOfV_AtObj(s, p[0]);
            if (s.substr(p[1], 2) == "06") { q.algparam = ASN1HEX.getHexOfV_AtObj(s, p[1]) }
            if (s.substr(r[2], 2) != "04") {
                throw "malformed PKCS8 private key(code:006)"
            }
            q.keyidx = ASN1HEX.getStartPosOfV_AtObj(s, r[2]);
            return q
        },
        getKeyFromPlainPrivatePKCS8PEM: function(q) {
            var p = this.getHexFromPEM(q, "PRIVATE KEY");
            var r = this.getKeyFromPlainPrivatePKCS8Hex(p);
            return r
        },
        getKeyFromPlainPrivatePKCS8Hex: function(p) {
            var w = this.parsePlainPrivatePKCS8Hex(p);
            if (w.algoid == "2a864886f70d010101") {
                this.parsePrivateRawRSAKeyHexAtObj(p, w);
                var u = w.key;
                var z = new RSAKey();
                z.setPrivateEx(u.n, u.e, u.d, u.p, u.q, u.dp, u.dq, u.co);
                return z
            } else {
                if (w.algoid == "2a8648ce3d0201") {
                    this.parsePrivateRawECKeyHexAtObj(p, w);
                    if (KJUR.crypto.OID.oidhex2name[w.algparam] === undefined) {
                        throw "KJUR.crypto.OID.oidhex2name undefined: " + w.algparam
                    }
                    var v = KJUR.crypto.OID.oidhex2name[w.algparam];
                    var z = new KJUR.crypto.ECDSA({ curve: v });
                    z.setPublicKeyHex(w.pubkey);
                    z.setPrivateKeyHex(w.key);
                    z.isPublic = false;
                    return z
                } else {
                    if (w.algoid == "2a8648ce380401") {
                        var t = ASN1HEX.getVbyList(p, 0, [1, 1, 0], "02");
                        var s = ASN1HEX.getVbyList(p, 0, [1, 1, 1], "02");
                        var y = ASN1HEX.getVbyList(p, 0, [1, 1, 2], "02");
                        var B = ASN1HEX.getVbyList(p, 0, [2, 0], "02");
                        var r = new BigInteger(t, 16);
                        var q = new BigInteger(s, 16);
                        var x = new BigInteger(y, 16);
                        var A = new BigInteger(B, 16);
                        var z = new KJUR.crypto.DSA();
                        z.setPrivate(r, q, x, null, A);
                        return z
                    } else {
                        throw "unsupported private key algorithm"
                    }
                }
            }
        },
        getRSAKeyFromPublicPKCS8PEM: function(q) {
            var r = this.getHexFromPEM(q, "PUBLIC KEY");
            var p = this.getRSAKeyFromPublicPKCS8Hex(r);
            return p
        },
        getKeyFromPublicPKCS8PEM: function(q) {
            var r = this.getHexFromPEM(q, "PUBLIC KEY");
            var p = this.getKeyFromPublicPKCS8Hex(r);
            return p
        },
        getKeyFromPublicPKCS8Hex: function(q) {
            var p = this.parsePublicPKCS8Hex(q);
            if (p.algoid == "2a864886f70d010101") {
                var u = this.parsePublicRawRSAKeyHex(p.key);
                var r = new RSAKey();
                r.setPublic(u.n, u.e);
                return r
            } else {
                if (p.algoid == "2a8648ce3d0201") {
                    if (KJUR.crypto.OID.oidhex2name[p.algparam] === undefined) {
                        throw "KJUR.crypto.OID.oidhex2name undefined: " + p.algparam
                    }
                    var s = KJUR.crypto.OID.oidhex2name[p.algparam];
                    var r = new KJUR.crypto.ECDSA({ curve: s, pub: p.key });
                    return r
                } else {
                    if (p.algoid == "2a8648ce380401") {
                        var t = p.algparam;
                        var v = ASN1HEX.getHexOfV_AtObj(p.key, 0);
                        var r = new KJUR.crypto.DSA();
                        r.setPublic(new BigInteger(t.p, 16), new BigInteger(t.q, 16), new BigInteger(t.g, 16), new BigInteger(v, 16));
                        return r
                    } else {
                        throw "unsupported public key algorithm"
                    }
                }
            }
        },
        parsePublicRawRSAKeyHex: function(r) {
            var p = {};
            if (r.substr(0, 2) != "30") {
                throw "malformed RSA key(code:001)"
            }
            var q = ASN1HEX.getPosArrayOfChildren_AtObj(r, 0);
            if (q.length != 2) {
                throw "malformed RSA key(code:002)"
            }
            if (r.substr(q[0], 2) != "02") {
                throw "malformed RSA key(code:003)"
            }
            p.n = ASN1HEX.getHexOfV_AtObj(r, q[0]);
            if (r.substr(q[1], 2) != "02") {
                throw "malformed RSA key(code:004)"
            }
            p.e = ASN1HEX.getHexOfV_AtObj(r, q[1]);
            return p
        },
        parsePrivateRawRSAKeyHexAtObj: function(q, s) {
            var r = s.keyidx;
            if (q.substr(r, 2) != "30") {
                throw "malformed RSA private key(code:001)"
            }
            var p = ASN1HEX.getPosArrayOfChildren_AtObj(q, r);
            if (p.length != 9) {
                throw "malformed RSA private key(code:002)"
            }
            s.key = {};
            s.key.n = ASN1HEX.getHexOfV_AtObj(q, p[1]);
            s.key.e = ASN1HEX.getHexOfV_AtObj(q, p[2]);
            s.key.d = ASN1HEX.getHexOfV_AtObj(q, p[3]);
            s.key.p = ASN1HEX.getHexOfV_AtObj(q, p[4]);
            s.key.q = ASN1HEX.getHexOfV_AtObj(q, p[5]);
            s.key.dp = ASN1HEX.getHexOfV_AtObj(q, p[6]);
            s.key.dq = ASN1HEX.getHexOfV_AtObj(q, p[7]);
            s.key.co = ASN1HEX.getHexOfV_AtObj(q, p[8])
        },
        parsePrivateRawECKeyHexAtObj: function(p, t) {
            var q = t.keyidx;
            var r = ASN1HEX.getVbyList(p, q, [1], "04");
            var s = ASN1HEX.getVbyList(p, q, [2, 0], "03").substr(2);
            t.key = r;
            t.pubkey = s
        },
        parsePublicPKCS8Hex: function(s) {
            var q = {};
            q.algparam = null;
            var r = ASN1HEX.getPosArrayOfChildren_AtObj(s, 0);
            if (r.length != 2) {
                throw "outer DERSequence shall have 2 elements: " + r.length
            }
            var t = r[0];
            if (s.substr(t, 2) != "30") {
                throw "malformed PKCS8 public key(code:001)"
            }
            var p = ASN1HEX.getPosArrayOfChildren_AtObj(s, t);
            if (p.length != 2) {
                throw "malformed PKCS8 public key(code:002)"
            }
            if (s.substr(p[0], 2) != "06") {
                throw "malformed PKCS8 public key(code:003)"
            }
            q.algoid = ASN1HEX.getHexOfV_AtObj(s, p[0]);
            if (s.substr(p[1], 2) == "06") { q.algparam = ASN1HEX.getHexOfV_AtObj(s, p[1]) } else {
                if (s.substr(p[1], 2) == "30") {
                    q.algparam = {};
                    q.algparam.p = ASN1HEX.getVbyList(s, p[1], [0], "02");
                    q.algparam.q = ASN1HEX.getVbyList(s, p[1], [1], "02");
                    q.algparam.g = ASN1HEX.getVbyList(s, p[1], [2], "02")
                }
            }
            if (s.substr(r[1], 2) != "03") {
                throw "malformed PKCS8 public key(code:004)"
            }
            q.key = ASN1HEX.getHexOfV_AtObj(s, r[1]).substr(2);
            return q
        },
        getRSAKeyFromPublicPKCS8Hex: function(t) {
            var s = ASN1HEX.getPosArrayOfChildren_AtObj(t, 0);
            if (s.length != 2) {
                throw "outer DERSequence shall have 2 elements: " + s.length
            }
            var r = ASN1HEX.getHexOfTLV_AtObj(t, s[0]);
            if (r != "300d06092a864886f70d0101010500") {
                throw "PKCS8 AlgorithmId is not rsaEncryption"
            }
            if (t.substr(s[1], 2) != "03") {
                throw "PKCS8 Public Key is not BITSTRING encapslated."
            }
            var v = ASN1HEX.getStartPosOfV_AtObj(t, s[1]) + 2;
            if (t.substr(v, 2) != "30") {
                throw "PKCS8 Public Key is not SEQUENCE."
            }
            var p = ASN1HEX.getPosArrayOfChildren_AtObj(t, v);
            if (p.length != 2) {
                throw "inner DERSequence shall have 2 elements: " + p.length
            }
            if (t.substr(p[0], 2) != "02") {
                throw "N is not ASN.1 INTEGER"
            }
            if (t.substr(p[1], 2) != "02") {
                throw "E is not ASN.1 INTEGER"
            }
            var w = ASN1HEX.getHexOfV_AtObj(t, p[0]);
            var u = ASN1HEX.getHexOfV_AtObj(t, p[1]);
            var q = new RSAKey();
            q.setPublic(w, u);
            return q
        },
    }
}();
KEYUTIL.getKey = function(f, e, h) {
    if (typeof RSAKey != "undefined" && f instanceof RSAKey) {
        return f
    }
    if (typeof KJUR.crypto.ECDSA != "undefined" && f instanceof KJUR.crypto.ECDSA) {
        return f
    }
    if (typeof KJUR.crypto.DSA != "undefined" && f instanceof KJUR.crypto.DSA) {
        return f
    }
    if (f.curve !== undefined && f.xy !== undefined && f.d === undefined) {
        return new KJUR.crypto.ECDSA({ pub: f.xy, curve: f.curve })
    }
    if (f.curve !== undefined && f.d !== undefined) {
        return new KJUR.crypto.ECDSA({ prv: f.d, curve: f.curve })
    }
    if (f.kty === undefined && f.n !== undefined && f.e !== undefined && f.d === undefined) {
        var w = new RSAKey();
        w.setPublic(f.n, f.e);
        return w
    }
    if (f.kty === undefined && f.n !== undefined && f.e !== undefined && f.d !== undefined && f.p !== undefined && f.q !== undefined && f.dp !== undefined && f.dq !== undefined && f.co !== undefined && f.qi === undefined) {
        var w = new RSAKey();
        w.setPrivateEx(f.n, f.e, f.d, f.p, f.q, f.dp, f.dq, f.co);
        return w
    }
    if (f.kty === undefined && f.n !== undefined && f.e !== undefined && f.d !== undefined && f.p === undefined) {
        var w = new RSAKey();
        w.setPrivate(f.n, f.e, f.d);
        return w
    }
    if (f.p !== undefined && f.q !== undefined && f.g !== undefined && f.y !== undefined && f.x === undefined) {
        var w = new KJUR.crypto.DSA();
        w.setPublic(f.p, f.q, f.g, f.y);
        return w
    }
    if (f.p !== undefined && f.q !== undefined && f.g !== undefined && f.y !== undefined && f.x !== undefined) {
        var w = new KJUR.crypto.DSA();
        w.setPrivate(f.p, f.q, f.g, f.y, f.x);
        return w
    }
    if (f.kty === "RSA" && f.n !== undefined && f.e !== undefined && f.d === undefined) {
        var w = new RSAKey();
        w.setPublic(b64utohex(f.n), b64utohex(f.e));
        return w
    }
    if (f.kty === "RSA" && f.n !== undefined && f.e !== undefined && f.d !== undefined && f.p !== undefined && f.q !== undefined && f.dp !== undefined && f.dq !== undefined && f.qi !== undefined) {
        var w = new RSAKey();
        w.setPrivateEx(b64utohex(f.n), b64utohex(f.e), b64utohex(f.d), b64utohex(f.p), b64utohex(f.q), b64utohex(f.dp), b64utohex(f.dq), b64utohex(f.qi));
        return w
    }
    if (f.kty === "RSA" && f.n !== undefined && f.e !== undefined && f.d !== undefined) {
        var w = new RSAKey();
        w.setPrivate(b64utohex(f.n), b64utohex(f.e), b64utohex(f.d));
        return w
    }
    if (f.kty === "EC" && f.crv !== undefined && f.x !== undefined && f.y !== undefined && f.d === undefined) {
        var d = new KJUR.crypto.ECDSA({ curve: f.crv });
        var l = d.ecparams.keylen / 4;
        var r = ("0000000000" + b64utohex(f.x)).slice(-l);
        var n = ("0000000000" + b64utohex(f.y)).slice(-l);
        var m = "04" + r + n;
        d.setPublicKeyHex(m);
        return d
    }
    if (f.kty === "EC" && f.crv !== undefined && f.x !== undefined && f.y !== undefined && f.d !== undefined) {
        var d = new KJUR.crypto.ECDSA({ curve: f.crv });
        var l = d.ecparams.keylen / 4;
        var a = ("0000000000" + b64utohex(f.d)).slice(-l);
        d.setPrivateKeyHex(a);
        return d
    }
    if (f.indexOf("-END CERTIFICATE-", 0) != -1 || f.indexOf("-END X509 CERTIFICATE-", 0) != -1 || f.indexOf("-END TRUSTED CERTIFICATE-", 0) != -1) {
        return X509.getPublicKeyFromCertPEM(f)
    }
    if (h === "pkcs8pub") {
        return KEYUTIL.getKeyFromPublicPKCS8Hex(f)
    }
    if (f.indexOf("-END PUBLIC KEY-") != -1) {
        return KEYUTIL.getKeyFromPublicPKCS8PEM(f)
    }
    if (h === "pkcs5prv") {
        var w = new RSAKey();
        w.readPrivateKeyFromASN1HexString(f);
        return w
    }
    if (h === "pkcs5prv") {
        var w = new RSAKey();
        w.readPrivateKeyFromASN1HexString(f);
        return w
    }
    if (f.indexOf("-END RSA PRIVATE KEY-") != -1 && f.indexOf("4,ENCRYPTED") == -1) {
        var i = KEYUTIL.getHexFromPEM(f, "RSA PRIVATE KEY");
        return KEYUTIL.getKey(i, null, "pkcs5prv")
    }
    if (f.indexOf("-END DSA PRIVATE KEY-") != -1 && f.indexOf("4,ENCRYPTED") == -1) {
        var u = this.getHexFromPEM(f, "DSA PRIVATE KEY");
        var t = ASN1HEX.getVbyList(u, 0, [1], "02");
        var s = ASN1HEX.getVbyList(u, 0, [2], "02");
        var v = ASN1HEX.getVbyList(u, 0, [3], "02");
        var j = ASN1HEX.getVbyList(u, 0, [4], "02");
        var k = ASN1HEX.getVbyList(u, 0, [5], "02");
        var w = new KJUR.crypto.DSA();
        w.setPrivate(new BigInteger(t, 16), new BigInteger(s, 16), new BigInteger(v, 16), new BigInteger(j, 16), new BigInteger(k, 16));
        return w
    }
    if (f.indexOf("-END PRIVATE KEY-") != -1) {
        return KEYUTIL.getKeyFromPlainPrivatePKCS8PEM(f)
    }
    if (f.indexOf("-END RSA PRIVATE KEY-") != -1 && f.indexOf("4,ENCRYPTED") != -1) {
        return KEYUTIL.getRSAKeyFromEncryptedPKCS5PEM(f, e)
    }
    if (f.indexOf("-END EC PRIVATE KEY-") != -1 && f.indexOf("4,ENCRYPTED") != -1) {
        var u = KEYUTIL.getDecryptedKeyHex(f, e);
        var w = ASN1HEX.getVbyList(u, 0, [1], "04");
        var c = ASN1HEX.getVbyList(u, 0, [2, 0], "06");
        var o = ASN1HEX.getVbyList(u, 0, [3, 0], "03").substr(2);
        var b = "";
        if (KJUR.crypto.OID.oidhex2name[c] !== undefined) { b = KJUR.crypto.OID.oidhex2name[c] } else {
            throw "undefined OID(hex) in KJUR.crypto.OID: " + c
        }
        var d = new KJUR.crypto.ECDSA({ name: b });
        d.setPublicKeyHex(o);
        d.setPrivateKeyHex(w);
        d.isPublic = false;
        return d
    }
    if (f.indexOf("-END DSA PRIVATE KEY-") != -1 && f.indexOf("4,ENCRYPTED") != -1) {
        var u = KEYUTIL.getDecryptedKeyHex(f, e);
        var t = ASN1HEX.getVbyList(u, 0, [1], "02");
        var s = ASN1HEX.getVbyList(u, 0, [2], "02");
        var v = ASN1HEX.getVbyList(u, 0, [3], "02");
        var j = ASN1HEX.getVbyList(u, 0, [4], "02");
        var k = ASN1HEX.getVbyList(u, 0, [5], "02");
        var w = new KJUR.crypto.DSA();
        w.setPrivate(new BigInteger(t, 16), new BigInteger(s, 16), new BigInteger(v, 16), new BigInteger(j, 16), new BigInteger(k, 16));
        return w
    }
    if (f.indexOf("-END ENCRYPTED PRIVATE KEY-") != -1) {
        return KEYUTIL.getKeyFromEncryptedPKCS8PEM(f, e)
    }
    throw "not supported argument"
};
KEYUTIL.generateKeypair = function(a, c) {
    if (a == "RSA") {
        var b = c;
        var h = new RSAKey();
        h.generate(b, "10001");
        h.isPrivate = true;
        h.isPublic = true;
        var f = new RSAKey();
        var e = h.n.toString(16);
        var i = h.e.toString(16);
        f.setPublic(e, i);
        f.isPrivate = false;
        f.isPublic = true;
        var k = {};
        k.prvKeyObj = h;
        k.pubKeyObj = f;
        return k
    } else {
        if (a == "EC") {
            var d = c;
            var g = new KJUR.crypto.ECDSA({ curve: d });
            var j = g.generateKeyPairHex();
            var h = new KJUR.crypto.ECDSA({ curve: d });
            h.setPrivateKeyHex(j.ecprvhex);
            h.isPrivate = true;
            h.isPublic = false;
            var f = new KJUR.crypto.ECDSA({ curve: d });
            f.setPublicKeyHex(j.ecpubhex);
            f.isPrivate = false;
            f.isPublic = true;
            var k = {};
            k.prvKeyObj = h;
            k.pubKeyObj = f;
            return k
        } else {
            throw "unknown algorithm: " + a
        }
    }
};
KEYUTIL.getPEM = function(a, r, o, g, j) {
    var v = KJUR.asn1;
    var u = KJUR.crypto;

    function p(s) {
        var w = KJUR.asn1.ASN1Util.newObject({ seq: [{ "int": 0 }, { "int": { bigint: s.n } }, { "int": s.e }, { "int": { bigint: s.d } }, { "int": { bigint: s.p } }, { "int": { bigint: s.q } }, { "int": { bigint: s.dmp1 } }, { "int": { bigint: s.dmq1 } }, { "int": { bigint: s.coeff } }] });
        return w
    }

    function q(w) {
        var s = KJUR.asn1.ASN1Util.newObject({ seq: [{ "int": 1 }, { octstr: { hex: w.prvKeyHex } }, { tag: ["a0", true, { oid: { name: w.curveName } }] }, { tag: ["a1", true, { bitstr: { hex: "00" + w.pubKeyHex } }] }] });
        return s
    }

    function n(s) {
        var w = KJUR.asn1.ASN1Util.newObject({ seq: [{ "int": 0 }, { "int": { bigint: s.p } }, { "int": { bigint: s.q } }, { "int": { bigint: s.g } }, { "int": { bigint: s.y } }, { "int": { bigint: s.x } }] });
        return w
    }
    if (((typeof RSAKey != "undefined" && a instanceof RSAKey) || (typeof u.DSA != "undefined" && a instanceof u.DSA) || (typeof u.ECDSA != "undefined" && a instanceof u.ECDSA)) && a.isPublic == true && (r === undefined || r == "PKCS8PUB")) {
        var t = new KJUR.asn1.x509.SubjectPublicKeyInfo(a);
        var m = t.getEncodedHex();
        return v.ASN1Util.getPEMStringFromHex(m, "PUBLIC KEY")
    }
    if (r == "PKCS1PRV" && typeof RSAKey != "undefined" && a instanceof RSAKey && (o === undefined || o == null) && a.isPrivate == true) {
        var t = p(a);
        var m = t.getEncodedHex();
        return v.ASN1Util.getPEMStringFromHex(m, "RSA PRIVATE KEY")
    }
    if (r == "PKCS1PRV" && typeof RSAKey != "undefined" && a instanceof KJUR.crypto.ECDSA && (o === undefined || o == null) && a.isPrivate == true) {
        var f = new KJUR.asn1.DERObjectIdentifier({ name: a.curveName });
        var l = f.getEncodedHex();
        var e = q(a);
        var k = e.getEncodedHex();
        var i = "";
        i += v.ASN1Util.getPEMStringFromHex(l, "EC PARAMETERS");
        i += v.ASN1Util.getPEMStringFromHex(k, "EC PRIVATE KEY");
        return i
    }
    if (r == "PKCS1PRV" && typeof KJUR.crypto.DSA != "undefined" && a instanceof KJUR.crypto.DSA && (o === undefined || o == null) && a.isPrivate == true) {
        var t = n(a);
        var m = t.getEncodedHex();
        return v.ASN1Util.getPEMStringFromHex(m, "DSA PRIVATE KEY")
    }
    if (r == "PKCS5PRV" && typeof RSAKey != "undefined" && a instanceof RSAKey && (o !== undefined && o != null) && a.isPrivate == true) {
        var t = p(a);
        var m = t.getEncodedHex();
        if (g === undefined) { g = "DES-EDE3-CBC" }
        return this.getEncryptedPKCS5PEMFromPrvKeyHex("RSA", m, o, g)
    }
    if (r == "PKCS5PRV" && typeof KJUR.crypto.ECDSA != "undefined" && a instanceof KJUR.crypto.ECDSA && (o !== undefined && o != null) && a.isPrivate == true) {
        var t = q(a);
        var m = t.getEncodedHex();
        if (g === undefined) { g = "DES-EDE3-CBC" }
        return this.getEncryptedPKCS5PEMFromPrvKeyHex("EC", m, o, g)
    }
    if (r == "PKCS5PRV" && typeof KJUR.crypto.DSA != "undefined" && a instanceof KJUR.crypto.DSA && (o !== undefined && o != null) && a.isPrivate == true) {
        var t = n(a);
        var m = t.getEncodedHex();
        if (g === undefined) { g = "DES-EDE3-CBC" }
        return this.getEncryptedPKCS5PEMFromPrvKeyHex("DSA", m, o, g)
    }
    var h = function(w, s) {
        var y = b(w, s);
        var x = new KJUR.asn1.ASN1Util.newObject({ seq: [{ seq: [{ oid: { name: "pkcs5PBES2" } }, { seq: [{ seq: [{ oid: { name: "pkcs5PBKDF2" } }, { seq: [{ octstr: { hex: y.pbkdf2Salt } }, { "int": y.pbkdf2Iter }] }] }, { seq: [{ oid: { name: "des-EDE3-CBC" } }, { octstr: { hex: y.encryptionSchemeIV } }] }] }] }, { octstr: { hex: y.ciphertext } }] });
        return x.getEncodedHex()
    };
    var b = function(D, E) {
        var x = 100;
        var C = CryptoJS.lib.WordArray.random(8);
        var B = "DES-EDE3-CBC";
        var s = CryptoJS.lib.WordArray.random(8);
        var y = CryptoJS.PBKDF2(E, C, { keySize: 192 / 32, iterations: x });
        var z = CryptoJS.enc.Hex.parse(D);
        var A = CryptoJS.TripleDES.encrypt(z, y, { iv: s }) + "";
        var w = {};
        w.ciphertext = A;
        w.pbkdf2Salt = CryptoJS.enc.Hex.stringify(C);
        w.pbkdf2Iter = x;
        w.encryptionSchemeAlg = B;
        w.encryptionSchemeIV = CryptoJS.enc.Hex.stringify(s);
        return w
    };
    if (r == "PKCS8PRV" && typeof RSAKey != "undefined" && a instanceof RSAKey && a.isPrivate == true) {
        var d = p(a);
        var c = d.getEncodedHex();
        var t = KJUR.asn1.ASN1Util.newObject({ seq: [{ "int": 0 }, { seq: [{ oid: { name: "rsaEncryption" } }, { "null": true }] }, { octstr: { hex: c } }] });
        var m = t.getEncodedHex();
        if (o === undefined || o == null) {
            return v.ASN1Util.getPEMStringFromHex(m, "PRIVATE KEY")
        } else {
            var k = h(m, o);
            return v.ASN1Util.getPEMStringFromHex(k, "ENCRYPTED PRIVATE KEY")
        }
    }
    if (r == "PKCS8PRV" && typeof KJUR.crypto.ECDSA != "undefined" && a instanceof KJUR.crypto.ECDSA && a.isPrivate == true) {
        var d = new KJUR.asn1.ASN1Util.newObject({ seq: [{ "int": 1 }, { octstr: { hex: a.prvKeyHex } }, { tag: ["a1", true, { bitstr: { hex: "00" + a.pubKeyHex } }] }] });
        var c = d.getEncodedHex();
        var t = KJUR.asn1.ASN1Util.newObject({ seq: [{ "int": 0 }, { seq: [{ oid: { name: "ecPublicKey" } }, { oid: { name: a.curveName } }] }, { octstr: { hex: c } }] });
        var m = t.getEncodedHex();
        if (o === undefined || o == null) {
            return v.ASN1Util.getPEMStringFromHex(m, "PRIVATE KEY")
        } else {
            var k = h(m, o);
            return v.ASN1Util.getPEMStringFromHex(k, "ENCRYPTED PRIVATE KEY")
        }
    }
    if (r == "PKCS8PRV" && typeof KJUR.crypto.DSA != "undefined" && a instanceof KJUR.crypto.DSA && a.isPrivate == true) {
        var d = new KJUR.asn1.DERInteger({ bigint: a.x });
        var c = d.getEncodedHex();
        var t = KJUR.asn1.ASN1Util.newObject({ seq: [{ "int": 0 }, { seq: [{ oid: { name: "dsa" } }, { seq: [{ "int": { bigint: a.p } }, { "int": { bigint: a.q } }, { "int": { bigint: a.g } }] }] }, { octstr: { hex: c } }] });
        var m = t.getEncodedHex();
        if (o === undefined || o == null) {
            return v.ASN1Util.getPEMStringFromHex(m, "PRIVATE KEY")
        } else {
            var k = h(m, o);
            return v.ASN1Util.getPEMStringFromHex(k, "ENCRYPTED PRIVATE KEY")
        }
    }
    throw "unsupported object nor format"
};
KEYUTIL.getKeyFromCSRPEM = function(b) {
    var a = KEYUTIL.getHexFromPEM(b, "CERTIFICATE REQUEST");
    var c = KEYUTIL.getKeyFromCSRHex(a);
    return c
};
KEYUTIL.getKeyFromCSRHex = function(a) {
    var c = KEYUTIL.parseCSRHex(a);
    var b = KEYUTIL.getKey(c.p8pubkeyhex, null, "pkcs8pub");
    return b
};
KEYUTIL.parseCSRHex = function(c) {
    var b = {};
    var e = c;
    if (e.substr(0, 2) != "30") {
        throw "malformed CSR(code:001)"
    }
    var d = ASN1HEX.getPosArrayOfChildren_AtObj(e, 0);
    if (d.length < 1) {
        throw "malformed CSR(code:002)"
    }
    if (e.substr(d[0], 2) != "30") {
        throw "malformed CSR(code:003)"
    }
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(e, d[0]);
    if (a.length < 3) {
        throw "malformed CSR(code:004)"
    }
    b.p8pubkeyhex = ASN1HEX.getHexOfTLV_AtObj(e, a[2]);
    return b
};
/*! rsapem-1.1.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
function _rsapem_pemToBase64(b) {
    var a = b;
    a = a.replace("-----BEGIN RSA PRIVATE KEY-----", "");
    a = a.replace("-----END RSA PRIVATE KEY-----", "");
    a = a.replace(/[ \n]+/g, "");
    return a
}

function _rsapem_getPosArrayOfChildrenFromHex(d) {
    var j = new Array();
    var k = ASN1HEX.getStartPosOfV_AtObj(d, 0);
    var f = ASN1HEX.getPosOfNextSibling_AtObj(d, k);
    var h = ASN1HEX.getPosOfNextSibling_AtObj(d, f);
    var b = ASN1HEX.getPosOfNextSibling_AtObj(d, h);
    var l = ASN1HEX.getPosOfNextSibling_AtObj(d, b);
    var e = ASN1HEX.getPosOfNextSibling_AtObj(d, l);
    var g = ASN1HEX.getPosOfNextSibling_AtObj(d, e);
    var c = ASN1HEX.getPosOfNextSibling_AtObj(d, g);
    var i = ASN1HEX.getPosOfNextSibling_AtObj(d, c);
    j.push(k, f, h, b, l, e, g, c, i);
    return j
}

function _rsapem_getHexValueArrayOfChildrenFromHex(i) {
    var o = _rsapem_getPosArrayOfChildrenFromHex(i);
    var r = ASN1HEX.getHexOfV_AtObj(i, o[0]);
    var f = ASN1HEX.getHexOfV_AtObj(i, o[1]);
    var j = ASN1HEX.getHexOfV_AtObj(i, o[2]);
    var k = ASN1HEX.getHexOfV_AtObj(i, o[3]);
    var c = ASN1HEX.getHexOfV_AtObj(i, o[4]);
    var b = ASN1HEX.getHexOfV_AtObj(i, o[5]);
    var h = ASN1HEX.getHexOfV_AtObj(i, o[6]);
    var g = ASN1HEX.getHexOfV_AtObj(i, o[7]);
    var l = ASN1HEX.getHexOfV_AtObj(i, o[8]);
    var m = new Array();
    m.push(r, f, j, k, c, b, h, g, l);
    return m
}

function _rsapem_readPrivateKeyFromASN1HexString(c) {
    var b = _rsapem_getHexValueArrayOfChildrenFromHex(c);
    this.setPrivateEx(b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8])
}

function _rsapem_readPrivateKeyFromPEMString(e) {
    var c = _rsapem_pemToBase64(e);
    var d = b64tohex(c);
    var b = _rsapem_getHexValueArrayOfChildrenFromHex(d);
    this.setPrivateEx(b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8])
}
RSAKey.prototype.readPrivateKeyFromPEMString = _rsapem_readPrivateKeyFromPEMString;
RSAKey.prototype.readPrivateKeyFromASN1HexString = _rsapem_readPrivateKeyFromASN1HexString;
/*! rsasign-1.2.7.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
var _RE_HEXDECONLY = new RegExp("");
_RE_HEXDECONLY.compile("[^0-9a-f]", "gi");

function _rsasign_getHexPaddedDigestInfoForString(d, e, a) {
    var b = function(f) {
        return KJUR.crypto.Util.hashString(f, a)
    };
    var c = b(d);
    return KJUR.crypto.Util.getPaddedDigestInfoHex(c, a, e)
}

function _zeroPaddingOfSignature(e, d) {
    var c = "";
    var a = d / 4 - e.length;
    for (var b = 0; b < a; b++) { c = c + "0" }
    return c + e
}

function _rsasign_signString(d, a) {
    var b = function(e) {
        return KJUR.crypto.Util.hashString(e, a)
    };
    var c = b(d);
    return this.signWithMessageHash(c, a)
}

function _rsasign_signWithMessageHash(e, c) {
    var f = KJUR.crypto.Util.getPaddedDigestInfoHex(e, c, this.n.bitLength());
    var b = parseBigInt(f, 16);
    var d = this.doPrivate(b);
    var a = d.toString(16);
    return _zeroPaddingOfSignature(a, this.n.bitLength())
}

function _rsasign_signStringWithSHA1(a) {
    return _rsasign_signString.call(this, a, "sha1")
}

function _rsasign_signStringWithSHA256(a) {
    return _rsasign_signString.call(this, a, "sha256")
}

function pss_mgf1_str(c, a, e) {
    var b = "",
        d = 0;
    while (b.length < a) {
        b += hextorstr(e(rstrtohex(c + String.fromCharCode.apply(String, [(d & 4278190080) >> 24, (d & 16711680) >> 16, (d & 65280) >> 8, d & 255]))));
        d += 1
    }
    return b
}

function _rsasign_signStringPSS(e, a, d) {
    var c = function(f) {
        return KJUR.crypto.Util.hashHex(f, a)
    };
    var b = c(rstrtohex(e));
    if (d === undefined) { d = -1 }
    return this.signWithMessageHashPSS(b, a, d)
}

function _rsasign_signWithMessageHashPSS(l, a, k) {
    var b = hextorstr(l);
    var g = b.length;
    var m = this.n.bitLength() - 1;
    var c = Math.ceil(m / 8);
    var d;
    var o = function(i) {
        return KJUR.crypto.Util.hashHex(i, a)
    };
    if (k === -1 || k === undefined) { k = g } else {
        if (k === -2) { k = c - g - 2 } else {
            if (k < -2) {
                throw "invalid salt length"
            }
        }
    }
    if (c < (g + k + 2)) {
        throw "data too long"
    }
    var f = "";
    if (k > 0) {
        f = new Array(k);
        new SecureRandom().nextBytes(f);
        f = String.fromCharCode.apply(String, f)
    }
    var n = hextorstr(o(rstrtohex("\x00\x00\x00\x00\x00\x00\x00\x00" + b + f)));
    var j = [];
    for (d = 0; d < c - k - g - 2; d += 1) { j[d] = 0 }
    var e = String.fromCharCode.apply(String, j) + "\x01" + f;
    var h = pss_mgf1_str(n, e.length, o);
    var q = [];
    for (d = 0; d < e.length; d += 1) { q[d] = e.charCodeAt(d) ^ h.charCodeAt(d) }
    var p = (65280 >> (8 * c - m)) & 255;
    q[0] &= ~p;
    for (d = 0; d < g; d++) { q.push(n.charCodeAt(d)) }
    q.push(188);
    return _zeroPaddingOfSignature(this.doPrivate(new BigInteger(q)).toString(16), this.n.bitLength())
}

function _rsasign_getDecryptSignatureBI(a, d, c) {
    var b = new RSAKey();
    b.setPublic(d, c);
    var e = b.doPublic(a);
    return e
}

function _rsasign_getHexDigestInfoFromSig(a, c, b) {
    var e = _rsasign_getDecryptSignatureBI(a, c, b);
    var d = e.toString(16).replace(/^1f+00/, "");
    return d
}

function _rsasign_getAlgNameAndHashFromHexDisgestInfo(f) {
    for (var e in KJUR.crypto.Util.DIGESTINFOHEAD) {
        var d = KJUR.crypto.Util.DIGESTINFOHEAD[e];
        var b = d.length;
        if (f.substring(0, b) == d) {
            var c = [e, f.substring(b)];
            return c
        }
    }
    return []
}

function _rsasign_verifySignatureWithArgs(f, b, g, j) {
    var e = _rsasign_getHexDigestInfoFromSig(b, g, j);
    var h = _rsasign_getAlgNameAndHashFromHexDisgestInfo(e);
    if (h.length == 0) {
        return false
    }
    var d = h[0];
    var i = h[1];
    var a = function(k) {
        return KJUR.crypto.Util.hashString(k, d)
    };
    var c = a(f);
    return (i == c)
}

function _rsasign_verifyHexSignatureForMessage(c, b) {
    var d = parseBigInt(c, 16);
    var a = _rsasign_verifySignatureWithArgs(b, d, this.n.toString(16), this.e.toString(16));
    return a
}

function _rsasign_verifyString(f, j) {
    j = j.replace(_RE_HEXDECONLY, "");
    j = j.replace(/[ \n]+/g, "");
    var b = parseBigInt(j, 16);
    if (b.bitLength() > this.n.bitLength()) {
        return 0
    }
    var i = this.doPublic(b);
    var e = i.toString(16).replace(/^1f+00/, "");
    var g = _rsasign_getAlgNameAndHashFromHexDisgestInfo(e);
    if (g.length == 0) {
        return false
    }
    var d = g[0];
    var h = g[1];
    var a = function(k) {
        return KJUR.crypto.Util.hashString(k, d)
    };
    var c = a(f);
    return (h == c)
}

function _rsasign_verifyWithMessageHash(e, a) {
    a = a.replace(_RE_HEXDECONLY, "");
    a = a.replace(/[ \n]+/g, "");
    var b = parseBigInt(a, 16);
    if (b.bitLength() > this.n.bitLength()) {
        return 0
    }
    var h = this.doPublic(b);
    var g = h.toString(16).replace(/^1f+00/, "");
    var c = _rsasign_getAlgNameAndHashFromHexDisgestInfo(g);
    if (c.length == 0) {
        return false
    }
    var d = c[0];
    var f = c[1];
    return (f == e)
}

function _rsasign_verifyStringPSS(c, b, a, f) {
    var e = function(g) {
        return KJUR.crypto.Util.hashHex(g, a)
    };
    var d = e(rstrtohex(c));
    if (f === undefined) { f = -1 }
    return this.verifyWithMessageHashPSS(d, b, a, f)
}

function _rsasign_verifyWithMessageHashPSS(f, s, l, c) {
    var k = new BigInteger(s, 16);
    if (k.bitLength() > this.n.bitLength()) {
        return false
    }
    var r = function(i) {
        return KJUR.crypto.Util.hashHex(i, l)
    };
    var j = hextorstr(f);
    var h = j.length;
    var g = this.n.bitLength() - 1;
    var m = Math.ceil(g / 8);
    var q;
    if (c === -1 || c === undefined) { c = h } else {
        if (c === -2) { c = m - h - 2 } else {
            if (c < -2) {
                throw "invalid salt length"
            }
        }
    }
    if (m < (h + c + 2)) {
        throw "data too long"
    }
    var a = this.doPublic(k).toByteArray();
    for (q = 0; q < a.length; q += 1) { a[q] &= 255 }
    while (a.length < m) { a.unshift(0) }
    if (a[m - 1] !== 188) {
        throw "encoded message does not end in 0xbc"
    }
    a = String.fromCharCode.apply(String, a);
    var d = a.substr(0, m - h - 1);
    var e = a.substr(d.length, h);
    var p = (65280 >> (8 * m - g)) & 255;
    if ((d.charCodeAt(0) & p) !== 0) {
        throw "bits beyond keysize not zero"
    }
    var n = pss_mgf1_str(e, d.length, r);
    var o = [];
    for (q = 0; q < d.length; q += 1) { o[q] = d.charCodeAt(q) ^ n.charCodeAt(q) }
    o[0] &= ~p;
    var b = m - h - c - 2;
    for (q = 0; q < b; q += 1) {
        if (o[q] !== 0) {
            throw "leftmost octets not zero"
        }
    }
    if (o[b] !== 1) {
        throw "0x01 marker not found"
    }
    return e === hextorstr(r(rstrtohex("\x00\x00\x00\x00\x00\x00\x00\x00" + j + String.fromCharCode.apply(String, o.slice(-c)))))
}
RSAKey.prototype.signWithMessageHash = _rsasign_signWithMessageHash;
RSAKey.prototype.signString = _rsasign_signString;
RSAKey.prototype.signStringWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signStringWithSHA256 = _rsasign_signStringWithSHA256;
RSAKey.prototype.sign = _rsasign_signString;
RSAKey.prototype.signWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signWithSHA256 = _rsasign_signStringWithSHA256;
RSAKey.prototype.signWithMessageHashPSS = _rsasign_signWithMessageHashPSS;
RSAKey.prototype.signStringPSS = _rsasign_signStringPSS;
RSAKey.prototype.signPSS = _rsasign_signStringPSS;
RSAKey.SALT_LEN_HLEN = -1;
RSAKey.SALT_LEN_MAX = -2;
RSAKey.prototype.verifyWithMessageHash = _rsasign_verifyWithMessageHash;
RSAKey.prototype.verifyString = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForMessage = _rsasign_verifyHexSignatureForMessage;
RSAKey.prototype.verify = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForByteArrayMessage = _rsasign_verifyHexSignatureForMessage;
RSAKey.prototype.verifyWithMessageHashPSS = _rsasign_verifyWithMessageHashPSS;
RSAKey.prototype.verifyStringPSS = _rsasign_verifyStringPSS;
RSAKey.prototype.verifyPSS = _rsasign_verifyStringPSS;
RSAKey.SALT_LEN_RECOVER = -2;
/*! x509-1.1.8.js (c) 2012-2016 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
function X509() {
    this.subjectPublicKeyRSA = null;
    this.subjectPublicKeyRSA_hN = null;
    this.subjectPublicKeyRSA_hE = null;
    this.hex = null;
    this.getSerialNumberHex = function() {
        return ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 1])
    };
    this.getSignatureAlgorithmField = function() {
        var b = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 2, 0]);
        var a = KJUR.asn1.ASN1Util.oidHexToInt(b);
        var c = KJUR.asn1.x509.OID.oid2name(a);
        return c
    };
    this.getIssuerHex = function() {
        return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3])
    };
    this.getIssuerString = function() {
        return X509.hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 3]))
    };
    this.getSubjectHex = function() {
        return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5])
    };
    this.getSubjectString = function() {
        return X509.hex2dn(ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0, 5]))
    };
    this.getNotBefore = function() {
        var a = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 0]);
        a = a.replace(/(..)/g, "%$1");
        a = decodeURIComponent(a);
        return a
    };
    this.getNotAfter = function() {
        var a = ASN1HEX.getDecendantHexVByNthList(this.hex, 0, [0, 4, 1]);
        a = a.replace(/(..)/g, "%$1");
        a = decodeURIComponent(a);
        return a
    };
    this.readCertPEM = function(c) {
        var e = X509.pemToHex(c);
        var b = X509.getPublicKeyHexArrayFromCertHex(e);
        var d = new RSAKey();
        d.setPublic(b[0], b[1]);
        this.subjectPublicKeyRSA = d;
        this.subjectPublicKeyRSA_hN = b[0];
        this.subjectPublicKeyRSA_hE = b[1];
        this.hex = e
    };
    this.readCertPEMWithoutRSAInit = function(c) {
        var d = X509.pemToHex(c);
        var b = X509.getPublicKeyHexArrayFromCertHex(d);
        this.subjectPublicKeyRSA.setPublic(b[0], b[1]);
        this.subjectPublicKeyRSA_hN = b[0];
        this.subjectPublicKeyRSA_hE = b[1];
        this.hex = d
    };
    this.getInfo = function() {
        var p = "Basic Fields\n";
        p += "  serial number: " + this.getSerialNumberHex() + "\n";
        p += "  signature algorithm: " + this.getSignatureAlgorithmField() + "\n";
        p += "  issuer: " + this.getIssuerString() + "\n";
        p += "  notBefore: " + this.getNotBefore() + "\n";
        p += "  notAfter: " + this.getNotAfter() + "\n";
        p += "  subject: " + this.getSubjectString() + "\n";
        p += "  subject public key info: \n";
        var j = X509.getSubjectPublicKeyInfoPosFromCertHex(this.hex);
        var d = ASN1HEX.getHexOfTLV_AtObj(this.hex, j);
        var n = KEYUTIL.getKey(d, null, "pkcs8pub");
        if (n instanceof RSAKey) {
            p += "    key algorithm: RSA\n";
            p += "    n=" + n.n.toString(16).substr(0, 16) + "...\n";
            p += "    e=" + n.e.toString(16) + "\n"
        }
        p += "X509v3 Extensions:\n";
        var m = X509.getV3ExtInfoListOfCertHex(this.hex);
        for (var e = 0; e < m.length; e++) {
            var b = m[e];
            var o = KJUR.asn1.x509.OID.oid2name(b.oid);
            if (o === "") { o = b.oid }
            var k = "";
            if (b.critical === true) { k = "CRITICAL" }
            p += "  " + o + " " + k + ":\n";
            if (o === "basicConstraints") {
                var g = X509.getExtBasicConstraints(this.hex);
                if (g.cA === undefined) { p += "    {}\n" } else {
                    p += "    cA=true";
                    if (g.pathLen !== undefined) { p += ", pathLen=" + g.pathLen }
                    p += "\n"
                }
            } else {
                if (o === "keyUsage") { p += "    " + X509.getExtKeyUsageString(this.hex) + "\n" } else {
                    if (o === "subjectKeyIdentifier") { p += "    " + X509.getExtSubjectKeyIdentifier(this.hex) + "\n" } else {
                        if (o === "authorityKeyIdentifier") {
                            var a = X509.getExtAuthorityKeyIdentifier(this.hex);
                            if (a.kid !== undefined) { p += "    kid=" + a.kid + "\n" }
                        } else {
                            if (o === "extKeyUsage") {
                                var h = X509.getExtExtKeyUsageName(this.hex);
                                p += "    " + h.join(", ") + "\n"
                            } else {
                                if (o === "subjectAltName") {
                                    var f = X509.getExtSubjectAltName(this.hex);
                                    p += "    " + f.join(", ") + "\n"
                                } else {
                                    if (o === "cRLDistributionPoints") {
                                        var l = X509.getExtCRLDistributionPointsURI(this.hex);
                                        p += "    " + l + "\n"
                                    } else {
                                        if (o === "authorityInfoAccess") {
                                            var c = X509.getExtAIAInfo(this.hex);
                                            if (c.ocsp !== undefined) { p += "    ocsp: " + c.ocsp.join(",") + "\n" }
                                            if (c.caissuer !== undefined) { p += "    caissuer: " + c.caissuer.join(",") + "\n" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        p += "signature algorithm: " + X509.getSignatureAlgorithmName(this.hex) + "\n";
        p += "signature: " + X509.getSignatureValueHex(this.hex).substr(0, 16) + "...\n";
        return p
    }
}
X509.pemToBase64 = function(a) {
    var b = a;
    b = b.replace("-----BEGIN CERTIFICATE-----", "");
    b = b.replace("-----END CERTIFICATE-----", "");
    b = b.replace(/[ \n]+/g, "");
    return b
};
X509.pemToHex = function(a) {
    var c = X509.pemToBase64(a);
    var b = b64tohex(c);
    return b
};
X509.getSubjectPublicKeyPosFromCertHex = function(f) {
    var e = X509.getSubjectPublicKeyInfoPosFromCertHex(f);
    if (e == -1) {
        return -1
    }
    var b = ASN1HEX.getPosArrayOfChildren_AtObj(f, e);
    if (b.length != 2) {
        return -1
    }
    var d = b[1];
    if (f.substring(d, d + 2) != "03") {
        return -1
    }
    var c = ASN1HEX.getStartPosOfV_AtObj(f, d);
    if (f.substring(c, c + 2) != "00") {
        return -1
    }
    return c + 2
};
X509.getSubjectPublicKeyInfoPosFromCertHex = function(d) {
    var c = ASN1HEX.getStartPosOfV_AtObj(d, 0);
    var b = ASN1HEX.getPosArrayOfChildren_AtObj(d, c);
    if (b.length < 1) {
        return -1
    }
    if (d.substring(b[0], b[0] + 10) == "a003020102") {
        if (b.length < 6) {
            return -1
        }
        return b[6]
    } else {
        if (b.length < 5) {
            return -1
        }
        return b[5]
    }
};
X509.getPublicKeyHexArrayFromCertHex = function(f) {
    var e = X509.getSubjectPublicKeyPosFromCertHex(f);
    var b = ASN1HEX.getPosArrayOfChildren_AtObj(f, e);
    if (b.length != 2) {
        return []
    }
    var d = ASN1HEX.getHexOfV_AtObj(f, b[0]);
    var c = ASN1HEX.getHexOfV_AtObj(f, b[1]);
    if (d != null && c != null) {
        return [d, c]
    } else {
        return []
    }
};
X509.getHexTbsCertificateFromCert = function(b) {
    var a = ASN1HEX.getStartPosOfV_AtObj(b, 0);
    return a
};
X509.getPublicKeyHexArrayFromCertPEM = function(c) {
    var d = X509.pemToHex(c);
    var b = X509.getPublicKeyHexArrayFromCertHex(d);
    return b
};
X509.hex2dn = function(e) {
    var f = "";
    var c = ASN1HEX.getPosArrayOfChildren_AtObj(e, 0);
    for (var d = 0; d < c.length; d++) {
        var b = ASN1HEX.getHexOfTLV_AtObj(e, c[d]);
        f = f + "/" + X509.hex2rdn(b)
    }
    return f
};
X509.hex2rdn = function(a) {
    var f = ASN1HEX.getDecendantHexTLVByNthList(a, 0, [0, 0]);
    var e = ASN1HEX.getDecendantHexVByNthList(a, 0, [0, 1]);
    var c = "";
    try { c = X509.DN_ATTRHEX[f] } catch (b) { c = f }
    e = e.replace(/(..)/g, "%$1");
    var d = decodeURIComponent(e);
    return c + "=" + d
};
X509.DN_ATTRHEX = { "0603550406": "C", "060355040a": "O", "060355040b": "OU", "0603550403": "CN", "0603550405": "SN", "0603550408": "ST", "0603550407": "L", };
X509.getPublicKeyFromCertPEM = function(f) {
    var c = X509.getPublicKeyInfoPropOfCertPEM(f);
    if (c.algoid == "2a864886f70d010101") {
        var i = KEYUTIL.parsePublicRawRSAKeyHex(c.keyhex);
        var j = new RSAKey();
        j.setPublic(i.n, i.e);
        return j
    } else {
        if (c.algoid == "2a8648ce3d0201") {
            var e = KJUR.crypto.OID.oidhex2name[c.algparam];
            var j = new KJUR.crypto.ECDSA({ curve: e, info: c.keyhex });
            j.setPublicKeyHex(c.keyhex);
            return j
        } else {
            if (c.algoid == "2a8648ce380401") {
                var b = ASN1HEX.getVbyList(c.algparam, 0, [0], "02");
                var a = ASN1HEX.getVbyList(c.algparam, 0, [1], "02");
                var d = ASN1HEX.getVbyList(c.algparam, 0, [2], "02");
                var h = ASN1HEX.getHexOfV_AtObj(c.keyhex, 0);
                h = h.substr(2);
                var j = new KJUR.crypto.DSA();
                j.setPublic(new BigInteger(b, 16), new BigInteger(a, 16), new BigInteger(d, 16), new BigInteger(h, 16));
                return j
            } else {
                throw "unsupported key"
            }
        }
    }
};
X509.getPublicKeyInfoPropOfCertPEM = function(e) {
    var c = {};
    c.algparam = null;
    var g = X509.pemToHex(e);
    var d = ASN1HEX.getPosArrayOfChildren_AtObj(g, 0);
    if (d.length != 3) {
        throw "malformed X.509 certificate PEM (code:001)"
    }
    if (g.substr(d[0], 2) != "30") {
        throw "malformed X.509 certificate PEM (code:002)"
    }
    var b = ASN1HEX.getPosArrayOfChildren_AtObj(g, d[0]);
    if (b.length < 7) {
        throw "malformed X.509 certificate PEM (code:003)"
    }
    var h = ASN1HEX.getPosArrayOfChildren_AtObj(g, b[6]);
    if (h.length != 2) {
        throw "malformed X.509 certificate PEM (code:004)"
    }
    var f = ASN1HEX.getPosArrayOfChildren_AtObj(g, h[0]);
    if (f.length != 2) {
        throw "malformed X.509 certificate PEM (code:005)"
    }
    c.algoid = ASN1HEX.getHexOfV_AtObj(g, f[0]);
    if (g.substr(f[1], 2) == "06") { c.algparam = ASN1HEX.getHexOfV_AtObj(g, f[1]) } else {
        if (g.substr(f[1], 2) == "30") { c.algparam = ASN1HEX.getHexOfTLV_AtObj(g, f[1]) }
    }
    if (g.substr(h[1], 2) != "03") {
        throw "malformed X.509 certificate PEM (code:006)"
    }
    var a = ASN1HEX.getHexOfV_AtObj(g, h[1]);
    c.keyhex = a.substr(2);
    return c
};
X509.getPublicKeyInfoPosOfCertHEX = function(c) {
    var b = ASN1HEX.getPosArrayOfChildren_AtObj(c, 0);
    if (b.length != 3) {
        throw "malformed X.509 certificate PEM (code:001)"
    }
    if (c.substr(b[0], 2) != "30") {
        throw "malformed X.509 certificate PEM (code:002)"
    }
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(c, b[0]);
    if (a.length < 7) {
        throw "malformed X.509 certificate PEM (code:003)"
    }
    return a[6]
};
X509.getV3ExtInfoListOfCertHex = function(g) {
    var b = ASN1HEX.getPosArrayOfChildren_AtObj(g, 0);
    if (b.length != 3) {
        throw "malformed X.509 certificate PEM (code:001)"
    }
    if (g.substr(b[0], 2) != "30") {
        throw "malformed X.509 certificate PEM (code:002)"
    }
    var a = ASN1HEX.getPosArrayOfChildren_AtObj(g, b[0]);
    if (a.length < 8) {
        throw "malformed X.509 certificate PEM (code:003)"
    }
    if (g.substr(a[7], 2) != "a3") {
        throw "malformed X.509 certificate PEM (code:004)"
    }
    var h = ASN1HEX.getPosArrayOfChildren_AtObj(g, a[7]);
    if (h.length != 1) {
        throw "malformed X.509 certificate PEM (code:005)"
    }
    if (g.substr(h[0], 2) != "30") {
        throw "malformed X.509 certificate PEM (code:006)"
    }
    var f = ASN1HEX.getPosArrayOfChildren_AtObj(g, h[0]);
    var e = f.length;
    var d = new Array(e);
    for (var c = 0; c < e; c++) { d[c] = X509.getV3ExtItemInfo_AtObj(g, f[c]) }
    return d
};
X509.getV3ExtItemInfo_AtObj = function(f, g) {
    var e = {};
    e.posTLV = g;
    var b = ASN1HEX.getPosArrayOfChildren_AtObj(f, g);
    if (b.length != 2 && b.length != 3) {
        throw "malformed X.509v3 Ext (code:001)"
    }
    if (f.substr(b[0], 2) != "06") {
        throw "malformed X.509v3 Ext (code:002)"
    }
    var d = ASN1HEX.getHexOfV_AtObj(f, b[0]);
    e.oid = ASN1HEX.hextooidstr(d);
    e.critical = false;
    if (b.length == 3) { e.critical = true }
    var c = b[b.length - 1];
    if (f.substr(c, 2) != "04") {
        throw "malformed X.509v3 Ext (code:003)"
    }
    e.posV = ASN1HEX.getStartPosOfV_AtObj(f, c);
    return e
};
X509.getHexOfTLV_V3ExtValue = function(b, a) {
    var c = X509.getPosOfTLV_V3ExtValue(b, a);
    if (c == -1) {
        return null
    }
    return ASN1HEX.getHexOfTLV_AtObj(b, c)
};
X509.getHexOfV_V3ExtValue = function(b, a) {
    var c = X509.getPosOfTLV_V3ExtValue(b, a);
    if (c == -1) {
        return null
    }
    return ASN1HEX.getHexOfV_AtObj(b, c)
};
X509.getPosOfTLV_V3ExtValue = function(f, b) {
    var d = b;
    if (!b.match(/^[0-9.]+$/)) { d = KJUR.asn1.x509.OID.name2oid(b) }
    if (d == "") {
        return -1
    }
    var c = X509.getV3ExtInfoListOfCertHex(f);
    for (var a = 0; a < c.length; a++) {
        var e = c[a];
        if (e.oid == d) {
            return e.posV
        }
    }
    return -1
};
X509.getExtBasicConstraints = function(d) {
    var a = X509.getHexOfV_V3ExtValue(d, "basicConstraints");
    if (a === null) {
        return null
    }
    if (a === "") {
        return {}
    }
    if (a === "0101ff") {
        return { cA: true }
    }
    if (a.substr(0, 8) === "0101ff02") {
        var c = ASN1HEX.getHexOfV_AtObj(a, 6);
        var b = parseInt(c, 16);
        return { cA: true, pathLen: b }
    }
    throw "unknown error"
};
X509.KEYUSAGE_NAME = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"];
X509.getExtKeyUsageBin = function(d) {
    var b = X509.getHexOfV_V3ExtValue(d, "keyUsage");
    if (b == "") {
        return ""
    }
    if (b.length % 2 != 0 || b.length <= 2) {
        throw "malformed key usage value"
    }
    var a = parseInt(b.substr(0, 2));
    var c = parseInt(b.substr(2), 16).toString(2);
    return c.substr(0, c.length - a)
};
X509.getExtKeyUsageString = function(e) {
    var d = X509.getExtKeyUsageBin(e);
    var b = new Array();
    for (var c = 0; c < d.length; c++) {
        if (d.substr(c, 1) == "1") { b.push(X509.KEYUSAGE_NAME[c]) }
    }
    return b.join(",")
};
X509.getExtSubjectKeyIdentifier = function(b) {
    var a = X509.getHexOfV_V3ExtValue(b, "subjectKeyIdentifier");
    return a
};
X509.getExtAuthorityKeyIdentifier = function(f) {
    var b = {};
    var e = X509.getHexOfTLV_V3ExtValue(f, "authorityKeyIdentifier");
    if (e === null) {
        return null
    }
    var c = ASN1HEX.getPosArrayOfChildren_AtObj(e, 0);
    for (var d = 0; d < c.length; d++) {
        if (e.substr(c[d], 2) === "80") { b.kid = ASN1HEX.getHexOfV_AtObj(e, c[d]) }
    }
    return b
};
X509.getExtExtKeyUsageName = function(k) {
    var b = new Array();
    var f = X509.getHexOfTLV_V3ExtValue(k, "extKeyUsage");
    if (f === null) {
        return null
    }
    var c = ASN1HEX.getPosArrayOfChildren_AtObj(f, 0);
    for (var e = 0; e < c.length; e++) {
        var j = ASN1HEX.getHexOfV_AtObj(f, c[e]);
        var g = KJUR.asn1.ASN1Util.oidHexToInt(j);
        var d = KJUR.asn1.x509.OID.oid2name(g);
        b.push(d)
    }
    return b
};
X509.getExtSubjectAltName = function(g) {
    var b = new Array();
    var f = X509.getHexOfTLV_V3ExtValue(g, "subjectAltName");
    var c = ASN1HEX.getPosArrayOfChildren_AtObj(f, 0);
    for (var e = 0; e < c.length; e++) {
        if (f.substr(c[e], 2) === "82") {
            var d = hextoutf8(ASN1HEX.getHexOfV_AtObj(f, c[e]));
            b.push(d)
        }
    }
    return b
};
X509.getExtCRLDistributionPointsURI = function(n) {
    var p = new Array();
    var k = X509.getHexOfTLV_V3ExtValue(n, "cRLDistributionPoints");
    var o = ASN1HEX.getPosArrayOfChildren_AtObj(k, 0);
    for (var g = 0; g < o.length; g++) {
        var l = ASN1HEX.getHexOfTLV_AtObj(k, o[g]);
        var b = ASN1HEX.getPosArrayOfChildren_AtObj(l, 0);
        for (var e = 0; e < b.length; e++) {
            if (l.substr(b[e], 2) === "a0") {
                var f = ASN1HEX.getHexOfV_AtObj(l, b[e]);
                if (f.substr(0, 2) === "a0") {
                    var c = ASN1HEX.getHexOfV_AtObj(f, 0);
                    if (c.substr(0, 2) === "86") {
                        var m = ASN1HEX.getHexOfV_AtObj(c, 0);
                        var d = hextoutf8(m);
                        p.push(d)
                    }
                }
            }
        }
    }
    return p
};
X509.getExtAIAInfo = function(g) {
    var j = {};
    j.ocsp = [];
    j.caissuer = [];
    var h = X509.getPosOfTLV_V3ExtValue(g, "authorityInfoAccess");
    if (h == -1) {
        return null
    }
    if (g.substr(h, 2) != "30") {
        throw "malformed AIA Extn Value"
    }
    var d = ASN1HEX.getPosArrayOfChildren_AtObj(g, h);
    for (var c = 0; c < d.length; c++) {
        var a = d[c];
        var b = ASN1HEX.getPosArrayOfChildren_AtObj(g, a);
        if (b.length != 2) {
            throw "malformed AccessDescription of AIA Extn"
        }
        var e = b[0];
        var f = b[1];
        if (ASN1HEX.getHexOfV_AtObj(g, e) == "2b06010505073001") {
            if (g.substr(f, 2) == "86") { j.ocsp.push(hextoutf8(ASN1HEX.getHexOfV_AtObj(g, f))) }
        }
        if (ASN1HEX.getHexOfV_AtObj(g, e) == "2b06010505073002") {
            if (g.substr(f, 2) == "86") { j.caissuer.push(hextoutf8(ASN1HEX.getHexOfV_AtObj(g, f))) }
        }
    }
    return j
};
X509.getSignatureAlgorithmName = function(d) {
    var b = ASN1HEX.getDecendantHexVByNthList(d, 0, [1, 0]);
    var a = KJUR.asn1.ASN1Util.oidHexToInt(b);
    var c = KJUR.asn1.x509.OID.oid2name(a);
    return c
};
X509.getSignatureValueHex = function(b) {
    var a = ASN1HEX.getDecendantHexVByNthList(b, 0, [2]);
    if (a.substr(0, 2) !== "00") {
        throw "can't get signature value"
    }
    return a.substr(2)
};
X509.getSerialNumberHex = function(a) {
    return ASN1HEX.getDecendantHexVByNthList(a, 0, [0, 1])
};
/*! jws-3.3.3 (c) 2013-2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
if (typeof KJUR == "undefined" || !KJUR) { KJUR = {} }
if (typeof KJUR.jws == "undefined" || !KJUR.jws) { KJUR.jws = {} }
KJUR.jws.JWS = function() {
    var a = KJUR.jws.JWS;
    this.parseJWS = function(e, g) {
        if ((this.parsedJWS !== undefined) && (g || (this.parsedJWS.sigvalH !== undefined))) {
            return
        }
        if (e.match(/^([^.]+)\.([^.]+)\.([^.]+)$/) == null) {
            throw "JWS signature is not a form of 'Head.Payload.SigValue'."
        }
        var h = RegExp.$1;
        var c = RegExp.$2;
        var i = RegExp.$3;
        var k = h + "." + c;
        this.parsedJWS = {};
        this.parsedJWS.headB64U = h;
        this.parsedJWS.payloadB64U = c;
        this.parsedJWS.sigvalB64U = i;
        this.parsedJWS.si = k;
        if (!g) {
            var f = b64utohex(i);
            var d = parseBigInt(f, 16);
            this.parsedJWS.sigvalH = f;
            this.parsedJWS.sigvalBI = d
        }
        var b = b64utoutf8(h);
        var j = b64utoutf8(c);
        this.parsedJWS.headS = b;
        this.parsedJWS.payloadS = j;
        if (!a.isSafeJSONString(b, this.parsedJWS, "headP")) {
            throw "malformed JSON string for JWS Head: " + b
        }
    }
};
KJUR.jws.JWS.sign = function(a, i, c, m, l) {
    var k = KJUR.jws.JWS;
    var q, e, j;
    if (typeof i != "string" && typeof i != "object") {
        throw "spHeader must be JSON string or object: " + i
    }
    if (typeof i == "object") {
        e = i;
        q = JSON.stringify(e)
    }
    if (typeof i == "string") {
        q = i;
        if (!k.isSafeJSONString(q)) {
            throw "JWS Head is not safe JSON string: " + q
        }
        e = k.readSafeJSONString(q)
    }
    j = c;
    if (typeof c == "object") { j = JSON.stringify(c) }
    if ((a == "" || a == null) && e.alg !== undefined) { a = e.alg }
    if ((a != "" && a != null) && e.alg === undefined) {
        e.alg = a;
        q = JSON.stringify(e)
    }
    if (a !== e.alg) {
        throw "alg and sHeader.alg doesn't match: " + a + "!=" + e.alg
    }
    var d = null;
    if (k.jwsalg2sigalg[a] === undefined) {
        throw "unsupported alg name: " + a
    } else { d = k.jwsalg2sigalg[a] }
    var b = utf8tob64u(q);
    var g = utf8tob64u(j);
    var o = b + "." + g;
    var n = "";
    if (d.substr(0, 4) == "Hmac") {
        if (m === undefined) {
            throw "mac key shall be specified for HS* alg"
        }
        var h = new KJUR.crypto.Mac({ alg: d, prov: "cryptojs", pass: m });
        h.updateString(o);
        n = h.doFinal()
    } else {
        if (d.indexOf("withECDSA") != -1) {
            var p = new KJUR.crypto.Signature({ alg: d });
            p.init(m, l);
            p.updateString(o);
            hASN1Sig = p.sign();
            n = KJUR.crypto.ECDSA.asn1SigToConcatSig(hASN1Sig)
        } else {
            if (d != "none") {
                var p = new KJUR.crypto.Signature({ alg: d });
                p.init(m, l);
                p.updateString(o);
                n = p.sign()
            }
        }
    }
    var f = hextob64u(n);
    return o + "." + f
};
KJUR.jws.JWS.verify = function(p, t, j) {
    var m = KJUR.jws.JWS;
    var q = p.split(".");
    var d = q[0];
    var l = q[1];
    var b = d + "." + l;
    var r = b64utohex(q[2]);
    var i = m.readSafeJSONString(b64utoutf8(q[0]));
    var h = null;
    var s = null;
    if (i.alg === undefined) {
        throw "algorithm not specified in header"
    } else {
        h = i.alg;
        s = h.substr(0, 2)
    }
    if (j != null && Object.prototype.toString.call(j) === "[object Array]" && j.length > 0) {
        var c = ":" + j.join(":") + ":";
        if (c.indexOf(":" + h + ":") == -1) {
            throw "algorithm '" + h + "' not accepted in the list"
        }
    }
    if (h != "none" && t === null) {
        throw "key shall be specified to verify."
    }
    if (typeof t == "string" && t.indexOf("-----BEGIN ") != -1) { t = KEYUTIL.getKey(t) }
    if (s == "RS" || s == "PS") {
        if (!(t instanceof RSAKey)) {
            throw "key shall be a RSAKey obj for RS* and PS* algs"
        }
    }
    if (s == "ES") {
        if (!(t instanceof KJUR.crypto.ECDSA)) {
            throw "key shall be a ECDSA obj for ES* algs"
        }
    }
    if (h == "none") {}
    var n = null;
    if (m.jwsalg2sigalg[i.alg] === undefined) {
        throw "unsupported alg name: " + h
    } else { n = m.jwsalg2sigalg[h] }
    if (n == "none") {
        throw "not supported"
    } else {
        if (n.substr(0, 4) == "Hmac") {
            var k = null;
            if (t === undefined) {
                throw "hexadecimal key shall be specified for HMAC"
            }
            var g = new KJUR.crypto.Mac({ alg: n, pass: t });
            g.updateString(b);
            k = g.doFinal();
            return r == k
        } else {
            if (n.indexOf("withECDSA") != -1) {
                var f = null;
                try { f = KJUR.crypto.ECDSA.concatSigToASN1Sig(r) } catch (o) {
                    return false
                }
                var e = new KJUR.crypto.Signature({ alg: n });
                e.init(t);
                e.updateString(b);
                return e.verify(f)
            } else {
                var e = new KJUR.crypto.Signature({ alg: n });
                e.init(t);
                e.updateString(b);
                return e.verify(r)
            }
        }
    }
};
KJUR.jws.JWS.parse = function(g) {
    var c = g.split(".");
    var b = {};
    var f, e, d;
    if (c.length != 2 && c.length != 3) {
        throw "malformed sJWS: wrong number of '.' splitted elements"
    }
    f = c[0];
    e = c[1];
    if (c.length == 3) { d = c[2] }
    b.headerObj = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(f));
    b.payloadObj = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(e));
    b.headerPP = JSON.stringify(b.headerObj, null, "  ");
    if (b.payloadObj == null) { b.payloadPP = b64utoutf8(e) } else { b.payloadPP = JSON.stringify(b.payloadObj, null, "  ") }
    if (d !== undefined) { b.sigHex = b64utohex(d) }
    return b
};
KJUR.jws.JWS.verifyJWT = function(d, j, l) {
    var h = KJUR.jws.JWS;
    var i = d.split(".");
    var c = i[0];
    var g = i[1];
    var m = c + "." + g;
    var k = b64utohex(i[2]);
    var f = h.readSafeJSONString(b64utoutf8(c));
    var e = h.readSafeJSONString(b64utoutf8(g));
    if (f.alg === undefined) {
        return false
    }
    if (l.alg === undefined) {
        throw "acceptField.alg shall be specified"
    }
    if (!h.inArray(f.alg, l.alg)) {
        return false
    }
    if (e.iss !== undefined && typeof l.iss === "object") {
        if (!h.inArray(e.iss, l.iss)) {
            return false
        }
    }
    if (e.sub !== undefined && typeof l.sub === "object") {
        if (!h.inArray(e.sub, l.sub)) {
            return false
        }
    }
    if (e.aud !== undefined && typeof l.aud === "object") {
        if (typeof e.aud == "string") {
            if (!h.inArray(e.aud, l.aud)) {
                return false
            }
        } else {
            if (typeof e.aud == "object") {
                if (!h.includedArray(e.aud, l.aud)) {
                    return false
                }
            }
        }
    }
    var b = KJUR.jws.IntDate.getNow();
    if (l.verifyAt !== undefined && typeof l.verifyAt == "number") { b = l.verifyAt }
    if (e.exp !== undefined && typeof e.exp == "number") {
        if (e.exp < b) {
            return false
        }
    }
    if (e.nbf !== undefined && typeof e.nbf == "number") {
        if (b < e.nbf) {
            return false
        }
    }
    if (e.iat !== undefined && typeof e.iat == "number") {
        if (b < e.iat) {
            return false
        }
    }
    if (e.jti !== undefined && l.jti !== undefined) {
        if (e.jti !== l.jti) {
            return false
        }
    }
    if (!KJUR.jws.JWS.verify(d, j, l.alg)) {
        return false
    }
    return true
};
KJUR.jws.JWS.includedArray = function(b, a) {
    var d = KJUR.jws.JWS.inArray;
    if (b === null) {
        return false
    }
    if (typeof b !== "object") {
        return false
    }
    if (typeof b.length !== "number") {
        return false
    }
    for (var c = 0; c < b.length; c++) {
        if (!d(b[c], a)) {
            return false
        }
    }
    return true
};
KJUR.jws.JWS.inArray = function(d, b) {
    if (b === null) {
        return false
    }
    if (typeof b !== "object") {
        return false
    }
    if (typeof b.length !== "number") {
        return false
    }
    for (var c = 0; c < b.length; c++) {
        if (b[c] == d) {
            return true
        }
    }
    return false
};
KJUR.jws.JWS.jwsalg2sigalg = { HS256: "HmacSHA256", HS384: "HmacSHA384", HS512: "HmacSHA512", RS256: "SHA256withRSA", RS384: "SHA384withRSA", RS512: "SHA512withRSA", ES256: "SHA256withECDSA", ES384: "SHA384withECDSA", PS256: "SHA256withRSAandMGF1", PS384: "SHA384withRSAandMGF1", PS512: "SHA512withRSAandMGF1", none: "none", };
KJUR.jws.JWS.isSafeJSONString = function(c, b, d) {
    var e = null;
    try {
        e = jsonParse(c);
        if (typeof e != "object") {
            return 0
        }
        if (e.constructor === Array) {
            return 0
        }
        if (b) { b[d] = e }
        return 1
    } catch (a) {
        return 0
    }
};
KJUR.jws.JWS.readSafeJSONString = function(b) {
    var c = null;
    try {
        c = jsonParse(b);
        if (typeof c != "object") {
            return null
        }
        if (c.constructor === Array) {
            return null
        }
        return c
    } catch (a) {
        return null
    }
};
KJUR.jws.JWS.getEncodedSignatureValueFromJWS = function(a) {
    if (a.match(/^[^.]+\.[^.]+\.([^.]+)$/) == null) {
        throw "JWS signature is not a form of 'Head.Payload.SigValue'."
    }
    return RegExp.$1
};
KJUR.jws.JWS.getJWKthumbprint = function(d) {
    if (d.kty !== "RSA" && d.kty !== "EC" && d.kty !== "oct") {
        throw "unsupported algorithm for JWK Thumprint"
    }
    var a = "{";
    if (d.kty === "RSA") {
        if (typeof d.n != "string" || typeof d.e != "string") {
            throw "wrong n and e value for RSA key"
        }
        a += '"e":"' + d.e + '",';
        a += '"kty":"' + d.kty + '",';
        a += '"n":"' + d.n + '"}'
    } else {
        if (d.kty === "EC") {
            if (typeof d.crv != "string" || typeof d.x != "string" || typeof d.y != "string") {
                throw "wrong crv, x and y value for EC key"
            }
            a += '"crv":"' + d.crv + '",';
            a += '"kty":"' + d.kty + '",';
            a += '"x":"' + d.x + '",';
            a += '"y":"' + d.y + '"}'
        } else {
            if (d.kty === "oct") {
                if (typeof d.k != "string") {
                    throw "wrong k value for oct(symmetric) key"
                }
                a += '"kty":"' + d.kty + '",';
                a += '"k":"' + d.k + '"}'
            }
        }
    }
    var b = rstrtohex(a);
    var c = KJUR.crypto.Util.hashHex(b, "sha256");
    var e = hextob64u(c);
    return e
};
KJUR.jws.IntDate = {};
KJUR.jws.IntDate.get = function(a) {
    if (a == "now") {
        return KJUR.jws.IntDate.getNow()
    } else {
        if (a == "now + 1hour") {
            return KJUR.jws.IntDate.getNow() + 60 * 60
        } else {
            if (a == "now + 1day") {
                return KJUR.jws.IntDate.getNow() + 60 * 60 * 24
            } else {
                if (a == "now + 1month") {
                    return KJUR.jws.IntDate.getNow() + 60 * 60 * 24 * 30
                } else {
                    if (a == "now + 1year") {
                        return KJUR.jws.IntDate.getNow() + 60 * 60 * 24 * 365
                    } else {
                        if (a.match(/Z$/)) {
                            return KJUR.jws.IntDate.getZulu(a)
                        } else {
                            if (a.match(/^[0-9]+$/)) {
                                return parseInt(a)
                            }
                        }
                    }
                }
            }
        }
    }
    throw "unsupported format: " + a
};
KJUR.jws.IntDate.getZulu = function(l) {
    var k;
    if (k = l.match(/(\d+)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z/)) {
        var b = RegExp.$1;
        var i = parseInt(b);
        if (b.length == 4) {} else {
            if (b.length == 2) {
                if (50 <= i && i < 100) { i = 1900 + i } else {
                    if (0 <= i && i < 50) { i = 2000 + i } else {
                        throw "malformed year string for UTCTime"
                    }
                }
            } else {
                throw "malformed year string"
            }
        }
        var g = parseInt(RegExp.$2) - 1;
        var j = parseInt(RegExp.$3);
        var c = parseInt(RegExp.$4);
        var e = parseInt(RegExp.$5);
        var f = parseInt(RegExp.$6);
        var h = new Date(Date.UTC(i, g, j, c, e, f));
        return ~~(h / 1000)
    }
    throw "unsupported format: " + l
};
KJUR.jws.IntDate.getNow = function() {
    var a = ~~(new Date() / 1000);
    return a
};
KJUR.jws.IntDate.intDate2UTCString = function(a) {
    var b = new Date(a * 1000);
    return b.toUTCString()
};
KJUR.jws.IntDate.intDate2Zulu = function(e) {
    var i = new Date(e * 1000);
    var h = ("0000" + i.getUTCFullYear()).slice(-4);
    var g = ("00" + (i.getUTCMonth() + 1)).slice(-2);
    var b = ("00" + i.getUTCDate()).slice(-2);
    var a = ("00" + i.getUTCHours()).slice(-2);
    var c = ("00" + i.getUTCMinutes()).slice(-2);
    var f = ("00" + i.getUTCSeconds()).slice(-2);
    return h + g + b + a + c + f + "Z"
};
/*! jwsjs-2.0.1 (c) 2010-2015 Kenji Urushima | kjur.github.com/jsjws/license
 */
if (typeof KJUR == "undefined" || !KJUR) { KJUR = {} }
if (typeof KJUR.jws == "undefined" || !KJUR.jws) { KJUR.jws = {} }
KJUR.jws.JWSJS = function() {
    var a = KJUR.jws.JWS;
    this.aHeader = [];
    this.sPayload = "";
    this.aSignature = [];
    this.init = function() {
        this.aHeader = [];
        this.sPayload = "";
        this.aSignature = []
    };
    this.initWithJWS = function(c) {
        this.init();
        var b = new KJUR.jws.JWS();
        b.parseJWS(c);
        this.aHeader.push(b.parsedJWS.headB64U);
        this.sPayload = b.parsedJWS.payloadB64U;
        this.aSignature.push(b.parsedJWS.sigvalB64U)
    };
    this.addSignatureByHeaderKey = function(e, b) {
        var d = b64utoutf8(this.sPayload);
        var c = new KJUR.jws.JWS();
        var f = c.generateJWSByP1PrvKey(e, d, b);
        this.aHeader.push(c.parsedJWS.headB64U);
        this.aSignature.push(c.parsedJWS.sigvalB64U)
    };
    this.addSignatureByHeaderPayloadKey = function(e, d, b) {
        var c = new KJUR.jws.JWS();
        var f = c.generateJWSByP1PrvKey(e, d, b);
        this.aHeader.push(c.parsedJWS.headB64U);
        this.sPayload = c.parsedJWS.payloadB64U;
        this.aSignature.push(c.parsedJWS.sigvalB64U)
    };
    this.verifyWithCerts = function(c) {
        if (this.aHeader.length != c.length) {
            throw "num headers does not match with num certs"
        }
        if (this.aSignature.length != c.length) {
            throw "num signatures does not match with num certs"
        }
        var k = this.sPayload;
        var g = "";
        for (var d = 0; d < c.length; d++) {
            var e = c[d];
            var f = this.aHeader[d];
            var m = this.aSignature[d];
            var b = f + "." + k + "." + m;
            var j = new KJUR.jws.JWS();
            try {
                var l = j.verifyJWSByPemX509Cert(b, e);
                if (l != 1) { g += (d + 1) + "th signature unmatch. " }
            } catch (h) { g += (d + 1) + "th signature fail(" + h + "). " }
        }
        if (g == "") {
            return 1
        } else {
            throw g
        }
    };
    this.readJWSJS = function(b) {
        var c = a.readSafeJSONString(b);
        if (c == null) {
            throw "argument is not JSON string: " + b
        }
        this.aHeader = c.headers;
        this.sPayload = c.payload;
        this.aSignature = c.signatures
    };
    this.getJSON = function() {
        return { headers: this.aHeader, payload: this.sPayload, signatures: this.aSignature }
    };
    this.isEmpty = function() {
        if (this.aHeader.length == 0) {
            return 1
        }
        return 0
    }
};
/*! nodeutil-1.0.0 (c) 2015 Kenji Urushima | kjur.github.com/jsrsasign/license
 */
function readFileUTF8(a) {
    return require("fs").readFileSync(a, "utf8")
}

function readFileHexByBin(c) {
    var b = require("jsrsasign");
    var a = require("fs");
    return b.rstrtohex(a.readFileSync(c, "binary"))
}

function readFile(b) {
    var a = require("fs");
    return a.readFileSync(b, "binary")
}

function saveFile(c, b) {
    var a = require("fs");
    a.writeFileSync(c, b, "binary")
}

function saveFileBinByHex(e, b) {
    var a = require("fs");
    var c = require("jsrsasign");
    var d = c.hextorstr(b);
    a.writeFileSync(e, d, "binary")
};
exports.SecureRandom = SecureRandom;
exports.rng_seed_time = rng_seed_time;

exports.BigInteger = BigInteger;
exports.RSAKey = RSAKey;
exports.ECDSA = KJUR.crypto.ECDSA;
exports.DSA = KJUR.crypto.DSA;
exports.Signature = KJUR.crypto.Signature;
exports.MessageDigest = KJUR.crypto.MessageDigest;
exports.Mac = KJUR.crypto.Mac;
exports.KEYUTIL = KEYUTIL;
exports.ASN1HEX = ASN1HEX;
exports.X509 = X509;
exports.CryptoJS = CryptoJS;

// ext/base64.js
exports.b64tohex = b64tohex;
exports.b64toBA = b64toBA;

// base64x.js
exports.stoBA = stoBA;
exports.BAtos = BAtos;
exports.BAtohex = BAtohex;
exports.stohex = stohex;
exports.stob64 = stob64;
exports.stob64u = stob64u;
exports.b64utos = b64utos;
exports.b64tob64u = b64tob64u;
exports.b64utob64 = b64utob64;
exports.hex2b64 = hex2b64;
exports.hextob64u = hextob64u;
exports.b64utohex = b64utohex;
exports.b64tohex = b64tohex;
exports.utf8tob64u = utf8tob64u;
exports.b64utoutf8 = b64utoutf8;
exports.utf8tob64 = utf8tob64;
exports.b64toutf8 = b64toutf8;
exports.utf8tohex = utf8tohex;
exports.hextoutf8 = hextoutf8;
exports.hextorstr = hextorstr;
exports.rstrtohex = rstrtohex;
exports.newline_toUnix = newline_toUnix;
exports.newline_toDos = newline_toDos;
exports.intarystrtohex = intarystrtohex;
exports.strdiffidx = strdiffidx;

exports.crypto = KJUR.crypto;
exports.asn1 = KJUR.asn1;
exports.jws = KJUR.jws;

exports.readFileUTF8 = readFileUTF8;
exports.readFileHexByBin = readFileHexByBin;
exports.readFile = readFile;
exports.saveFile = saveFile;
exports.saveFileBinByHex = saveFileBinByHex;

}).call(this,require("buffer").Buffer)
},{"buffer":9,"fs":7,"jsrsasign":34}],35:[function(require,module,exports){
// Generated by CoffeeScript 1.10.0
(function() {
  "use strict";
  var xml2js;

  xml2js = require('../lib/xml2js');

  exports.stripBOM = function(str) {
    if (str[0] === '\uFEFF') {
      return str.substring(1);
    } else {
      return str;
    }
  };

}).call(this);

},{"../lib/xml2js":37}],36:[function(require,module,exports){
// Generated by CoffeeScript 1.10.0
(function() {
  "use strict";
  var prefixMatch;

  prefixMatch = new RegExp(/(?!xmlns)^.*:/);

  exports.normalize = function(str) {
    return str.toLowerCase();
  };

  exports.firstCharLowerCase = function(str) {
    return str.charAt(0).toLowerCase() + str.slice(1);
  };

  exports.stripPrefix = function(str) {
    return str.replace(prefixMatch, '');
  };

  exports.parseNumbers = function(str) {
    if (!isNaN(str)) {
      str = str % 1 === 0 ? parseInt(str, 10) : parseFloat(str);
    }
    return str;
  };

  exports.parseBooleans = function(str) {
    if (/^(?:true|false)$/i.test(str)) {
      str = str.toLowerCase() === 'true';
    }
    return str;
  };

}).call(this);

},{}],37:[function(require,module,exports){
// Generated by CoffeeScript 1.10.0
(function() {
  "use strict";
  var bom, builder, escapeCDATA, events, isEmpty, processName, processors, requiresCDATA, sax, setImmediate, wrapCDATA,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty,
    bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

  sax = require('sax');

  events = require('events');

  builder = require('xmlbuilder');

  bom = require('./bom');

  processors = require('./processors');

  setImmediate = require('timers').setImmediate;

  isEmpty = function(thing) {
    return typeof thing === "object" && (thing != null) && Object.keys(thing).length === 0;
  };

  processName = function(processors, processedName) {
    var i, len, process;
    for (i = 0, len = processors.length; i < len; i++) {
      process = processors[i];
      processedName = process(processedName);
    }
    return processedName;
  };

  requiresCDATA = function(entry) {
    return entry.indexOf('&') >= 0 || entry.indexOf('>') >= 0 || entry.indexOf('<') >= 0;
  };

  wrapCDATA = function(entry) {
    return "<![CDATA[" + (escapeCDATA(entry)) + "]]>";
  };

  escapeCDATA = function(entry) {
    return entry.replace(']]>', ']]]]><![CDATA[>');
  };

  exports.processors = processors;

  exports.defaults = {
    "0.1": {
      explicitCharkey: false,
      trim: true,
      normalize: true,
      normalizeTags: false,
      attrkey: "@",
      charkey: "#",
      explicitArray: false,
      ignoreAttrs: false,
      mergeAttrs: false,
      explicitRoot: false,
      validator: null,
      xmlns: false,
      explicitChildren: false,
      childkey: '@@',
      charsAsChildren: false,
      async: false,
      strict: true,
      attrNameProcessors: null,
      attrValueProcessors: null,
      tagNameProcessors: null,
      valueProcessors: null,
      emptyTag: ''
    },
    "0.2": {
      explicitCharkey: false,
      trim: false,
      normalize: false,
      normalizeTags: false,
      attrkey: "$",
      charkey: "_",
      explicitArray: true,
      ignoreAttrs: false,
      mergeAttrs: false,
      explicitRoot: true,
      validator: null,
      xmlns: false,
      explicitChildren: false,
      preserveChildrenOrder: false,
      childkey: '$$',
      charsAsChildren: false,
      async: false,
      strict: true,
      attrNameProcessors: null,
      attrValueProcessors: null,
      tagNameProcessors: null,
      valueProcessors: null,
      rootName: 'root',
      xmldec: {
        'version': '1.0',
        'encoding': 'UTF-8',
        'standalone': true
      },
      doctype: null,
      renderOpts: {
        'pretty': true,
        'indent': '  ',
        'newline': '\n'
      },
      headless: false,
      chunkSize: 10000,
      emptyTag: '',
      cdata: false
    }
  };

  exports.ValidationError = (function(superClass) {
    extend(ValidationError, superClass);

    function ValidationError(message) {
      this.message = message;
    }

    return ValidationError;

  })(Error);

  exports.Builder = (function() {
    function Builder(opts) {
      var key, ref, value;
      this.options = {};
      ref = exports.defaults["0.2"];
      for (key in ref) {
        if (!hasProp.call(ref, key)) continue;
        value = ref[key];
        this.options[key] = value;
      }
      for (key in opts) {
        if (!hasProp.call(opts, key)) continue;
        value = opts[key];
        this.options[key] = value;
      }
    }

    Builder.prototype.buildObject = function(rootObj) {
      var attrkey, charkey, render, rootElement, rootName;
      attrkey = this.options.attrkey;
      charkey = this.options.charkey;
      if ((Object.keys(rootObj).length === 1) && (this.options.rootName === exports.defaults['0.2'].rootName)) {
        rootName = Object.keys(rootObj)[0];
        rootObj = rootObj[rootName];
      } else {
        rootName = this.options.rootName;
      }
      render = (function(_this) {
        return function(element, obj) {
          var attr, child, entry, index, key, value;
          if (typeof obj !== 'object') {
            if (_this.options.cdata && requiresCDATA(obj)) {
              element.raw(wrapCDATA(obj));
            } else {
              element.txt(obj);
            }
          } else {
            for (key in obj) {
              if (!hasProp.call(obj, key)) continue;
              child = obj[key];
              if (key === attrkey) {
                if (typeof child === "object") {
                  for (attr in child) {
                    value = child[attr];
                    element = element.att(attr, value);
                  }
                }
              } else if (key === charkey) {
                if (_this.options.cdata && requiresCDATA(child)) {
                  element = element.raw(wrapCDATA(child));
                } else {
                  element = element.txt(child);
                }
              } else if (Array.isArray(child)) {
                for (index in child) {
                  if (!hasProp.call(child, index)) continue;
                  entry = child[index];
                  if (typeof entry === 'string') {
                    if (_this.options.cdata && requiresCDATA(entry)) {
                      element = element.ele(key).raw(wrapCDATA(entry)).up();
                    } else {
                      element = element.ele(key, entry).up();
                    }
                  } else {
                    element = render(element.ele(key), entry).up();
                  }
                }
              } else if (typeof child === "object") {
                element = render(element.ele(key), child).up();
              } else {
                if (typeof child === 'string' && _this.options.cdata && requiresCDATA(child)) {
                  element = element.ele(key).raw(wrapCDATA(child)).up();
                } else {
                  if (child == null) {
                    child = '';
                  }
                  element = element.ele(key, child.toString()).up();
                }
              }
            }
          }
          return element;
        };
      })(this);
      rootElement = builder.create(rootName, this.options.xmldec, this.options.doctype, {
        headless: this.options.headless,
        allowSurrogateChars: this.options.allowSurrogateChars
      });
      return render(rootElement, rootObj).end(this.options.renderOpts);
    };

    return Builder;

  })();

  exports.Parser = (function(superClass) {
    extend(Parser, superClass);

    function Parser(opts) {
      this.parseString = bind(this.parseString, this);
      this.reset = bind(this.reset, this);
      this.assignOrPush = bind(this.assignOrPush, this);
      this.processAsync = bind(this.processAsync, this);
      var key, ref, value;
      if (!(this instanceof exports.Parser)) {
        return new exports.Parser(opts);
      }
      this.options = {};
      ref = exports.defaults["0.2"];
      for (key in ref) {
        if (!hasProp.call(ref, key)) continue;
        value = ref[key];
        this.options[key] = value;
      }
      for (key in opts) {
        if (!hasProp.call(opts, key)) continue;
        value = opts[key];
        this.options[key] = value;
      }
      if (this.options.xmlns) {
        this.options.xmlnskey = this.options.attrkey + "ns";
      }
      if (this.options.normalizeTags) {
        if (!this.options.tagNameProcessors) {
          this.options.tagNameProcessors = [];
        }
        this.options.tagNameProcessors.unshift(processors.normalize);
      }
      this.reset();
    }

    Parser.prototype.processAsync = function() {
      var chunk, err, error1;
      try {
        if (this.remaining.length <= this.options.chunkSize) {
          chunk = this.remaining;
          this.remaining = '';
          this.saxParser = this.saxParser.write(chunk);
          return this.saxParser.close();
        } else {
          chunk = this.remaining.substr(0, this.options.chunkSize);
          this.remaining = this.remaining.substr(this.options.chunkSize, this.remaining.length);
          this.saxParser = this.saxParser.write(chunk);
          return setImmediate(this.processAsync);
        }
      } catch (error1) {
        err = error1;
        if (!this.saxParser.errThrown) {
          this.saxParser.errThrown = true;
          return this.emit(err);
        }
      }
    };

    Parser.prototype.assignOrPush = function(obj, key, newValue) {
      if (!(key in obj)) {
        if (!this.options.explicitArray) {
          return obj[key] = newValue;
        } else {
          return obj[key] = [newValue];
        }
      } else {
        if (!(obj[key] instanceof Array)) {
          obj[key] = [obj[key]];
        }
        return obj[key].push(newValue);
      }
    };

    Parser.prototype.reset = function() {
      var attrkey, charkey, ontext, stack;
      this.removeAllListeners();
      this.saxParser = sax.parser(this.options.strict, {
        trim: false,
        normalize: false,
        xmlns: this.options.xmlns
      });
      this.saxParser.errThrown = false;
      this.saxParser.onerror = (function(_this) {
        return function(error) {
          _this.saxParser.resume();
          if (!_this.saxParser.errThrown) {
            _this.saxParser.errThrown = true;
            return _this.emit("error", error);
          }
        };
      })(this);
      this.saxParser.onend = (function(_this) {
        return function() {
          if (!_this.saxParser.ended) {
            _this.saxParser.ended = true;
            return _this.emit("end", _this.resultObject);
          }
        };
      })(this);
      this.saxParser.ended = false;
      this.EXPLICIT_CHARKEY = this.options.explicitCharkey;
      this.resultObject = null;
      stack = [];
      attrkey = this.options.attrkey;
      charkey = this.options.charkey;
      this.saxParser.onopentag = (function(_this) {
        return function(node) {
          var key, newValue, obj, processedKey, ref;
          obj = {};
          obj[charkey] = "";
          if (!_this.options.ignoreAttrs) {
            ref = node.attributes;
            for (key in ref) {
              if (!hasProp.call(ref, key)) continue;
              if (!(attrkey in obj) && !_this.options.mergeAttrs) {
                obj[attrkey] = {};
              }
              newValue = _this.options.attrValueProcessors ? processName(_this.options.attrValueProcessors, node.attributes[key]) : node.attributes[key];
              processedKey = _this.options.attrNameProcessors ? processName(_this.options.attrNameProcessors, key) : key;
              if (_this.options.mergeAttrs) {
                _this.assignOrPush(obj, processedKey, newValue);
              } else {
                obj[attrkey][processedKey] = newValue;
              }
            }
          }
          obj["#name"] = _this.options.tagNameProcessors ? processName(_this.options.tagNameProcessors, node.name) : node.name;
          if (_this.options.xmlns) {
            obj[_this.options.xmlnskey] = {
              uri: node.uri,
              local: node.local
            };
          }
          return stack.push(obj);
        };
      })(this);
      this.saxParser.onclosetag = (function(_this) {
        return function() {
          var cdata, emptyStr, err, error1, key, node, nodeName, obj, objClone, old, s, xpath;
          obj = stack.pop();
          nodeName = obj["#name"];
          if (!_this.options.explicitChildren || !_this.options.preserveChildrenOrder) {
            delete obj["#name"];
          }
          if (obj.cdata === true) {
            cdata = obj.cdata;
            delete obj.cdata;
          }
          s = stack[stack.length - 1];
          if (obj[charkey].match(/^\s*$/) && !cdata) {
            emptyStr = obj[charkey];
            delete obj[charkey];
          } else {
            if (_this.options.trim) {
              obj[charkey] = obj[charkey].trim();
            }
            if (_this.options.normalize) {
              obj[charkey] = obj[charkey].replace(/\s{2,}/g, " ").trim();
            }
            obj[charkey] = _this.options.valueProcessors ? processName(_this.options.valueProcessors, obj[charkey]) : obj[charkey];
            if (Object.keys(obj).length === 1 && charkey in obj && !_this.EXPLICIT_CHARKEY) {
              obj = obj[charkey];
            }
          }
          if (isEmpty(obj)) {
            obj = _this.options.emptyTag !== '' ? _this.options.emptyTag : emptyStr;
          }
          if (_this.options.validator != null) {
            xpath = "/" + ((function() {
              var i, len, results;
              results = [];
              for (i = 0, len = stack.length; i < len; i++) {
                node = stack[i];
                results.push(node["#name"]);
              }
              return results;
            })()).concat(nodeName).join("/");
            try {
              obj = _this.options.validator(xpath, s && s[nodeName], obj);
            } catch (error1) {
              err = error1;
              _this.emit("error", err);
            }
          }
          if (_this.options.explicitChildren && !_this.options.mergeAttrs && typeof obj === 'object') {
            if (!_this.options.preserveChildrenOrder) {
              node = {};
              if (_this.options.attrkey in obj) {
                node[_this.options.attrkey] = obj[_this.options.attrkey];
                delete obj[_this.options.attrkey];
              }
              if (!_this.options.charsAsChildren && _this.options.charkey in obj) {
                node[_this.options.charkey] = obj[_this.options.charkey];
                delete obj[_this.options.charkey];
              }
              if (Object.getOwnPropertyNames(obj).length > 0) {
                node[_this.options.childkey] = obj;
              }
              obj = node;
            } else if (s) {
              s[_this.options.childkey] = s[_this.options.childkey] || [];
              objClone = {};
              for (key in obj) {
                if (!hasProp.call(obj, key)) continue;
                objClone[key] = obj[key];
              }
              s[_this.options.childkey].push(objClone);
              delete obj["#name"];
              if (Object.keys(obj).length === 1 && charkey in obj && !_this.EXPLICIT_CHARKEY) {
                obj = obj[charkey];
              }
            }
          }
          if (stack.length > 0) {
            return _this.assignOrPush(s, nodeName, obj);
          } else {
            if (_this.options.explicitRoot) {
              old = obj;
              obj = {};
              obj[nodeName] = old;
            }
            _this.resultObject = obj;
            _this.saxParser.ended = true;
            return _this.emit("end", _this.resultObject);
          }
        };
      })(this);
      ontext = (function(_this) {
        return function(text) {
          var charChild, s;
          s = stack[stack.length - 1];
          if (s) {
            s[charkey] += text;
            if (_this.options.explicitChildren && _this.options.preserveChildrenOrder && _this.options.charsAsChildren && text.replace(/\\n/g, '').trim() !== '') {
              s[_this.options.childkey] = s[_this.options.childkey] || [];
              charChild = {
                '#name': '__text__'
              };
              charChild[charkey] = text;
              s[_this.options.childkey].push(charChild);
            }
            return s;
          }
        };
      })(this);
      this.saxParser.ontext = ontext;
      return this.saxParser.oncdata = (function(_this) {
        return function(text) {
          var s;
          s = ontext(text);
          if (s) {
            return s.cdata = true;
          }
        };
      })(this);
    };

    Parser.prototype.parseString = function(str, cb) {
      var err, error1;
      if ((cb != null) && typeof cb === "function") {
        this.on("end", function(result) {
          this.reset();
          return cb(null, result);
        });
        this.on("error", function(err) {
          this.reset();
          return cb(err);
        });
      }
      try {
        str = str.toString();
        if (str.trim() === '') {
          this.emit("end", null);
          return true;
        }
        str = bom.stripBOM(str);
        if (this.options.async) {
          this.remaining = str;
          setImmediate(this.processAsync);
          return this.saxParser;
        }
        return this.saxParser.write(str).close();
      } catch (error1) {
        err = error1;
        if (!(this.saxParser.errThrown || this.saxParser.ended)) {
          this.emit('error', err);
          return this.saxParser.errThrown = true;
        } else if (this.saxParser.ended) {
          throw err;
        }
      }
    };

    return Parser;

  })(events.EventEmitter);

  exports.parseString = function(str, a, b) {
    var cb, options, parser;
    if (b != null) {
      if (typeof b === 'function') {
        cb = b;
      }
      if (typeof a === 'object') {
        options = a;
      }
    } else {
      if (typeof a === 'function') {
        cb = a;
      }
      options = {};
    }
    parser = new exports.Parser(options);
    return parser.parseString(str, cb);
  };

}).call(this);

},{"./bom":35,"./processors":36,"events":13,"sax":38,"timers":33,"xmlbuilder":55}],38:[function(require,module,exports){
(function (Buffer){
;(function (sax) { // wrapper for non-node envs
  sax.parser = function (strict, opt) { return new SAXParser(strict, opt) }
  sax.SAXParser = SAXParser
  sax.SAXStream = SAXStream
  sax.createStream = createStream

  // When we pass the MAX_BUFFER_LENGTH position, start checking for buffer overruns.
  // When we check, schedule the next check for MAX_BUFFER_LENGTH - (max(buffer lengths)),
  // since that's the earliest that a buffer overrun could occur.  This way, checks are
  // as rare as required, but as often as necessary to ensure never crossing this bound.
  // Furthermore, buffers are only tested at most once per write(), so passing a very
  // large string into write() might have undesirable effects, but this is manageable by
  // the caller, so it is assumed to be safe.  Thus, a call to write() may, in the extreme
  // edge case, result in creating at most one complete copy of the string passed in.
  // Set to Infinity to have unlimited buffers.
  sax.MAX_BUFFER_LENGTH = 64 * 1024

  var buffers = [
    'comment', 'sgmlDecl', 'textNode', 'tagName', 'doctype',
    'procInstName', 'procInstBody', 'entity', 'attribName',
    'attribValue', 'cdata', 'script'
  ]

  sax.EVENTS = [
    'text',
    'processinginstruction',
    'sgmldeclaration',
    'doctype',
    'comment',
    'opentagstart',
    'attribute',
    'opentag',
    'closetag',
    'opencdata',
    'cdata',
    'closecdata',
    'error',
    'end',
    'ready',
    'script',
    'opennamespace',
    'closenamespace'
  ]

  function SAXParser (strict, opt) {
    if (!(this instanceof SAXParser)) {
      return new SAXParser(strict, opt)
    }

    var parser = this
    clearBuffers(parser)
    parser.q = parser.c = ''
    parser.bufferCheckPosition = sax.MAX_BUFFER_LENGTH
    parser.opt = opt || {}
    parser.opt.lowercase = parser.opt.lowercase || parser.opt.lowercasetags
    parser.looseCase = parser.opt.lowercase ? 'toLowerCase' : 'toUpperCase'
    parser.tags = []
    parser.closed = parser.closedRoot = parser.sawRoot = false
    parser.tag = parser.error = null
    parser.strict = !!strict
    parser.noscript = !!(strict || parser.opt.noscript)
    parser.state = S.BEGIN
    parser.strictEntities = parser.opt.strictEntities
    parser.ENTITIES = parser.strictEntities ? Object.create(sax.XML_ENTITIES) : Object.create(sax.ENTITIES)
    parser.attribList = []

    // namespaces form a prototype chain.
    // it always points at the current tag,
    // which protos to its parent tag.
    if (parser.opt.xmlns) {
      parser.ns = Object.create(rootNS)
    }

    // mostly just for error reporting
    parser.trackPosition = parser.opt.position !== false
    if (parser.trackPosition) {
      parser.position = parser.line = parser.column = 0
    }
    emit(parser, 'onready')
  }

  if (!Object.create) {
    Object.create = function (o) {
      function F () {}
      F.prototype = o
      var newf = new F()
      return newf
    }
  }

  if (!Object.keys) {
    Object.keys = function (o) {
      var a = []
      for (var i in o) if (o.hasOwnProperty(i)) a.push(i)
      return a
    }
  }

  function checkBufferLength (parser) {
    var maxAllowed = Math.max(sax.MAX_BUFFER_LENGTH, 10)
    var maxActual = 0
    for (var i = 0, l = buffers.length; i < l; i++) {
      var len = parser[buffers[i]].length
      if (len > maxAllowed) {
        // Text/cdata nodes can get big, and since they're buffered,
        // we can get here under normal conditions.
        // Avoid issues by emitting the text node now,
        // so at least it won't get any bigger.
        switch (buffers[i]) {
          case 'textNode':
            closeText(parser)
            break

          case 'cdata':
            emitNode(parser, 'oncdata', parser.cdata)
            parser.cdata = ''
            break

          case 'script':
            emitNode(parser, 'onscript', parser.script)
            parser.script = ''
            break

          default:
            error(parser, 'Max buffer length exceeded: ' + buffers[i])
        }
      }
      maxActual = Math.max(maxActual, len)
    }
    // schedule the next check for the earliest possible buffer overrun.
    var m = sax.MAX_BUFFER_LENGTH - maxActual
    parser.bufferCheckPosition = m + parser.position
  }

  function clearBuffers (parser) {
    for (var i = 0, l = buffers.length; i < l; i++) {
      parser[buffers[i]] = ''
    }
  }

  function flushBuffers (parser) {
    closeText(parser)
    if (parser.cdata !== '') {
      emitNode(parser, 'oncdata', parser.cdata)
      parser.cdata = ''
    }
    if (parser.script !== '') {
      emitNode(parser, 'onscript', parser.script)
      parser.script = ''
    }
  }

  SAXParser.prototype = {
    end: function () { end(this) },
    write: write,
    resume: function () { this.error = null; return this },
    close: function () { return this.write(null) },
    flush: function () { flushBuffers(this) }
  }

  var Stream
  try {
    Stream = require('stream').Stream
  } catch (ex) {
    Stream = function () {}
  }

  var streamWraps = sax.EVENTS.filter(function (ev) {
    return ev !== 'error' && ev !== 'end'
  })

  function createStream (strict, opt) {
    return new SAXStream(strict, opt)
  }

  function SAXStream (strict, opt) {
    if (!(this instanceof SAXStream)) {
      return new SAXStream(strict, opt)
    }

    Stream.apply(this)

    this._parser = new SAXParser(strict, opt)
    this.writable = true
    this.readable = true

    var me = this

    this._parser.onend = function () {
      me.emit('end')
    }

    this._parser.onerror = function (er) {
      me.emit('error', er)

      // if didn't throw, then means error was handled.
      // go ahead and clear error, so we can write again.
      me._parser.error = null
    }

    this._decoder = null

    streamWraps.forEach(function (ev) {
      Object.defineProperty(me, 'on' + ev, {
        get: function () {
          return me._parser['on' + ev]
        },
        set: function (h) {
          if (!h) {
            me.removeAllListeners(ev)
            me._parser['on' + ev] = h
            return h
          }
          me.on(ev, h)
        },
        enumerable: true,
        configurable: false
      })
    })
  }

  SAXStream.prototype = Object.create(Stream.prototype, {
    constructor: {
      value: SAXStream
    }
  })

  SAXStream.prototype.write = function (data) {
    if (typeof Buffer === 'function' &&
      typeof Buffer.isBuffer === 'function' &&
      Buffer.isBuffer(data)) {
      if (!this._decoder) {
        var SD = require('string_decoder').StringDecoder
        this._decoder = new SD('utf8')
      }
      data = this._decoder.write(data)
    }

    this._parser.write(data.toString())
    this.emit('data', data)
    return true
  }

  SAXStream.prototype.end = function (chunk) {
    if (chunk && chunk.length) {
      this.write(chunk)
    }
    this._parser.end()
    return true
  }

  SAXStream.prototype.on = function (ev, handler) {
    var me = this
    if (!me._parser['on' + ev] && streamWraps.indexOf(ev) !== -1) {
      me._parser['on' + ev] = function () {
        var args = arguments.length === 1 ? [arguments[0]] : Array.apply(null, arguments)
        args.splice(0, 0, ev)
        me.emit.apply(me, args)
      }
    }

    return Stream.prototype.on.call(me, ev, handler)
  }

  // character classes and tokens
  var whitespace = '\r\n\t '

  // this really needs to be replaced with character classes.
  // XML allows all manner of ridiculous numbers and digits.
  var number = '0124356789'
  var letter = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

  // (Letter | "_" | ":")
  var quote = '\'"'
  var attribEnd = whitespace + '>'
  var CDATA = '[CDATA['
  var DOCTYPE = 'DOCTYPE'
  var XML_NAMESPACE = 'http://www.w3.org/XML/1998/namespace'
  var XMLNS_NAMESPACE = 'http://www.w3.org/2000/xmlns/'
  var rootNS = { xml: XML_NAMESPACE, xmlns: XMLNS_NAMESPACE }

  // turn all the string character sets into character class objects.
  whitespace = charClass(whitespace)
  number = charClass(number)
  letter = charClass(letter)

  // http://www.w3.org/TR/REC-xml/#NT-NameStartChar
  // This implementation works on strings, a single character at a time
  // as such, it cannot ever support astral-plane characters (10000-EFFFF)
  // without a significant breaking change to either this  parser, or the
  // JavaScript language.  Implementation of an emoji-capable xml parser
  // is left as an exercise for the reader.
  var nameStart = /[:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]/

  var nameBody = /[:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD\u00B7\u0300-\u036F\u203F-\u2040\.\d-]/

  var entityStart = /[#:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]/
  var entityBody = /[#:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD\u00B7\u0300-\u036F\u203F-\u2040\.\d-]/

  quote = charClass(quote)
  attribEnd = charClass(attribEnd)

  function charClass (str) {
    return str.split('').reduce(function (s, c) {
      s[c] = true
      return s
    }, {})
  }

  function isRegExp (c) {
    return Object.prototype.toString.call(c) === '[object RegExp]'
  }

  function is (charclass, c) {
    return isRegExp(charclass) ? !!c.match(charclass) : charclass[c]
  }

  function not (charclass, c) {
    return !is(charclass, c)
  }

  var S = 0
  sax.STATE = {
    BEGIN: S++, // leading byte order mark or whitespace
    BEGIN_WHITESPACE: S++, // leading whitespace
    TEXT: S++, // general stuff
    TEXT_ENTITY: S++, // &amp and such.
    OPEN_WAKA: S++, // <
    SGML_DECL: S++, // <!BLARG
    SGML_DECL_QUOTED: S++, // <!BLARG foo "bar
    DOCTYPE: S++, // <!DOCTYPE
    DOCTYPE_QUOTED: S++, // <!DOCTYPE "//blah
    DOCTYPE_DTD: S++, // <!DOCTYPE "//blah" [ ...
    DOCTYPE_DTD_QUOTED: S++, // <!DOCTYPE "//blah" [ "foo
    COMMENT_STARTING: S++, // <!-
    COMMENT: S++, // <!--
    COMMENT_ENDING: S++, // <!-- blah -
    COMMENT_ENDED: S++, // <!-- blah --
    CDATA: S++, // <![CDATA[ something
    CDATA_ENDING: S++, // ]
    CDATA_ENDING_2: S++, // ]]
    PROC_INST: S++, // <?hi
    PROC_INST_BODY: S++, // <?hi there
    PROC_INST_ENDING: S++, // <?hi "there" ?
    OPEN_TAG: S++, // <strong
    OPEN_TAG_SLASH: S++, // <strong /
    ATTRIB: S++, // <a
    ATTRIB_NAME: S++, // <a foo
    ATTRIB_NAME_SAW_WHITE: S++, // <a foo _
    ATTRIB_VALUE: S++, // <a foo=
    ATTRIB_VALUE_QUOTED: S++, // <a foo="bar
    ATTRIB_VALUE_CLOSED: S++, // <a foo="bar"
    ATTRIB_VALUE_UNQUOTED: S++, // <a foo=bar
    ATTRIB_VALUE_ENTITY_Q: S++, // <foo bar="&quot;"
    ATTRIB_VALUE_ENTITY_U: S++, // <foo bar=&quot
    CLOSE_TAG: S++, // </a
    CLOSE_TAG_SAW_WHITE: S++, // </a   >
    SCRIPT: S++, // <script> ...
    SCRIPT_ENDING: S++ // <script> ... <
  }

  sax.XML_ENTITIES = {
    'amp': '&',
    'gt': '>',
    'lt': '<',
    'quot': '"',
    'apos': "'"
  }

  sax.ENTITIES = {
    'amp': '&',
    'gt': '>',
    'lt': '<',
    'quot': '"',
    'apos': "'",
    'AElig': 198,
    'Aacute': 193,
    'Acirc': 194,
    'Agrave': 192,
    'Aring': 197,
    'Atilde': 195,
    'Auml': 196,
    'Ccedil': 199,
    'ETH': 208,
    'Eacute': 201,
    'Ecirc': 202,
    'Egrave': 200,
    'Euml': 203,
    'Iacute': 205,
    'Icirc': 206,
    'Igrave': 204,
    'Iuml': 207,
    'Ntilde': 209,
    'Oacute': 211,
    'Ocirc': 212,
    'Ograve': 210,
    'Oslash': 216,
    'Otilde': 213,
    'Ouml': 214,
    'THORN': 222,
    'Uacute': 218,
    'Ucirc': 219,
    'Ugrave': 217,
    'Uuml': 220,
    'Yacute': 221,
    'aacute': 225,
    'acirc': 226,
    'aelig': 230,
    'agrave': 224,
    'aring': 229,
    'atilde': 227,
    'auml': 228,
    'ccedil': 231,
    'eacute': 233,
    'ecirc': 234,
    'egrave': 232,
    'eth': 240,
    'euml': 235,
    'iacute': 237,
    'icirc': 238,
    'igrave': 236,
    'iuml': 239,
    'ntilde': 241,
    'oacute': 243,
    'ocirc': 244,
    'ograve': 242,
    'oslash': 248,
    'otilde': 245,
    'ouml': 246,
    'szlig': 223,
    'thorn': 254,
    'uacute': 250,
    'ucirc': 251,
    'ugrave': 249,
    'uuml': 252,
    'yacute': 253,
    'yuml': 255,
    'copy': 169,
    'reg': 174,
    'nbsp': 160,
    'iexcl': 161,
    'cent': 162,
    'pound': 163,
    'curren': 164,
    'yen': 165,
    'brvbar': 166,
    'sect': 167,
    'uml': 168,
    'ordf': 170,
    'laquo': 171,
    'not': 172,
    'shy': 173,
    'macr': 175,
    'deg': 176,
    'plusmn': 177,
    'sup1': 185,
    'sup2': 178,
    'sup3': 179,
    'acute': 180,
    'micro': 181,
    'para': 182,
    'middot': 183,
    'cedil': 184,
    'ordm': 186,
    'raquo': 187,
    'frac14': 188,
    'frac12': 189,
    'frac34': 190,
    'iquest': 191,
    'times': 215,
    'divide': 247,
    'OElig': 338,
    'oelig': 339,
    'Scaron': 352,
    'scaron': 353,
    'Yuml': 376,
    'fnof': 402,
    'circ': 710,
    'tilde': 732,
    'Alpha': 913,
    'Beta': 914,
    'Gamma': 915,
    'Delta': 916,
    'Epsilon': 917,
    'Zeta': 918,
    'Eta': 919,
    'Theta': 920,
    'Iota': 921,
    'Kappa': 922,
    'Lambda': 923,
    'Mu': 924,
    'Nu': 925,
    'Xi': 926,
    'Omicron': 927,
    'Pi': 928,
    'Rho': 929,
    'Sigma': 931,
    'Tau': 932,
    'Upsilon': 933,
    'Phi': 934,
    'Chi': 935,
    'Psi': 936,
    'Omega': 937,
    'alpha': 945,
    'beta': 946,
    'gamma': 947,
    'delta': 948,
    'epsilon': 949,
    'zeta': 950,
    'eta': 951,
    'theta': 952,
    'iota': 953,
    'kappa': 954,
    'lambda': 955,
    'mu': 956,
    'nu': 957,
    'xi': 958,
    'omicron': 959,
    'pi': 960,
    'rho': 961,
    'sigmaf': 962,
    'sigma': 963,
    'tau': 964,
    'upsilon': 965,
    'phi': 966,
    'chi': 967,
    'psi': 968,
    'omega': 969,
    'thetasym': 977,
    'upsih': 978,
    'piv': 982,
    'ensp': 8194,
    'emsp': 8195,
    'thinsp': 8201,
    'zwnj': 8204,
    'zwj': 8205,
    'lrm': 8206,
    'rlm': 8207,
    'ndash': 8211,
    'mdash': 8212,
    'lsquo': 8216,
    'rsquo': 8217,
    'sbquo': 8218,
    'ldquo': 8220,
    'rdquo': 8221,
    'bdquo': 8222,
    'dagger': 8224,
    'Dagger': 8225,
    'bull': 8226,
    'hellip': 8230,
    'permil': 8240,
    'prime': 8242,
    'Prime': 8243,
    'lsaquo': 8249,
    'rsaquo': 8250,
    'oline': 8254,
    'frasl': 8260,
    'euro': 8364,
    'image': 8465,
    'weierp': 8472,
    'real': 8476,
    'trade': 8482,
    'alefsym': 8501,
    'larr': 8592,
    'uarr': 8593,
    'rarr': 8594,
    'darr': 8595,
    'harr': 8596,
    'crarr': 8629,
    'lArr': 8656,
    'uArr': 8657,
    'rArr': 8658,
    'dArr': 8659,
    'hArr': 8660,
    'forall': 8704,
    'part': 8706,
    'exist': 8707,
    'empty': 8709,
    'nabla': 8711,
    'isin': 8712,
    'notin': 8713,
    'ni': 8715,
    'prod': 8719,
    'sum': 8721,
    'minus': 8722,
    'lowast': 8727,
    'radic': 8730,
    'prop': 8733,
    'infin': 8734,
    'ang': 8736,
    'and': 8743,
    'or': 8744,
    'cap': 8745,
    'cup': 8746,
    'int': 8747,
    'there4': 8756,
    'sim': 8764,
    'cong': 8773,
    'asymp': 8776,
    'ne': 8800,
    'equiv': 8801,
    'le': 8804,
    'ge': 8805,
    'sub': 8834,
    'sup': 8835,
    'nsub': 8836,
    'sube': 8838,
    'supe': 8839,
    'oplus': 8853,
    'otimes': 8855,
    'perp': 8869,
    'sdot': 8901,
    'lceil': 8968,
    'rceil': 8969,
    'lfloor': 8970,
    'rfloor': 8971,
    'lang': 9001,
    'rang': 9002,
    'loz': 9674,
    'spades': 9824,
    'clubs': 9827,
    'hearts': 9829,
    'diams': 9830
  }

  Object.keys(sax.ENTITIES).forEach(function (key) {
    var e = sax.ENTITIES[key]
    var s = typeof e === 'number' ? String.fromCharCode(e) : e
    sax.ENTITIES[key] = s
  })

  for (var s in sax.STATE) {
    sax.STATE[sax.STATE[s]] = s
  }

  // shorthand
  S = sax.STATE

  function emit (parser, event, data) {
    parser[event] && parser[event](data)
  }

  function emitNode (parser, nodeType, data) {
    if (parser.textNode) closeText(parser)
    emit(parser, nodeType, data)
  }

  function closeText (parser) {
    parser.textNode = textopts(parser.opt, parser.textNode)
    if (parser.textNode) emit(parser, 'ontext', parser.textNode)
    parser.textNode = ''
  }

  function textopts (opt, text) {
    if (opt.trim) text = text.trim()
    if (opt.normalize) text = text.replace(/\s+/g, ' ')
    return text
  }

  function error (parser, er) {
    closeText(parser)
    if (parser.trackPosition) {
      er += '\nLine: ' + parser.line +
        '\nColumn: ' + parser.column +
        '\nChar: ' + parser.c
    }
    er = new Error(er)
    parser.error = er
    emit(parser, 'onerror', er)
    return parser
  }

  function end (parser) {
    if (parser.sawRoot && !parser.closedRoot) strictFail(parser, 'Unclosed root tag')
    if ((parser.state !== S.BEGIN) &&
      (parser.state !== S.BEGIN_WHITESPACE) &&
      (parser.state !== S.TEXT)) {
      error(parser, 'Unexpected end')
    }
    closeText(parser)
    parser.c = ''
    parser.closed = true
    emit(parser, 'onend')
    SAXParser.call(parser, parser.strict, parser.opt)
    return parser
  }

  function strictFail (parser, message) {
    if (typeof parser !== 'object' || !(parser instanceof SAXParser)) {
      throw new Error('bad call to strictFail')
    }
    if (parser.strict) {
      error(parser, message)
    }
  }

  function newTag (parser) {
    if (!parser.strict) parser.tagName = parser.tagName[parser.looseCase]()
    var parent = parser.tags[parser.tags.length - 1] || parser
    var tag = parser.tag = { name: parser.tagName, attributes: {} }

    // will be overridden if tag contails an xmlns="foo" or xmlns:foo="bar"
    if (parser.opt.xmlns) {
      tag.ns = parent.ns
    }
    parser.attribList.length = 0
    emitNode(parser, 'onopentagstart', tag)
  }

  function qname (name, attribute) {
    var i = name.indexOf(':')
    var qualName = i < 0 ? [ '', name ] : name.split(':')
    var prefix = qualName[0]
    var local = qualName[1]

    // <x "xmlns"="http://foo">
    if (attribute && name === 'xmlns') {
      prefix = 'xmlns'
      local = ''
    }

    return { prefix: prefix, local: local }
  }

  function attrib (parser) {
    if (!parser.strict) {
      parser.attribName = parser.attribName[parser.looseCase]()
    }

    if (parser.attribList.indexOf(parser.attribName) !== -1 ||
      parser.tag.attributes.hasOwnProperty(parser.attribName)) {
      parser.attribName = parser.attribValue = ''
      return
    }

    if (parser.opt.xmlns) {
      var qn = qname(parser.attribName, true)
      var prefix = qn.prefix
      var local = qn.local

      if (prefix === 'xmlns') {
        // namespace binding attribute. push the binding into scope
        if (local === 'xml' && parser.attribValue !== XML_NAMESPACE) {
          strictFail(parser,
            'xml: prefix must be bound to ' + XML_NAMESPACE + '\n' +
            'Actual: ' + parser.attribValue)
        } else if (local === 'xmlns' && parser.attribValue !== XMLNS_NAMESPACE) {
          strictFail(parser,
            'xmlns: prefix must be bound to ' + XMLNS_NAMESPACE + '\n' +
            'Actual: ' + parser.attribValue)
        } else {
          var tag = parser.tag
          var parent = parser.tags[parser.tags.length - 1] || parser
          if (tag.ns === parent.ns) {
            tag.ns = Object.create(parent.ns)
          }
          tag.ns[local] = parser.attribValue
        }
      }

      // defer onattribute events until all attributes have been seen
      // so any new bindings can take effect. preserve attribute order
      // so deferred events can be emitted in document order
      parser.attribList.push([parser.attribName, parser.attribValue])
    } else {
      // in non-xmlns mode, we can emit the event right away
      parser.tag.attributes[parser.attribName] = parser.attribValue
      emitNode(parser, 'onattribute', {
        name: parser.attribName,
        value: parser.attribValue
      })
    }

    parser.attribName = parser.attribValue = ''
  }

  function openTag (parser, selfClosing) {
    if (parser.opt.xmlns) {
      // emit namespace binding events
      var tag = parser.tag

      // add namespace info to tag
      var qn = qname(parser.tagName)
      tag.prefix = qn.prefix
      tag.local = qn.local
      tag.uri = tag.ns[qn.prefix] || ''

      if (tag.prefix && !tag.uri) {
        strictFail(parser, 'Unbound namespace prefix: ' +
          JSON.stringify(parser.tagName))
        tag.uri = qn.prefix
      }

      var parent = parser.tags[parser.tags.length - 1] || parser
      if (tag.ns && parent.ns !== tag.ns) {
        Object.keys(tag.ns).forEach(function (p) {
          emitNode(parser, 'onopennamespace', {
            prefix: p,
            uri: tag.ns[p]
          })
        })
      }

      // handle deferred onattribute events
      // Note: do not apply default ns to attributes:
      //   http://www.w3.org/TR/REC-xml-names/#defaulting
      for (var i = 0, l = parser.attribList.length; i < l; i++) {
        var nv = parser.attribList[i]
        var name = nv[0]
        var value = nv[1]
        var qualName = qname(name, true)
        var prefix = qualName.prefix
        var local = qualName.local
        var uri = prefix === '' ? '' : (tag.ns[prefix] || '')
        var a = {
          name: name,
          value: value,
          prefix: prefix,
          local: local,
          uri: uri
        }

        // if there's any attributes with an undefined namespace,
        // then fail on them now.
        if (prefix && prefix !== 'xmlns' && !uri) {
          strictFail(parser, 'Unbound namespace prefix: ' +
            JSON.stringify(prefix))
          a.uri = prefix
        }
        parser.tag.attributes[name] = a
        emitNode(parser, 'onattribute', a)
      }
      parser.attribList.length = 0
    }

    parser.tag.isSelfClosing = !!selfClosing

    // process the tag
    parser.sawRoot = true
    parser.tags.push(parser.tag)
    emitNode(parser, 'onopentag', parser.tag)
    if (!selfClosing) {
      // special case for <script> in non-strict mode.
      if (!parser.noscript && parser.tagName.toLowerCase() === 'script') {
        parser.state = S.SCRIPT
      } else {
        parser.state = S.TEXT
      }
      parser.tag = null
      parser.tagName = ''
    }
    parser.attribName = parser.attribValue = ''
    parser.attribList.length = 0
  }

  function closeTag (parser) {
    if (!parser.tagName) {
      strictFail(parser, 'Weird empty close tag.')
      parser.textNode += '</>'
      parser.state = S.TEXT
      return
    }

    if (parser.script) {
      if (parser.tagName !== 'script') {
        parser.script += '</' + parser.tagName + '>'
        parser.tagName = ''
        parser.state = S.SCRIPT
        return
      }
      emitNode(parser, 'onscript', parser.script)
      parser.script = ''
    }

    // first make sure that the closing tag actually exists.
    // <a><b></c></b></a> will close everything, otherwise.
    var t = parser.tags.length
    var tagName = parser.tagName
    if (!parser.strict) {
      tagName = tagName[parser.looseCase]()
    }
    var closeTo = tagName
    while (t--) {
      var close = parser.tags[t]
      if (close.name !== closeTo) {
        // fail the first time in strict mode
        strictFail(parser, 'Unexpected close tag')
      } else {
        break
      }
    }

    // didn't find it.  we already failed for strict, so just abort.
    if (t < 0) {
      strictFail(parser, 'Unmatched closing tag: ' + parser.tagName)
      parser.textNode += '</' + parser.tagName + '>'
      parser.state = S.TEXT
      return
    }
    parser.tagName = tagName
    var s = parser.tags.length
    while (s-- > t) {
      var tag = parser.tag = parser.tags.pop()
      parser.tagName = parser.tag.name
      emitNode(parser, 'onclosetag', parser.tagName)

      var x = {}
      for (var i in tag.ns) {
        x[i] = tag.ns[i]
      }

      var parent = parser.tags[parser.tags.length - 1] || parser
      if (parser.opt.xmlns && tag.ns !== parent.ns) {
        // remove namespace bindings introduced by tag
        Object.keys(tag.ns).forEach(function (p) {
          var n = tag.ns[p]
          emitNode(parser, 'onclosenamespace', { prefix: p, uri: n })
        })
      }
    }
    if (t === 0) parser.closedRoot = true
    parser.tagName = parser.attribValue = parser.attribName = ''
    parser.attribList.length = 0
    parser.state = S.TEXT
  }

  function parseEntity (parser) {
    var entity = parser.entity
    var entityLC = entity.toLowerCase()
    var num
    var numStr = ''

    if (parser.ENTITIES[entity]) {
      return parser.ENTITIES[entity]
    }
    if (parser.ENTITIES[entityLC]) {
      return parser.ENTITIES[entityLC]
    }
    entity = entityLC
    if (entity.charAt(0) === '#') {
      if (entity.charAt(1) === 'x') {
        entity = entity.slice(2)
        num = parseInt(entity, 16)
        numStr = num.toString(16)
      } else {
        entity = entity.slice(1)
        num = parseInt(entity, 10)
        numStr = num.toString(10)
      }
    }
    entity = entity.replace(/^0+/, '')
    if (numStr.toLowerCase() !== entity) {
      strictFail(parser, 'Invalid character entity')
      return '&' + parser.entity + ';'
    }

    return String.fromCodePoint(num)
  }

  function beginWhiteSpace (parser, c) {
    if (c === '<') {
      parser.state = S.OPEN_WAKA
      parser.startTagPosition = parser.position
    } else if (not(whitespace, c)) {
      // have to process this as a text node.
      // weird, but happens.
      strictFail(parser, 'Non-whitespace before first tag.')
      parser.textNode = c
      parser.state = S.TEXT
    }
  }

  function charAt (chunk, i) {
    var result = ''
    if (i < chunk.length) {
      result = chunk.charAt(i)
    }
    return result
  }

  function write (chunk) {
    var parser = this
    if (this.error) {
      throw this.error
    }
    if (parser.closed) {
      return error(parser,
        'Cannot write after close. Assign an onready handler.')
    }
    if (chunk === null) {
      return end(parser)
    }
    if (typeof chunk === 'object') {
      chunk = chunk.toString()
    }
    var i = 0
    var c = ''
    while (true) {
      c = charAt(chunk, i++)
      parser.c = c
      if (!c) {
        break
      }
      if (parser.trackPosition) {
        parser.position++
        if (c === '\n') {
          parser.line++
          parser.column = 0
        } else {
          parser.column++
        }
      }
      switch (parser.state) {
        case S.BEGIN:
          parser.state = S.BEGIN_WHITESPACE
          if (c === '\uFEFF') {
            continue
          }
          beginWhiteSpace(parser, c)
          continue

        case S.BEGIN_WHITESPACE:
          beginWhiteSpace(parser, c)
          continue

        case S.TEXT:
          if (parser.sawRoot && !parser.closedRoot) {
            var starti = i - 1
            while (c && c !== '<' && c !== '&') {
              c = charAt(chunk, i++)
              if (c && parser.trackPosition) {
                parser.position++
                if (c === '\n') {
                  parser.line++
                  parser.column = 0
                } else {
                  parser.column++
                }
              }
            }
            parser.textNode += chunk.substring(starti, i - 1)
          }
          if (c === '<' && !(parser.sawRoot && parser.closedRoot && !parser.strict)) {
            parser.state = S.OPEN_WAKA
            parser.startTagPosition = parser.position
          } else {
            if (not(whitespace, c) && (!parser.sawRoot || parser.closedRoot)) {
              strictFail(parser, 'Text data outside of root node.')
            }
            if (c === '&') {
              parser.state = S.TEXT_ENTITY
            } else {
              parser.textNode += c
            }
          }
          continue

        case S.SCRIPT:
          // only non-strict
          if (c === '<') {
            parser.state = S.SCRIPT_ENDING
          } else {
            parser.script += c
          }
          continue

        case S.SCRIPT_ENDING:
          if (c === '/') {
            parser.state = S.CLOSE_TAG
          } else {
            parser.script += '<' + c
            parser.state = S.SCRIPT
          }
          continue

        case S.OPEN_WAKA:
          // either a /, ?, !, or text is coming next.
          if (c === '!') {
            parser.state = S.SGML_DECL
            parser.sgmlDecl = ''
          } else if (is(whitespace, c)) {
            // wait for it...
          } else if (is(nameStart, c)) {
            parser.state = S.OPEN_TAG
            parser.tagName = c
          } else if (c === '/') {
            parser.state = S.CLOSE_TAG
            parser.tagName = ''
          } else if (c === '?') {
            parser.state = S.PROC_INST
            parser.procInstName = parser.procInstBody = ''
          } else {
            strictFail(parser, 'Unencoded <')
            // if there was some whitespace, then add that in.
            if (parser.startTagPosition + 1 < parser.position) {
              var pad = parser.position - parser.startTagPosition
              c = new Array(pad).join(' ') + c
            }
            parser.textNode += '<' + c
            parser.state = S.TEXT
          }
          continue

        case S.SGML_DECL:
          if ((parser.sgmlDecl + c).toUpperCase() === CDATA) {
            emitNode(parser, 'onopencdata')
            parser.state = S.CDATA
            parser.sgmlDecl = ''
            parser.cdata = ''
          } else if (parser.sgmlDecl + c === '--') {
            parser.state = S.COMMENT
            parser.comment = ''
            parser.sgmlDecl = ''
          } else if ((parser.sgmlDecl + c).toUpperCase() === DOCTYPE) {
            parser.state = S.DOCTYPE
            if (parser.doctype || parser.sawRoot) {
              strictFail(parser,
                'Inappropriately located doctype declaration')
            }
            parser.doctype = ''
            parser.sgmlDecl = ''
          } else if (c === '>') {
            emitNode(parser, 'onsgmldeclaration', parser.sgmlDecl)
            parser.sgmlDecl = ''
            parser.state = S.TEXT
          } else if (is(quote, c)) {
            parser.state = S.SGML_DECL_QUOTED
            parser.sgmlDecl += c
          } else {
            parser.sgmlDecl += c
          }
          continue

        case S.SGML_DECL_QUOTED:
          if (c === parser.q) {
            parser.state = S.SGML_DECL
            parser.q = ''
          }
          parser.sgmlDecl += c
          continue

        case S.DOCTYPE:
          if (c === '>') {
            parser.state = S.TEXT
            emitNode(parser, 'ondoctype', parser.doctype)
            parser.doctype = true // just remember that we saw it.
          } else {
            parser.doctype += c
            if (c === '[') {
              parser.state = S.DOCTYPE_DTD
            } else if (is(quote, c)) {
              parser.state = S.DOCTYPE_QUOTED
              parser.q = c
            }
          }
          continue

        case S.DOCTYPE_QUOTED:
          parser.doctype += c
          if (c === parser.q) {
            parser.q = ''
            parser.state = S.DOCTYPE
          }
          continue

        case S.DOCTYPE_DTD:
          parser.doctype += c
          if (c === ']') {
            parser.state = S.DOCTYPE
          } else if (is(quote, c)) {
            parser.state = S.DOCTYPE_DTD_QUOTED
            parser.q = c
          }
          continue

        case S.DOCTYPE_DTD_QUOTED:
          parser.doctype += c
          if (c === parser.q) {
            parser.state = S.DOCTYPE_DTD
            parser.q = ''
          }
          continue

        case S.COMMENT:
          if (c === '-') {
            parser.state = S.COMMENT_ENDING
          } else {
            parser.comment += c
          }
          continue

        case S.COMMENT_ENDING:
          if (c === '-') {
            parser.state = S.COMMENT_ENDED
            parser.comment = textopts(parser.opt, parser.comment)
            if (parser.comment) {
              emitNode(parser, 'oncomment', parser.comment)
            }
            parser.comment = ''
          } else {
            parser.comment += '-' + c
            parser.state = S.COMMENT
          }
          continue

        case S.COMMENT_ENDED:
          if (c !== '>') {
            strictFail(parser, 'Malformed comment')
            // allow <!-- blah -- bloo --> in non-strict mode,
            // which is a comment of " blah -- bloo "
            parser.comment += '--' + c
            parser.state = S.COMMENT
          } else {
            parser.state = S.TEXT
          }
          continue

        case S.CDATA:
          if (c === ']') {
            parser.state = S.CDATA_ENDING
          } else {
            parser.cdata += c
          }
          continue

        case S.CDATA_ENDING:
          if (c === ']') {
            parser.state = S.CDATA_ENDING_2
          } else {
            parser.cdata += ']' + c
            parser.state = S.CDATA
          }
          continue

        case S.CDATA_ENDING_2:
          if (c === '>') {
            if (parser.cdata) {
              emitNode(parser, 'oncdata', parser.cdata)
            }
            emitNode(parser, 'onclosecdata')
            parser.cdata = ''
            parser.state = S.TEXT
          } else if (c === ']') {
            parser.cdata += ']'
          } else {
            parser.cdata += ']]' + c
            parser.state = S.CDATA
          }
          continue

        case S.PROC_INST:
          if (c === '?') {
            parser.state = S.PROC_INST_ENDING
          } else if (is(whitespace, c)) {
            parser.state = S.PROC_INST_BODY
          } else {
            parser.procInstName += c
          }
          continue

        case S.PROC_INST_BODY:
          if (!parser.procInstBody && is(whitespace, c)) {
            continue
          } else if (c === '?') {
            parser.state = S.PROC_INST_ENDING
          } else {
            parser.procInstBody += c
          }
          continue

        case S.PROC_INST_ENDING:
          if (c === '>') {
            emitNode(parser, 'onprocessinginstruction', {
              name: parser.procInstName,
              body: parser.procInstBody
            })
            parser.procInstName = parser.procInstBody = ''
            parser.state = S.TEXT
          } else {
            parser.procInstBody += '?' + c
            parser.state = S.PROC_INST_BODY
          }
          continue

        case S.OPEN_TAG:
          if (is(nameBody, c)) {
            parser.tagName += c
          } else {
            newTag(parser)
            if (c === '>') {
              openTag(parser)
            } else if (c === '/') {
              parser.state = S.OPEN_TAG_SLASH
            } else {
              if (not(whitespace, c)) {
                strictFail(parser, 'Invalid character in tag name')
              }
              parser.state = S.ATTRIB
            }
          }
          continue

        case S.OPEN_TAG_SLASH:
          if (c === '>') {
            openTag(parser, true)
            closeTag(parser)
          } else {
            strictFail(parser, 'Forward-slash in opening tag not followed by >')
            parser.state = S.ATTRIB
          }
          continue

        case S.ATTRIB:
          // haven't read the attribute name yet.
          if (is(whitespace, c)) {
            continue
          } else if (c === '>') {
            openTag(parser)
          } else if (c === '/') {
            parser.state = S.OPEN_TAG_SLASH
          } else if (is(nameStart, c)) {
            parser.attribName = c
            parser.attribValue = ''
            parser.state = S.ATTRIB_NAME
          } else {
            strictFail(parser, 'Invalid attribute name')
          }
          continue

        case S.ATTRIB_NAME:
          if (c === '=') {
            parser.state = S.ATTRIB_VALUE
          } else if (c === '>') {
            strictFail(parser, 'Attribute without value')
            parser.attribValue = parser.attribName
            attrib(parser)
            openTag(parser)
          } else if (is(whitespace, c)) {
            parser.state = S.ATTRIB_NAME_SAW_WHITE
          } else if (is(nameBody, c)) {
            parser.attribName += c
          } else {
            strictFail(parser, 'Invalid attribute name')
          }
          continue

        case S.ATTRIB_NAME_SAW_WHITE:
          if (c === '=') {
            parser.state = S.ATTRIB_VALUE
          } else if (is(whitespace, c)) {
            continue
          } else {
            strictFail(parser, 'Attribute without value')
            parser.tag.attributes[parser.attribName] = ''
            parser.attribValue = ''
            emitNode(parser, 'onattribute', {
              name: parser.attribName,
              value: ''
            })
            parser.attribName = ''
            if (c === '>') {
              openTag(parser)
            } else if (is(nameStart, c)) {
              parser.attribName = c
              parser.state = S.ATTRIB_NAME
            } else {
              strictFail(parser, 'Invalid attribute name')
              parser.state = S.ATTRIB
            }
          }
          continue

        case S.ATTRIB_VALUE:
          if (is(whitespace, c)) {
            continue
          } else if (is(quote, c)) {
            parser.q = c
            parser.state = S.ATTRIB_VALUE_QUOTED
          } else {
            strictFail(parser, 'Unquoted attribute value')
            parser.state = S.ATTRIB_VALUE_UNQUOTED
            parser.attribValue = c
          }
          continue

        case S.ATTRIB_VALUE_QUOTED:
          if (c !== parser.q) {
            if (c === '&') {
              parser.state = S.ATTRIB_VALUE_ENTITY_Q
            } else {
              parser.attribValue += c
            }
            continue
          }
          attrib(parser)
          parser.q = ''
          parser.state = S.ATTRIB_VALUE_CLOSED
          continue

        case S.ATTRIB_VALUE_CLOSED:
          if (is(whitespace, c)) {
            parser.state = S.ATTRIB
          } else if (c === '>') {
            openTag(parser)
          } else if (c === '/') {
            parser.state = S.OPEN_TAG_SLASH
          } else if (is(nameStart, c)) {
            strictFail(parser, 'No whitespace between attributes')
            parser.attribName = c
            parser.attribValue = ''
            parser.state = S.ATTRIB_NAME
          } else {
            strictFail(parser, 'Invalid attribute name')
          }
          continue

        case S.ATTRIB_VALUE_UNQUOTED:
          if (not(attribEnd, c)) {
            if (c === '&') {
              parser.state = S.ATTRIB_VALUE_ENTITY_U
            } else {
              parser.attribValue += c
            }
            continue
          }
          attrib(parser)
          if (c === '>') {
            openTag(parser)
          } else {
            parser.state = S.ATTRIB
          }
          continue

        case S.CLOSE_TAG:
          if (!parser.tagName) {
            if (is(whitespace, c)) {
              continue
            } else if (not(nameStart, c)) {
              if (parser.script) {
                parser.script += '</' + c
                parser.state = S.SCRIPT
              } else {
                strictFail(parser, 'Invalid tagname in closing tag.')
              }
            } else {
              parser.tagName = c
            }
          } else if (c === '>') {
            closeTag(parser)
          } else if (is(nameBody, c)) {
            parser.tagName += c
          } else if (parser.script) {
            parser.script += '</' + parser.tagName
            parser.tagName = ''
            parser.state = S.SCRIPT
          } else {
            if (not(whitespace, c)) {
              strictFail(parser, 'Invalid tagname in closing tag')
            }
            parser.state = S.CLOSE_TAG_SAW_WHITE
          }
          continue

        case S.CLOSE_TAG_SAW_WHITE:
          if (is(whitespace, c)) {
            continue
          }
          if (c === '>') {
            closeTag(parser)
          } else {
            strictFail(parser, 'Invalid characters in closing tag')
          }
          continue

        case S.TEXT_ENTITY:
        case S.ATTRIB_VALUE_ENTITY_Q:
        case S.ATTRIB_VALUE_ENTITY_U:
          var returnState
          var buffer
          switch (parser.state) {
            case S.TEXT_ENTITY:
              returnState = S.TEXT
              buffer = 'textNode'
              break

            case S.ATTRIB_VALUE_ENTITY_Q:
              returnState = S.ATTRIB_VALUE_QUOTED
              buffer = 'attribValue'
              break

            case S.ATTRIB_VALUE_ENTITY_U:
              returnState = S.ATTRIB_VALUE_UNQUOTED
              buffer = 'attribValue'
              break
          }

          if (c === ';') {
            parser[buffer] += parseEntity(parser)
            parser.entity = ''
            parser.state = returnState
          } else if (is(parser.entity.length ? entityBody : entityStart, c)) {
            parser.entity += c
          } else {
            strictFail(parser, 'Invalid character in entity name')
            parser[buffer] += '&' + parser.entity + c
            parser.entity = ''
            parser.state = returnState
          }

          continue

        default:
          throw new Error(parser, 'Unknown state: ' + parser.state)
      }
    } // while

    if (parser.position >= parser.bufferCheckPosition) {
      checkBufferLength(parser)
    }
    return parser
  }

  /*! http://mths.be/fromcodepoint v0.1.0 by @mathias */
  if (!String.fromCodePoint) {
    (function () {
      var stringFromCharCode = String.fromCharCode
      var floor = Math.floor
      var fromCodePoint = function () {
        var MAX_SIZE = 0x4000
        var codeUnits = []
        var highSurrogate
        var lowSurrogate
        var index = -1
        var length = arguments.length
        if (!length) {
          return ''
        }
        var result = ''
        while (++index < length) {
          var codePoint = Number(arguments[index])
          if (
            !isFinite(codePoint) || // `NaN`, `+Infinity`, or `-Infinity`
            codePoint < 0 || // not a valid Unicode code point
            codePoint > 0x10FFFF || // not a valid Unicode code point
            floor(codePoint) !== codePoint // not an integer
          ) {
            throw RangeError('Invalid code point: ' + codePoint)
          }
          if (codePoint <= 0xFFFF) { // BMP code point
            codeUnits.push(codePoint)
          } else { // Astral code point; split in surrogate halves
            // http://mathiasbynens.be/notes/javascript-encoding#surrogate-formulae
            codePoint -= 0x10000
            highSurrogate = (codePoint >> 10) + 0xD800
            lowSurrogate = (codePoint % 0x400) + 0xDC00
            codeUnits.push(highSurrogate, lowSurrogate)
          }
          if (index + 1 === length || codeUnits.length > MAX_SIZE) {
            result += stringFromCharCode.apply(null, codeUnits)
            codeUnits.length = 0
          }
        }
        return result
      }
      if (Object.defineProperty) {
        Object.defineProperty(String, 'fromCodePoint', {
          value: fromCodePoint,
          configurable: true,
          writable: true
        })
      } else {
        String.fromCodePoint = fromCodePoint
      }
    }())
  }
})(typeof exports === 'undefined' ? this.sax = {} : exports)

}).call(this,require("buffer").Buffer)
},{"buffer":9,"stream":31,"string_decoder":32}],39:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLAttribute, create;

  create = require('lodash/create');

  module.exports = XMLAttribute = (function() {
    function XMLAttribute(parent, name, value) {
      this.stringify = parent.stringify;
      if (name == null) {
        throw new Error("Missing attribute name of element " + parent.name);
      }
      if (value == null) {
        throw new Error("Missing attribute value for attribute " + name + " of element " + parent.name);
      }
      this.name = this.stringify.attName(name);
      this.value = this.stringify.attValue(value);
    }

    XMLAttribute.prototype.clone = function() {
      return create(XMLAttribute.prototype, this);
    };

    XMLAttribute.prototype.toString = function(options, level) {
      return ' ' + this.name + '="' + this.value + '"';
    };

    return XMLAttribute;

  })();

}).call(this);

},{"lodash/create":144}],40:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLBuilder, XMLDeclaration, XMLDocType, XMLElement, XMLStringifier;

  XMLStringifier = require('./XMLStringifier');

  XMLDeclaration = require('./XMLDeclaration');

  XMLDocType = require('./XMLDocType');

  XMLElement = require('./XMLElement');

  module.exports = XMLBuilder = (function() {
    function XMLBuilder(name, options) {
      var root, temp;
      if (name == null) {
        throw new Error("Root element needs a name");
      }
      if (options == null) {
        options = {};
      }
      this.options = options;
      this.stringify = new XMLStringifier(options);
      temp = new XMLElement(this, 'doc');
      root = temp.element(name);
      root.isRoot = true;
      root.documentObject = this;
      this.rootObject = root;
      if (!options.headless) {
        root.declaration(options);
        if ((options.pubID != null) || (options.sysID != null)) {
          root.doctype(options);
        }
      }
    }

    XMLBuilder.prototype.root = function() {
      return this.rootObject;
    };

    XMLBuilder.prototype.end = function(options) {
      return this.toString(options);
    };

    XMLBuilder.prototype.toString = function(options) {
      var indent, newline, offset, pretty, r, ref, ref1, ref2;
      pretty = (options != null ? options.pretty : void 0) || false;
      indent = (ref = options != null ? options.indent : void 0) != null ? ref : '  ';
      offset = (ref1 = options != null ? options.offset : void 0) != null ? ref1 : 0;
      newline = (ref2 = options != null ? options.newline : void 0) != null ? ref2 : '\n';
      r = '';
      if (this.xmldec != null) {
        r += this.xmldec.toString(options);
      }
      if (this.doctype != null) {
        r += this.doctype.toString(options);
      }
      r += this.rootObject.toString(options);
      if (pretty && r.slice(-newline.length) === newline) {
        r = r.slice(0, -newline.length);
      }
      return r;
    };

    return XMLBuilder;

  })();

}).call(this);

},{"./XMLDeclaration":47,"./XMLDocType":48,"./XMLElement":49,"./XMLStringifier":53}],41:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLCData, XMLNode, create,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  create = require('lodash/create');

  XMLNode = require('./XMLNode');

  module.exports = XMLCData = (function(superClass) {
    extend(XMLCData, superClass);

    function XMLCData(parent, text) {
      XMLCData.__super__.constructor.call(this, parent);
      if (text == null) {
        throw new Error("Missing CDATA text");
      }
      this.text = this.stringify.cdata(text);
    }

    XMLCData.prototype.clone = function() {
      return create(XMLCData.prototype, this);
    };

    XMLCData.prototype.toString = function(options, level) {
      var indent, newline, offset, pretty, r, ref, ref1, ref2, space;
      pretty = (options != null ? options.pretty : void 0) || false;
      indent = (ref = options != null ? options.indent : void 0) != null ? ref : '  ';
      offset = (ref1 = options != null ? options.offset : void 0) != null ? ref1 : 0;
      newline = (ref2 = options != null ? options.newline : void 0) != null ? ref2 : '\n';
      level || (level = 0);
      space = new Array(level + offset + 1).join(indent);
      r = '';
      if (pretty) {
        r += space;
      }
      r += '<![CDATA[' + this.text + ']]>';
      if (pretty) {
        r += newline;
      }
      return r;
    };

    return XMLCData;

  })(XMLNode);

}).call(this);

},{"./XMLNode":50,"lodash/create":144}],42:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLComment, XMLNode, create,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  create = require('lodash/create');

  XMLNode = require('./XMLNode');

  module.exports = XMLComment = (function(superClass) {
    extend(XMLComment, superClass);

    function XMLComment(parent, text) {
      XMLComment.__super__.constructor.call(this, parent);
      if (text == null) {
        throw new Error("Missing comment text");
      }
      this.text = this.stringify.comment(text);
    }

    XMLComment.prototype.clone = function() {
      return create(XMLComment.prototype, this);
    };

    XMLComment.prototype.toString = function(options, level) {
      var indent, newline, offset, pretty, r, ref, ref1, ref2, space;
      pretty = (options != null ? options.pretty : void 0) || false;
      indent = (ref = options != null ? options.indent : void 0) != null ? ref : '  ';
      offset = (ref1 = options != null ? options.offset : void 0) != null ? ref1 : 0;
      newline = (ref2 = options != null ? options.newline : void 0) != null ? ref2 : '\n';
      level || (level = 0);
      space = new Array(level + offset + 1).join(indent);
      r = '';
      if (pretty) {
        r += space;
      }
      r += '<!-- ' + this.text + ' -->';
      if (pretty) {
        r += newline;
      }
      return r;
    };

    return XMLComment;

  })(XMLNode);

}).call(this);

},{"./XMLNode":50,"lodash/create":144}],43:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLDTDAttList, create;

  create = require('lodash/create');

  module.exports = XMLDTDAttList = (function() {
    function XMLDTDAttList(parent, elementName, attributeName, attributeType, defaultValueType, defaultValue) {
      this.stringify = parent.stringify;
      if (elementName == null) {
        throw new Error("Missing DTD element name");
      }
      if (attributeName == null) {
        throw new Error("Missing DTD attribute name");
      }
      if (!attributeType) {
        throw new Error("Missing DTD attribute type");
      }
      if (!defaultValueType) {
        throw new Error("Missing DTD attribute default");
      }
      if (defaultValueType.indexOf('#') !== 0) {
        defaultValueType = '#' + defaultValueType;
      }
      if (!defaultValueType.match(/^(#REQUIRED|#IMPLIED|#FIXED|#DEFAULT)$/)) {
        throw new Error("Invalid default value type; expected: #REQUIRED, #IMPLIED, #FIXED or #DEFAULT");
      }
      if (defaultValue && !defaultValueType.match(/^(#FIXED|#DEFAULT)$/)) {
        throw new Error("Default value only applies to #FIXED or #DEFAULT");
      }
      this.elementName = this.stringify.eleName(elementName);
      this.attributeName = this.stringify.attName(attributeName);
      this.attributeType = this.stringify.dtdAttType(attributeType);
      this.defaultValue = this.stringify.dtdAttDefault(defaultValue);
      this.defaultValueType = defaultValueType;
    }

    XMLDTDAttList.prototype.toString = function(options, level) {
      var indent, newline, offset, pretty, r, ref, ref1, ref2, space;
      pretty = (options != null ? options.pretty : void 0) || false;
      indent = (ref = options != null ? options.indent : void 0) != null ? ref : '  ';
      offset = (ref1 = options != null ? options.offset : void 0) != null ? ref1 : 0;
      newline = (ref2 = options != null ? options.newline : void 0) != null ? ref2 : '\n';
      level || (level = 0);
      space = new Array(level + offset + 1).join(indent);
      r = '';
      if (pretty) {
        r += space;
      }
      r += '<!ATTLIST ' + this.elementName + ' ' + this.attributeName + ' ' + this.attributeType;
      if (this.defaultValueType !== '#DEFAULT') {
        r += ' ' + this.defaultValueType;
      }
      if (this.defaultValue) {
        r += ' "' + this.defaultValue + '"';
      }
      r += '>';
      if (pretty) {
        r += newline;
      }
      return r;
    };

    return XMLDTDAttList;

  })();

}).call(this);

},{"lodash/create":144}],44:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLDTDElement, create;

  create = require('lodash/create');

  module.exports = XMLDTDElement = (function() {
    function XMLDTDElement(parent, name, value) {
      this.stringify = parent.stringify;
      if (name == null) {
        throw new Error("Missing DTD element name");
      }
      if (!value) {
        value = '(#PCDATA)';
      }
      if (Array.isArray(value)) {
        value = '(' + value.join(',') + ')';
      }
      this.name = this.stringify.eleName(name);
      this.value = this.stringify.dtdElementValue(value);
    }

    XMLDTDElement.prototype.toString = function(options, level) {
      var indent, newline, offset, pretty, r, ref, ref1, ref2, space;
      pretty = (options != null ? options.pretty : void 0) || false;
      indent = (ref = options != null ? options.indent : void 0) != null ? ref : '  ';
      offset = (ref1 = options != null ? options.offset : void 0) != null ? ref1 : 0;
      newline = (ref2 = options != null ? options.newline : void 0) != null ? ref2 : '\n';
      level || (level = 0);
      space = new Array(level + offset + 1).join(indent);
      r = '';
      if (pretty) {
        r += space;
      }
      r += '<!ELEMENT ' + this.name + ' ' + this.value + '>';
      if (pretty) {
        r += newline;
      }
      return r;
    };

    return XMLDTDElement;

  })();

}).call(this);

},{"lodash/create":144}],45:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLDTDEntity, create, isObject;

  create = require('lodash/create');

  isObject = require('lodash/isObject');

  module.exports = XMLDTDEntity = (function() {
    function XMLDTDEntity(parent, pe, name, value) {
      this.stringify = parent.stringify;
      if (name == null) {
        throw new Error("Missing entity name");
      }
      if (value == null) {
        throw new Error("Missing entity value");
      }
      this.pe = !!pe;
      this.name = this.stringify.eleName(name);
      if (!isObject(value)) {
        this.value = this.stringify.dtdEntityValue(value);
      } else {
        if (!value.pubID && !value.sysID) {
          throw new Error("Public and/or system identifiers are required for an external entity");
        }
        if (value.pubID && !value.sysID) {
          throw new Error("System identifier is required for a public external entity");
        }
        if (value.pubID != null) {
          this.pubID = this.stringify.dtdPubID(value.pubID);
        }
        if (value.sysID != null) {
          this.sysID = this.stringify.dtdSysID(value.sysID);
        }
        if (value.nData != null) {
          this.nData = this.stringify.dtdNData(value.nData);
        }
        if (this.pe && this.nData) {
          throw new Error("Notation declaration is not allowed in a parameter entity");
        }
      }
    }

    XMLDTDEntity.prototype.toString = function(options, level) {
      var indent, newline, offset, pretty, r, ref, ref1, ref2, space;
      pretty = (options != null ? options.pretty : void 0) || false;
      indent = (ref = options != null ? options.indent : void 0) != null ? ref : '  ';
      offset = (ref1 = options != null ? options.offset : void 0) != null ? ref1 : 0;
      newline = (ref2 = options != null ? options.newline : void 0) != null ? ref2 : '\n';
      level || (level = 0);
      space = new Array(level + offset + 1).join(indent);
      r = '';
      if (pretty) {
        r += space;
      }
      r += '<!ENTITY';
      if (this.pe) {
        r += ' %';
      }
      r += ' ' + this.name;
      if (this.value) {
        r += ' "' + this.value + '"';
      } else {
        if (this.pubID && this.sysID) {
          r += ' PUBLIC "' + this.pubID + '" "' + this.sysID + '"';
        } else if (this.sysID) {
          r += ' SYSTEM "' + this.sysID + '"';
        }
        if (this.nData) {
          r += ' NDATA ' + this.nData;
        }
      }
      r += '>';
      if (pretty) {
        r += newline;
      }
      return r;
    };

    return XMLDTDEntity;

  })();

}).call(this);

},{"lodash/create":144,"lodash/isObject":159}],46:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLDTDNotation, create;

  create = require('lodash/create');

  module.exports = XMLDTDNotation = (function() {
    function XMLDTDNotation(parent, name, value) {
      this.stringify = parent.stringify;
      if (name == null) {
        throw new Error("Missing notation name");
      }
      if (!value.pubID && !value.sysID) {
        throw new Error("Public or system identifiers are required for an external entity");
      }
      this.name = this.stringify.eleName(name);
      if (value.pubID != null) {
        this.pubID = this.stringify.dtdPubID(value.pubID);
      }
      if (value.sysID != null) {
        this.sysID = this.stringify.dtdSysID(value.sysID);
      }
    }

    XMLDTDNotation.prototype.toString = function(options, level) {
      var indent, newline, offset, pretty, r, ref, ref1, ref2, space;
      pretty = (options != null ? options.pretty : void 0) || false;
      indent = (ref = options != null ? options.indent : void 0) != null ? ref : '  ';
      offset = (ref1 = options != null ? options.offset : void 0) != null ? ref1 : 0;
      newline = (ref2 = options != null ? options.newline : void 0) != null ? ref2 : '\n';
      level || (level = 0);
      space = new Array(level + offset + 1).join(indent);
      r = '';
      if (pretty) {
        r += space;
      }
      r += '<!NOTATION ' + this.name;
      if (this.pubID && this.sysID) {
        r += ' PUBLIC "' + this.pubID + '" "' + this.sysID + '"';
      } else if (this.pubID) {
        r += ' PUBLIC "' + this.pubID + '"';
      } else if (this.sysID) {
        r += ' SYSTEM "' + this.sysID + '"';
      }
      r += '>';
      if (pretty) {
        r += newline;
      }
      return r;
    };

    return XMLDTDNotation;

  })();

}).call(this);

},{"lodash/create":144}],47:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLDeclaration, XMLNode, create, isObject,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  create = require('lodash/create');

  isObject = require('lodash/isObject');

  XMLNode = require('./XMLNode');

  module.exports = XMLDeclaration = (function(superClass) {
    extend(XMLDeclaration, superClass);

    function XMLDeclaration(parent, version, encoding, standalone) {
      var ref;
      XMLDeclaration.__super__.constructor.call(this, parent);
      if (isObject(version)) {
        ref = version, version = ref.version, encoding = ref.encoding, standalone = ref.standalone;
      }
      if (!version) {
        version = '1.0';
      }
      this.version = this.stringify.xmlVersion(version);
      if (encoding != null) {
        this.encoding = this.stringify.xmlEncoding(encoding);
      }
      if (standalone != null) {
        this.standalone = this.stringify.xmlStandalone(standalone);
      }
    }

    XMLDeclaration.prototype.toString = function(options, level) {
      var indent, newline, offset, pretty, r, ref, ref1, ref2, space;
      pretty = (options != null ? options.pretty : void 0) || false;
      indent = (ref = options != null ? options.indent : void 0) != null ? ref : '  ';
      offset = (ref1 = options != null ? options.offset : void 0) != null ? ref1 : 0;
      newline = (ref2 = options != null ? options.newline : void 0) != null ? ref2 : '\n';
      level || (level = 0);
      space = new Array(level + offset + 1).join(indent);
      r = '';
      if (pretty) {
        r += space;
      }
      r += '<?xml';
      r += ' version="' + this.version + '"';
      if (this.encoding != null) {
        r += ' encoding="' + this.encoding + '"';
      }
      if (this.standalone != null) {
        r += ' standalone="' + this.standalone + '"';
      }
      r += '?>';
      if (pretty) {
        r += newline;
      }
      return r;
    };

    return XMLDeclaration;

  })(XMLNode);

}).call(this);

},{"./XMLNode":50,"lodash/create":144,"lodash/isObject":159}],48:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLCData, XMLComment, XMLDTDAttList, XMLDTDElement, XMLDTDEntity, XMLDTDNotation, XMLDocType, XMLProcessingInstruction, create, isObject;

  create = require('lodash/create');

  isObject = require('lodash/isObject');

  XMLCData = require('./XMLCData');

  XMLComment = require('./XMLComment');

  XMLDTDAttList = require('./XMLDTDAttList');

  XMLDTDEntity = require('./XMLDTDEntity');

  XMLDTDElement = require('./XMLDTDElement');

  XMLDTDNotation = require('./XMLDTDNotation');

  XMLProcessingInstruction = require('./XMLProcessingInstruction');

  module.exports = XMLDocType = (function() {
    function XMLDocType(parent, pubID, sysID) {
      var ref, ref1;
      this.documentObject = parent;
      this.stringify = this.documentObject.stringify;
      this.children = [];
      if (isObject(pubID)) {
        ref = pubID, pubID = ref.pubID, sysID = ref.sysID;
      }
      if (sysID == null) {
        ref1 = [pubID, sysID], sysID = ref1[0], pubID = ref1[1];
      }
      if (pubID != null) {
        this.pubID = this.stringify.dtdPubID(pubID);
      }
      if (sysID != null) {
        this.sysID = this.stringify.dtdSysID(sysID);
      }
    }

    XMLDocType.prototype.element = function(name, value) {
      var child;
      child = new XMLDTDElement(this, name, value);
      this.children.push(child);
      return this;
    };

    XMLDocType.prototype.attList = function(elementName, attributeName, attributeType, defaultValueType, defaultValue) {
      var child;
      child = new XMLDTDAttList(this, elementName, attributeName, attributeType, defaultValueType, defaultValue);
      this.children.push(child);
      return this;
    };

    XMLDocType.prototype.entity = function(name, value) {
      var child;
      child = new XMLDTDEntity(this, false, name, value);
      this.children.push(child);
      return this;
    };

    XMLDocType.prototype.pEntity = function(name, value) {
      var child;
      child = new XMLDTDEntity(this, true, name, value);
      this.children.push(child);
      return this;
    };

    XMLDocType.prototype.notation = function(name, value) {
      var child;
      child = new XMLDTDNotation(this, name, value);
      this.children.push(child);
      return this;
    };

    XMLDocType.prototype.cdata = function(value) {
      var child;
      child = new XMLCData(this, value);
      this.children.push(child);
      return this;
    };

    XMLDocType.prototype.comment = function(value) {
      var child;
      child = new XMLComment(this, value);
      this.children.push(child);
      return this;
    };

    XMLDocType.prototype.instruction = function(target, value) {
      var child;
      child = new XMLProcessingInstruction(this, target, value);
      this.children.push(child);
      return this;
    };

    XMLDocType.prototype.root = function() {
      return this.documentObject.root();
    };

    XMLDocType.prototype.document = function() {
      return this.documentObject;
    };

    XMLDocType.prototype.toString = function(options, level) {
      var child, i, indent, len, newline, offset, pretty, r, ref, ref1, ref2, ref3, space;
      pretty = (options != null ? options.pretty : void 0) || false;
      indent = (ref = options != null ? options.indent : void 0) != null ? ref : '  ';
      offset = (ref1 = options != null ? options.offset : void 0) != null ? ref1 : 0;
      newline = (ref2 = options != null ? options.newline : void 0) != null ? ref2 : '\n';
      level || (level = 0);
      space = new Array(level + offset + 1).join(indent);
      r = '';
      if (pretty) {
        r += space;
      }
      r += '<!DOCTYPE ' + this.root().name;
      if (this.pubID && this.sysID) {
        r += ' PUBLIC "' + this.pubID + '" "' + this.sysID + '"';
      } else if (this.sysID) {
        r += ' SYSTEM "' + this.sysID + '"';
      }
      if (this.children.length > 0) {
        r += ' [';
        if (pretty) {
          r += newline;
        }
        ref3 = this.children;
        for (i = 0, len = ref3.length; i < len; i++) {
          child = ref3[i];
          r += child.toString(options, level + 1);
        }
        r += ']';
      }
      r += '>';
      if (pretty) {
        r += newline;
      }
      return r;
    };

    XMLDocType.prototype.ele = function(name, value) {
      return this.element(name, value);
    };

    XMLDocType.prototype.att = function(elementName, attributeName, attributeType, defaultValueType, defaultValue) {
      return this.attList(elementName, attributeName, attributeType, defaultValueType, defaultValue);
    };

    XMLDocType.prototype.ent = function(name, value) {
      return this.entity(name, value);
    };

    XMLDocType.prototype.pent = function(name, value) {
      return this.pEntity(name, value);
    };

    XMLDocType.prototype.not = function(name, value) {
      return this.notation(name, value);
    };

    XMLDocType.prototype.dat = function(value) {
      return this.cdata(value);
    };

    XMLDocType.prototype.com = function(value) {
      return this.comment(value);
    };

    XMLDocType.prototype.ins = function(target, value) {
      return this.instruction(target, value);
    };

    XMLDocType.prototype.up = function() {
      return this.root();
    };

    XMLDocType.prototype.doc = function() {
      return this.document();
    };

    return XMLDocType;

  })();

}).call(this);

},{"./XMLCData":41,"./XMLComment":42,"./XMLDTDAttList":43,"./XMLDTDElement":44,"./XMLDTDEntity":45,"./XMLDTDNotation":46,"./XMLProcessingInstruction":51,"lodash/create":144,"lodash/isObject":159}],49:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLAttribute, XMLElement, XMLNode, XMLProcessingInstruction, create, every, isFunction, isObject,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  create = require('lodash/create');

  isObject = require('lodash/isObject');

  isFunction = require('lodash/isFunction');

  every = require('lodash/every');

  XMLNode = require('./XMLNode');

  XMLAttribute = require('./XMLAttribute');

  XMLProcessingInstruction = require('./XMLProcessingInstruction');

  module.exports = XMLElement = (function(superClass) {
    extend(XMLElement, superClass);

    function XMLElement(parent, name, attributes) {
      XMLElement.__super__.constructor.call(this, parent);
      if (name == null) {
        throw new Error("Missing element name");
      }
      this.name = this.stringify.eleName(name);
      this.children = [];
      this.instructions = [];
      this.attributes = {};
      if (attributes != null) {
        this.attribute(attributes);
      }
    }

    XMLElement.prototype.clone = function() {
      var att, attName, clonedSelf, i, len, pi, ref, ref1;
      clonedSelf = create(XMLElement.prototype, this);
      if (clonedSelf.isRoot) {
        clonedSelf.documentObject = null;
      }
      clonedSelf.attributes = {};
      ref = this.attributes;
      for (attName in ref) {
        if (!hasProp.call(ref, attName)) continue;
        att = ref[attName];
        clonedSelf.attributes[attName] = att.clone();
      }
      clonedSelf.instructions = [];
      ref1 = this.instructions;
      for (i = 0, len = ref1.length; i < len; i++) {
        pi = ref1[i];
        clonedSelf.instructions.push(pi.clone());
      }
      clonedSelf.children = [];
      this.children.forEach(function(child) {
        var clonedChild;
        clonedChild = child.clone();
        clonedChild.parent = clonedSelf;
        return clonedSelf.children.push(clonedChild);
      });
      return clonedSelf;
    };

    XMLElement.prototype.attribute = function(name, value) {
      var attName, attValue;
      if (name != null) {
        name = name.valueOf();
      }
      if (isObject(name)) {
        for (attName in name) {
          if (!hasProp.call(name, attName)) continue;
          attValue = name[attName];
          this.attribute(attName, attValue);
        }
      } else {
        if (isFunction(value)) {
          value = value.apply();
        }
        if (!this.options.skipNullAttributes || (value != null)) {
          this.attributes[name] = new XMLAttribute(this, name, value);
        }
      }
      return this;
    };

    XMLElement.prototype.removeAttribute = function(name) {
      var attName, i, len;
      if (name == null) {
        throw new Error("Missing attribute name");
      }
      name = name.valueOf();
      if (Array.isArray(name)) {
        for (i = 0, len = name.length; i < len; i++) {
          attName = name[i];
          delete this.attributes[attName];
        }
      } else {
        delete this.attributes[name];
      }
      return this;
    };

    XMLElement.prototype.instruction = function(target, value) {
      var i, insTarget, insValue, instruction, len;
      if (target != null) {
        target = target.valueOf();
      }
      if (value != null) {
        value = value.valueOf();
      }
      if (Array.isArray(target)) {
        for (i = 0, len = target.length; i < len; i++) {
          insTarget = target[i];
          this.instruction(insTarget);
        }
      } else if (isObject(target)) {
        for (insTarget in target) {
          if (!hasProp.call(target, insTarget)) continue;
          insValue = target[insTarget];
          this.instruction(insTarget, insValue);
        }
      } else {
        if (isFunction(value)) {
          value = value.apply();
        }
        instruction = new XMLProcessingInstruction(this, target, value);
        this.instructions.push(instruction);
      }
      return this;
    };

    XMLElement.prototype.toString = function(options, level) {
      var att, child, i, indent, instruction, j, len, len1, name, newline, offset, pretty, r, ref, ref1, ref2, ref3, ref4, ref5, space;
      pretty = (options != null ? options.pretty : void 0) || false;
      indent = (ref = options != null ? options.indent : void 0) != null ? ref : '  ';
      offset = (ref1 = options != null ? options.offset : void 0) != null ? ref1 : 0;
      newline = (ref2 = options != null ? options.newline : void 0) != null ? ref2 : '\n';
      level || (level = 0);
      space = new Array(level + offset + 1).join(indent);
      r = '';
      ref3 = this.instructions;
      for (i = 0, len = ref3.length; i < len; i++) {
        instruction = ref3[i];
        r += instruction.toString(options, level);
      }
      if (pretty) {
        r += space;
      }
      r += '<' + this.name;
      ref4 = this.attributes;
      for (name in ref4) {
        if (!hasProp.call(ref4, name)) continue;
        att = ref4[name];
        r += att.toString(options);
      }
      if (this.children.length === 0 || every(this.children, function(e) {
        return e.value === '';
      })) {
        r += '/>';
        if (pretty) {
          r += newline;
        }
      } else if (pretty && this.children.length === 1 && (this.children[0].value != null)) {
        r += '>';
        r += this.children[0].value;
        r += '</' + this.name + '>';
        r += newline;
      } else {
        r += '>';
        if (pretty) {
          r += newline;
        }
        ref5 = this.children;
        for (j = 0, len1 = ref5.length; j < len1; j++) {
          child = ref5[j];
          r += child.toString(options, level + 1);
        }
        if (pretty) {
          r += space;
        }
        r += '</' + this.name + '>';
        if (pretty) {
          r += newline;
        }
      }
      return r;
    };

    XMLElement.prototype.att = function(name, value) {
      return this.attribute(name, value);
    };

    XMLElement.prototype.ins = function(target, value) {
      return this.instruction(target, value);
    };

    XMLElement.prototype.a = function(name, value) {
      return this.attribute(name, value);
    };

    XMLElement.prototype.i = function(target, value) {
      return this.instruction(target, value);
    };

    return XMLElement;

  })(XMLNode);

}).call(this);

},{"./XMLAttribute":39,"./XMLNode":50,"./XMLProcessingInstruction":51,"lodash/create":144,"lodash/every":146,"lodash/isFunction":156,"lodash/isObject":159}],50:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLCData, XMLComment, XMLDeclaration, XMLDocType, XMLElement, XMLNode, XMLRaw, XMLText, isEmpty, isFunction, isObject,
    hasProp = {}.hasOwnProperty;

  isObject = require('lodash/isObject');

  isFunction = require('lodash/isFunction');

  isEmpty = require('lodash/isEmpty');

  XMLElement = null;

  XMLCData = null;

  XMLComment = null;

  XMLDeclaration = null;

  XMLDocType = null;

  XMLRaw = null;

  XMLText = null;

  module.exports = XMLNode = (function() {
    function XMLNode(parent) {
      this.parent = parent;
      this.options = this.parent.options;
      this.stringify = this.parent.stringify;
      if (XMLElement === null) {
        XMLElement = require('./XMLElement');
        XMLCData = require('./XMLCData');
        XMLComment = require('./XMLComment');
        XMLDeclaration = require('./XMLDeclaration');
        XMLDocType = require('./XMLDocType');
        XMLRaw = require('./XMLRaw');
        XMLText = require('./XMLText');
      }
    }

    XMLNode.prototype.element = function(name, attributes, text) {
      var childNode, item, j, k, key, lastChild, len, len1, ref, val;
      lastChild = null;
      if (attributes == null) {
        attributes = {};
      }
      attributes = attributes.valueOf();
      if (!isObject(attributes)) {
        ref = [attributes, text], text = ref[0], attributes = ref[1];
      }
      if (name != null) {
        name = name.valueOf();
      }
      if (Array.isArray(name)) {
        for (j = 0, len = name.length; j < len; j++) {
          item = name[j];
          lastChild = this.element(item);
        }
      } else if (isFunction(name)) {
        lastChild = this.element(name.apply());
      } else if (isObject(name)) {
        for (key in name) {
          if (!hasProp.call(name, key)) continue;
          val = name[key];
          if (isFunction(val)) {
            val = val.apply();
          }
          if ((isObject(val)) && (isEmpty(val))) {
            val = null;
          }
          if (!this.options.ignoreDecorators && this.stringify.convertAttKey && key.indexOf(this.stringify.convertAttKey) === 0) {
            lastChild = this.attribute(key.substr(this.stringify.convertAttKey.length), val);
          } else if (!this.options.ignoreDecorators && this.stringify.convertPIKey && key.indexOf(this.stringify.convertPIKey) === 0) {
            lastChild = this.instruction(key.substr(this.stringify.convertPIKey.length), val);
          } else if (!this.options.separateArrayItems && Array.isArray(val)) {
            for (k = 0, len1 = val.length; k < len1; k++) {
              item = val[k];
              childNode = {};
              childNode[key] = item;
              lastChild = this.element(childNode);
            }
          } else if (isObject(val)) {
            lastChild = this.element(key);
            lastChild.element(val);
          } else {
            lastChild = this.element(key, val);
          }
        }
      } else {
        if (!this.options.ignoreDecorators && this.stringify.convertTextKey && name.indexOf(this.stringify.convertTextKey) === 0) {
          lastChild = this.text(text);
        } else if (!this.options.ignoreDecorators && this.stringify.convertCDataKey && name.indexOf(this.stringify.convertCDataKey) === 0) {
          lastChild = this.cdata(text);
        } else if (!this.options.ignoreDecorators && this.stringify.convertCommentKey && name.indexOf(this.stringify.convertCommentKey) === 0) {
          lastChild = this.comment(text);
        } else if (!this.options.ignoreDecorators && this.stringify.convertRawKey && name.indexOf(this.stringify.convertRawKey) === 0) {
          lastChild = this.raw(text);
        } else {
          lastChild = this.node(name, attributes, text);
        }
      }
      if (lastChild == null) {
        throw new Error("Could not create any elements with: " + name);
      }
      return lastChild;
    };

    XMLNode.prototype.insertBefore = function(name, attributes, text) {
      var child, i, removed;
      if (this.isRoot) {
        throw new Error("Cannot insert elements at root level");
      }
      i = this.parent.children.indexOf(this);
      removed = this.parent.children.splice(i);
      child = this.parent.element(name, attributes, text);
      Array.prototype.push.apply(this.parent.children, removed);
      return child;
    };

    XMLNode.prototype.insertAfter = function(name, attributes, text) {
      var child, i, removed;
      if (this.isRoot) {
        throw new Error("Cannot insert elements at root level");
      }
      i = this.parent.children.indexOf(this);
      removed = this.parent.children.splice(i + 1);
      child = this.parent.element(name, attributes, text);
      Array.prototype.push.apply(this.parent.children, removed);
      return child;
    };

    XMLNode.prototype.remove = function() {
      var i, ref;
      if (this.isRoot) {
        throw new Error("Cannot remove the root element");
      }
      i = this.parent.children.indexOf(this);
      [].splice.apply(this.parent.children, [i, i - i + 1].concat(ref = [])), ref;
      return this.parent;
    };

    XMLNode.prototype.node = function(name, attributes, text) {
      var child, ref;
      if (name != null) {
        name = name.valueOf();
      }
      if (attributes == null) {
        attributes = {};
      }
      attributes = attributes.valueOf();
      if (!isObject(attributes)) {
        ref = [attributes, text], text = ref[0], attributes = ref[1];
      }
      child = new XMLElement(this, name, attributes);
      if (text != null) {
        child.text(text);
      }
      this.children.push(child);
      return child;
    };

    XMLNode.prototype.text = function(value) {
      var child;
      child = new XMLText(this, value);
      this.children.push(child);
      return this;
    };

    XMLNode.prototype.cdata = function(value) {
      var child;
      child = new XMLCData(this, value);
      this.children.push(child);
      return this;
    };

    XMLNode.prototype.comment = function(value) {
      var child;
      child = new XMLComment(this, value);
      this.children.push(child);
      return this;
    };

    XMLNode.prototype.raw = function(value) {
      var child;
      child = new XMLRaw(this, value);
      this.children.push(child);
      return this;
    };

    XMLNode.prototype.declaration = function(version, encoding, standalone) {
      var doc, xmldec;
      doc = this.document();
      xmldec = new XMLDeclaration(doc, version, encoding, standalone);
      doc.xmldec = xmldec;
      return doc.root();
    };

    XMLNode.prototype.doctype = function(pubID, sysID) {
      var doc, doctype;
      doc = this.document();
      doctype = new XMLDocType(doc, pubID, sysID);
      doc.doctype = doctype;
      return doctype;
    };

    XMLNode.prototype.up = function() {
      if (this.isRoot) {
        throw new Error("The root node has no parent. Use doc() if you need to get the document object.");
      }
      return this.parent;
    };

    XMLNode.prototype.root = function() {
      var child;
      if (this.isRoot) {
        return this;
      }
      child = this.parent;
      while (!child.isRoot) {
        child = child.parent;
      }
      return child;
    };

    XMLNode.prototype.document = function() {
      return this.root().documentObject;
    };

    XMLNode.prototype.end = function(options) {
      return this.document().toString(options);
    };

    XMLNode.prototype.prev = function() {
      var i;
      if (this.isRoot) {
        throw new Error("Root node has no siblings");
      }
      i = this.parent.children.indexOf(this);
      if (i < 1) {
        throw new Error("Already at the first node");
      }
      return this.parent.children[i - 1];
    };

    XMLNode.prototype.next = function() {
      var i;
      if (this.isRoot) {
        throw new Error("Root node has no siblings");
      }
      i = this.parent.children.indexOf(this);
      if (i === -1 || i === this.parent.children.length - 1) {
        throw new Error("Already at the last node");
      }
      return this.parent.children[i + 1];
    };

    XMLNode.prototype.importXMLBuilder = function(xmlbuilder) {
      var clonedRoot;
      clonedRoot = xmlbuilder.root().clone();
      clonedRoot.parent = this;
      clonedRoot.isRoot = false;
      this.children.push(clonedRoot);
      return this;
    };

    XMLNode.prototype.ele = function(name, attributes, text) {
      return this.element(name, attributes, text);
    };

    XMLNode.prototype.nod = function(name, attributes, text) {
      return this.node(name, attributes, text);
    };

    XMLNode.prototype.txt = function(value) {
      return this.text(value);
    };

    XMLNode.prototype.dat = function(value) {
      return this.cdata(value);
    };

    XMLNode.prototype.com = function(value) {
      return this.comment(value);
    };

    XMLNode.prototype.doc = function() {
      return this.document();
    };

    XMLNode.prototype.dec = function(version, encoding, standalone) {
      return this.declaration(version, encoding, standalone);
    };

    XMLNode.prototype.dtd = function(pubID, sysID) {
      return this.doctype(pubID, sysID);
    };

    XMLNode.prototype.e = function(name, attributes, text) {
      return this.element(name, attributes, text);
    };

    XMLNode.prototype.n = function(name, attributes, text) {
      return this.node(name, attributes, text);
    };

    XMLNode.prototype.t = function(value) {
      return this.text(value);
    };

    XMLNode.prototype.d = function(value) {
      return this.cdata(value);
    };

    XMLNode.prototype.c = function(value) {
      return this.comment(value);
    };

    XMLNode.prototype.r = function(value) {
      return this.raw(value);
    };

    XMLNode.prototype.u = function() {
      return this.up();
    };

    return XMLNode;

  })();

}).call(this);

},{"./XMLCData":41,"./XMLComment":42,"./XMLDeclaration":47,"./XMLDocType":48,"./XMLElement":49,"./XMLRaw":52,"./XMLText":54,"lodash/isEmpty":155,"lodash/isFunction":156,"lodash/isObject":159}],51:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLProcessingInstruction, create;

  create = require('lodash/create');

  module.exports = XMLProcessingInstruction = (function() {
    function XMLProcessingInstruction(parent, target, value) {
      this.stringify = parent.stringify;
      if (target == null) {
        throw new Error("Missing instruction target");
      }
      this.target = this.stringify.insTarget(target);
      if (value) {
        this.value = this.stringify.insValue(value);
      }
    }

    XMLProcessingInstruction.prototype.clone = function() {
      return create(XMLProcessingInstruction.prototype, this);
    };

    XMLProcessingInstruction.prototype.toString = function(options, level) {
      var indent, newline, offset, pretty, r, ref, ref1, ref2, space;
      pretty = (options != null ? options.pretty : void 0) || false;
      indent = (ref = options != null ? options.indent : void 0) != null ? ref : '  ';
      offset = (ref1 = options != null ? options.offset : void 0) != null ? ref1 : 0;
      newline = (ref2 = options != null ? options.newline : void 0) != null ? ref2 : '\n';
      level || (level = 0);
      space = new Array(level + offset + 1).join(indent);
      r = '';
      if (pretty) {
        r += space;
      }
      r += '<?';
      r += this.target;
      if (this.value) {
        r += ' ' + this.value;
      }
      r += '?>';
      if (pretty) {
        r += newline;
      }
      return r;
    };

    return XMLProcessingInstruction;

  })();

}).call(this);

},{"lodash/create":144}],52:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLNode, XMLRaw, create,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  create = require('lodash/create');

  XMLNode = require('./XMLNode');

  module.exports = XMLRaw = (function(superClass) {
    extend(XMLRaw, superClass);

    function XMLRaw(parent, text) {
      XMLRaw.__super__.constructor.call(this, parent);
      if (text == null) {
        throw new Error("Missing raw text");
      }
      this.value = this.stringify.raw(text);
    }

    XMLRaw.prototype.clone = function() {
      return create(XMLRaw.prototype, this);
    };

    XMLRaw.prototype.toString = function(options, level) {
      var indent, newline, offset, pretty, r, ref, ref1, ref2, space;
      pretty = (options != null ? options.pretty : void 0) || false;
      indent = (ref = options != null ? options.indent : void 0) != null ? ref : '  ';
      offset = (ref1 = options != null ? options.offset : void 0) != null ? ref1 : 0;
      newline = (ref2 = options != null ? options.newline : void 0) != null ? ref2 : '\n';
      level || (level = 0);
      space = new Array(level + offset + 1).join(indent);
      r = '';
      if (pretty) {
        r += space;
      }
      r += this.value;
      if (pretty) {
        r += newline;
      }
      return r;
    };

    return XMLRaw;

  })(XMLNode);

}).call(this);

},{"./XMLNode":50,"lodash/create":144}],53:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLStringifier,
    bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    hasProp = {}.hasOwnProperty;

  module.exports = XMLStringifier = (function() {
    function XMLStringifier(options) {
      this.assertLegalChar = bind(this.assertLegalChar, this);
      var key, ref, value;
      this.allowSurrogateChars = options != null ? options.allowSurrogateChars : void 0;
      this.noDoubleEncoding = options != null ? options.noDoubleEncoding : void 0;
      ref = (options != null ? options.stringify : void 0) || {};
      for (key in ref) {
        if (!hasProp.call(ref, key)) continue;
        value = ref[key];
        this[key] = value;
      }
    }

    XMLStringifier.prototype.eleName = function(val) {
      val = '' + val || '';
      return this.assertLegalChar(val);
    };

    XMLStringifier.prototype.eleText = function(val) {
      val = '' + val || '';
      return this.assertLegalChar(this.elEscape(val));
    };

    XMLStringifier.prototype.cdata = function(val) {
      val = '' + val || '';
      if (val.match(/]]>/)) {
        throw new Error("Invalid CDATA text: " + val);
      }
      return this.assertLegalChar(val);
    };

    XMLStringifier.prototype.comment = function(val) {
      val = '' + val || '';
      if (val.match(/--/)) {
        throw new Error("Comment text cannot contain double-hypen: " + val);
      }
      return this.assertLegalChar(val);
    };

    XMLStringifier.prototype.raw = function(val) {
      return '' + val || '';
    };

    XMLStringifier.prototype.attName = function(val) {
      return '' + val || '';
    };

    XMLStringifier.prototype.attValue = function(val) {
      val = '' + val || '';
      return this.attEscape(val);
    };

    XMLStringifier.prototype.insTarget = function(val) {
      return '' + val || '';
    };

    XMLStringifier.prototype.insValue = function(val) {
      val = '' + val || '';
      if (val.match(/\?>/)) {
        throw new Error("Invalid processing instruction value: " + val);
      }
      return val;
    };

    XMLStringifier.prototype.xmlVersion = function(val) {
      val = '' + val || '';
      if (!val.match(/1\.[0-9]+/)) {
        throw new Error("Invalid version number: " + val);
      }
      return val;
    };

    XMLStringifier.prototype.xmlEncoding = function(val) {
      val = '' + val || '';
      if (!val.match(/^[A-Za-z](?:[A-Za-z0-9._-]|-)*$/)) {
        throw new Error("Invalid encoding: " + val);
      }
      return val;
    };

    XMLStringifier.prototype.xmlStandalone = function(val) {
      if (val) {
        return "yes";
      } else {
        return "no";
      }
    };

    XMLStringifier.prototype.dtdPubID = function(val) {
      return '' + val || '';
    };

    XMLStringifier.prototype.dtdSysID = function(val) {
      return '' + val || '';
    };

    XMLStringifier.prototype.dtdElementValue = function(val) {
      return '' + val || '';
    };

    XMLStringifier.prototype.dtdAttType = function(val) {
      return '' + val || '';
    };

    XMLStringifier.prototype.dtdAttDefault = function(val) {
      if (val != null) {
        return '' + val || '';
      } else {
        return val;
      }
    };

    XMLStringifier.prototype.dtdEntityValue = function(val) {
      return '' + val || '';
    };

    XMLStringifier.prototype.dtdNData = function(val) {
      return '' + val || '';
    };

    XMLStringifier.prototype.convertAttKey = '@';

    XMLStringifier.prototype.convertPIKey = '?';

    XMLStringifier.prototype.convertTextKey = '#text';

    XMLStringifier.prototype.convertCDataKey = '#cdata';

    XMLStringifier.prototype.convertCommentKey = '#comment';

    XMLStringifier.prototype.convertRawKey = '#raw';

    XMLStringifier.prototype.assertLegalChar = function(str) {
      var chars, chr;
      if (this.allowSurrogateChars) {
        chars = /[\u0000-\u0008\u000B-\u000C\u000E-\u001F\uFFFE-\uFFFF]/;
      } else {
        chars = /[\u0000-\u0008\u000B-\u000C\u000E-\u001F\uD800-\uDFFF\uFFFE-\uFFFF]/;
      }
      chr = str.match(chars);
      if (chr) {
        throw new Error("Invalid character (" + chr + ") in string: " + str + " at index " + chr.index);
      }
      return str;
    };

    XMLStringifier.prototype.elEscape = function(str) {
      var ampregex;
      ampregex = this.noDoubleEncoding ? /(?!&\S+;)&/g : /&/g;
      return str.replace(ampregex, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r/g, '&#xD;');
    };

    XMLStringifier.prototype.attEscape = function(str) {
      var ampregex;
      ampregex = this.noDoubleEncoding ? /(?!&\S+;)&/g : /&/g;
      return str.replace(ampregex, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
    };

    return XMLStringifier;

  })();

}).call(this);

},{}],54:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLNode, XMLText, create,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  create = require('lodash/create');

  XMLNode = require('./XMLNode');

  module.exports = XMLText = (function(superClass) {
    extend(XMLText, superClass);

    function XMLText(parent, text) {
      XMLText.__super__.constructor.call(this, parent);
      if (text == null) {
        throw new Error("Missing element text");
      }
      this.value = this.stringify.eleText(text);
    }

    XMLText.prototype.clone = function() {
      return create(XMLText.prototype, this);
    };

    XMLText.prototype.toString = function(options, level) {
      var indent, newline, offset, pretty, r, ref, ref1, ref2, space;
      pretty = (options != null ? options.pretty : void 0) || false;
      indent = (ref = options != null ? options.indent : void 0) != null ? ref : '  ';
      offset = (ref1 = options != null ? options.offset : void 0) != null ? ref1 : 0;
      newline = (ref2 = options != null ? options.newline : void 0) != null ? ref2 : '\n';
      level || (level = 0);
      space = new Array(level + offset + 1).join(indent);
      r = '';
      if (pretty) {
        r += space;
      }
      r += this.value;
      if (pretty) {
        r += newline;
      }
      return r;
    };

    return XMLText;

  })(XMLNode);

}).call(this);

},{"./XMLNode":50,"lodash/create":144}],55:[function(require,module,exports){
// Generated by CoffeeScript 1.9.1
(function() {
  var XMLBuilder, assign;

  assign = require('lodash/assign');

  XMLBuilder = require('./XMLBuilder');

  module.exports.create = function(name, xmldec, doctype, options) {
    options = assign({}, xmldec, doctype, options);
    return new XMLBuilder(name, options).root();
  };

}).call(this);

},{"./XMLBuilder":40,"lodash/assign":142}],56:[function(require,module,exports){
var getNative = require('./_getNative'),
    root = require('./_root');

/* Built-in method references that are verified to be native. */
var DataView = getNative(root, 'DataView');

module.exports = DataView;

},{"./_getNative":108,"./_root":132}],57:[function(require,module,exports){
var nativeCreate = require('./_nativeCreate');

/** Used for built-in method references. */
var objectProto = Object.prototype;

/**
 * Creates a hash object.
 *
 * @private
 * @constructor
 * @returns {Object} Returns the new hash object.
 */
function Hash() {}

// Avoid inheriting from `Object.prototype` when possible.
Hash.prototype = nativeCreate ? nativeCreate(null) : objectProto;

module.exports = Hash;

},{"./_nativeCreate":131}],58:[function(require,module,exports){
var getNative = require('./_getNative'),
    root = require('./_root');

/* Built-in method references that are verified to be native. */
var Map = getNative(root, 'Map');

module.exports = Map;

},{"./_getNative":108,"./_root":132}],59:[function(require,module,exports){
var mapClear = require('./_mapClear'),
    mapDelete = require('./_mapDelete'),
    mapGet = require('./_mapGet'),
    mapHas = require('./_mapHas'),
    mapSet = require('./_mapSet');

/**
 * Creates a map cache object to store key-value pairs.
 *
 * @private
 * @constructor
 * @param {Array} [values] The values to cache.
 */
function MapCache(values) {
  var index = -1,
      length = values ? values.length : 0;

  this.clear();
  while (++index < length) {
    var entry = values[index];
    this.set(entry[0], entry[1]);
  }
}

// Add methods to `MapCache`.
MapCache.prototype.clear = mapClear;
MapCache.prototype['delete'] = mapDelete;
MapCache.prototype.get = mapGet;
MapCache.prototype.has = mapHas;
MapCache.prototype.set = mapSet;

module.exports = MapCache;

},{"./_mapClear":124,"./_mapDelete":125,"./_mapGet":126,"./_mapHas":127,"./_mapSet":128}],60:[function(require,module,exports){
var getNative = require('./_getNative'),
    root = require('./_root');

/* Built-in method references that are verified to be native. */
var Promise = getNative(root, 'Promise');

module.exports = Promise;

},{"./_getNative":108,"./_root":132}],61:[function(require,module,exports){
var getNative = require('./_getNative'),
    root = require('./_root');

/* Built-in method references that are verified to be native. */
var Set = getNative(root, 'Set');

module.exports = Set;

},{"./_getNative":108,"./_root":132}],62:[function(require,module,exports){
var stackClear = require('./_stackClear'),
    stackDelete = require('./_stackDelete'),
    stackGet = require('./_stackGet'),
    stackHas = require('./_stackHas'),
    stackSet = require('./_stackSet');

/**
 * Creates a stack cache object to store key-value pairs.
 *
 * @private
 * @constructor
 * @param {Array} [values] The values to cache.
 */
function Stack(values) {
  var index = -1,
      length = values ? values.length : 0;

  this.clear();
  while (++index < length) {
    var entry = values[index];
    this.set(entry[0], entry[1]);
  }
}

// Add methods to `Stack`.
Stack.prototype.clear = stackClear;
Stack.prototype['delete'] = stackDelete;
Stack.prototype.get = stackGet;
Stack.prototype.has = stackHas;
Stack.prototype.set = stackSet;

module.exports = Stack;

},{"./_stackClear":134,"./_stackDelete":135,"./_stackGet":136,"./_stackHas":137,"./_stackSet":138}],63:[function(require,module,exports){
var root = require('./_root');

/** Built-in value references. */
var Symbol = root.Symbol;

module.exports = Symbol;

},{"./_root":132}],64:[function(require,module,exports){
var root = require('./_root');

/** Built-in value references. */
var Uint8Array = root.Uint8Array;

module.exports = Uint8Array;

},{"./_root":132}],65:[function(require,module,exports){
var getNative = require('./_getNative'),
    root = require('./_root');

/* Built-in method references that are verified to be native. */
var WeakMap = getNative(root, 'WeakMap');

module.exports = WeakMap;

},{"./_getNative":108,"./_root":132}],66:[function(require,module,exports){
/**
 * A faster alternative to `Function#apply`, this function invokes `func`
 * with the `this` binding of `thisArg` and the arguments of `args`.
 *
 * @private
 * @param {Function} func The function to invoke.
 * @param {*} thisArg The `this` binding of `func`.
 * @param {Array} args The arguments to invoke `func` with.
 * @returns {*} Returns the result of `func`.
 */
function apply(func, thisArg, args) {
  var length = args.length;
  switch (length) {
    case 0: return func.call(thisArg);
    case 1: return func.call(thisArg, args[0]);
    case 2: return func.call(thisArg, args[0], args[1]);
    case 3: return func.call(thisArg, args[0], args[1], args[2]);
  }
  return func.apply(thisArg, args);
}

module.exports = apply;

},{}],67:[function(require,module,exports){
/**
 * A specialized version of `_.every` for arrays without support for
 * iteratee shorthands.
 *
 * @private
 * @param {Array} array The array to iterate over.
 * @param {Function} predicate The function invoked per iteration.
 * @returns {boolean} Returns `true` if all elements pass the predicate check,
 *  else `false`.
 */
function arrayEvery(array, predicate) {
  var index = -1,
      length = array.length;

  while (++index < length) {
    if (!predicate(array[index], index, array)) {
      return false;
    }
  }
  return true;
}

module.exports = arrayEvery;

},{}],68:[function(require,module,exports){
/**
 * A specialized version of `_.map` for arrays without support for iteratee
 * shorthands.
 *
 * @private
 * @param {Array} array The array to iterate over.
 * @param {Function} iteratee The function invoked per iteration.
 * @returns {Array} Returns the new mapped array.
 */
function arrayMap(array, iteratee) {
  var index = -1,
      length = array.length,
      result = Array(length);

  while (++index < length) {
    result[index] = iteratee(array[index], index, array);
  }
  return result;
}

module.exports = arrayMap;

},{}],69:[function(require,module,exports){
/**
 * A specialized version of `_.some` for arrays without support for iteratee
 * shorthands.
 *
 * @private
 * @param {Array} array The array to iterate over.
 * @param {Function} predicate The function invoked per iteration.
 * @returns {boolean} Returns `true` if any element passes the predicate check,
 *  else `false`.
 */
function arraySome(array, predicate) {
  var index = -1,
      length = array.length;

  while (++index < length) {
    if (predicate(array[index], index, array)) {
      return true;
    }
  }
  return false;
}

module.exports = arraySome;

},{}],70:[function(require,module,exports){
var eq = require('./eq');

/** Used for built-in method references. */
var objectProto = Object.prototype;

/** Used to check objects for own properties. */
var hasOwnProperty = objectProto.hasOwnProperty;

/**
 * Assigns `value` to `key` of `object` if the existing value is not equivalent
 * using [`SameValueZero`](http://ecma-international.org/ecma-262/6.0/#sec-samevaluezero)
 * for equality comparisons.
 *
 * @private
 * @param {Object} object The object to modify.
 * @param {string} key The key of the property to assign.
 * @param {*} value The value to assign.
 */
function assignValue(object, key, value) {
  var objValue = object[key];
  if (!(hasOwnProperty.call(object, key) && eq(objValue, value)) ||
      (value === undefined && !(key in object))) {
    object[key] = value;
  }
}

module.exports = assignValue;

},{"./eq":145}],71:[function(require,module,exports){
var assocIndexOf = require('./_assocIndexOf');

/** Used for built-in method references. */
var arrayProto = Array.prototype;

/** Built-in value references. */
var splice = arrayProto.splice;

/**
 * Removes `key` and its value from the associative array.
 *
 * @private
 * @param {Array} array The array to modify.
 * @param {string} key The key of the value to remove.
 * @returns {boolean} Returns `true` if the entry was removed, else `false`.
 */
function assocDelete(array, key) {
  var index = assocIndexOf(array, key);
  if (index < 0) {
    return false;
  }
  var lastIndex = array.length - 1;
  if (index == lastIndex) {
    array.pop();
  } else {
    splice.call(array, index, 1);
  }
  return true;
}

module.exports = assocDelete;

},{"./_assocIndexOf":74}],72:[function(require,module,exports){
var assocIndexOf = require('./_assocIndexOf');

/**
 * Gets the associative array value for `key`.
 *
 * @private
 * @param {Array} array The array to query.
 * @param {string} key The key of the value to get.
 * @returns {*} Returns the entry value.
 */
function assocGet(array, key) {
  var index = assocIndexOf(array, key);
  return index < 0 ? undefined : array[index][1];
}

module.exports = assocGet;

},{"./_assocIndexOf":74}],73:[function(require,module,exports){
var assocIndexOf = require('./_assocIndexOf');

/**
 * Checks if an associative array value for `key` exists.
 *
 * @private
 * @param {Array} array The array to query.
 * @param {string} key The key of the entry to check.
 * @returns {boolean} Returns `true` if an entry for `key` exists, else `false`.
 */
function assocHas(array, key) {
  return assocIndexOf(array, key) > -1;
}

module.exports = assocHas;

},{"./_assocIndexOf":74}],74:[function(require,module,exports){
var eq = require('./eq');

/**
 * Gets the index at which the `key` is found in `array` of key-value pairs.
 *
 * @private
 * @param {Array} array The array to search.
 * @param {*} key The key to search for.
 * @returns {number} Returns the index of the matched value, else `-1`.
 */
function assocIndexOf(array, key) {
  var length = array.length;
  while (length--) {
    if (eq(array[length][0], key)) {
      return length;
    }
  }
  return -1;
}

module.exports = assocIndexOf;

},{"./eq":145}],75:[function(require,module,exports){
var assocIndexOf = require('./_assocIndexOf');

/**
 * Sets the associative array `key` to `value`.
 *
 * @private
 * @param {Array} array The array to modify.
 * @param {string} key The key of the value to set.
 * @param {*} value The value to set.
 */
function assocSet(array, key, value) {
  var index = assocIndexOf(array, key);
  if (index < 0) {
    array.push([key, value]);
  } else {
    array[index][1] = value;
  }
}

module.exports = assocSet;

},{"./_assocIndexOf":74}],76:[function(require,module,exports){
var copyObject = require('./_copyObject'),
    keys = require('./keys');

/**
 * The base implementation of `_.assign` without support for multiple sources
 * or `customizer` functions.
 *
 * @private
 * @param {Object} object The destination object.
 * @param {Object} source The source object.
 * @returns {Object} Returns `object`.
 */
function baseAssign(object, source) {
  return object && copyObject(source, keys(source), object);
}

module.exports = baseAssign;

},{"./_copyObject":99,"./keys":164}],77:[function(require,module,exports){
var isObject = require('./isObject');

/** Built-in value references. */
var objectCreate = Object.create;

/**
 * The base implementation of `_.create` without support for assigning
 * properties to the created object.
 *
 * @private
 * @param {Object} prototype The object to inherit from.
 * @returns {Object} Returns the new object.
 */
function baseCreate(proto) {
  return isObject(proto) ? objectCreate(proto) : {};
}

module.exports = baseCreate;

},{"./isObject":159}],78:[function(require,module,exports){
var baseForOwn = require('./_baseForOwn'),
    createBaseEach = require('./_createBaseEach');

/**
 * The base implementation of `_.forEach` without support for iteratee shorthands.
 *
 * @private
 * @param {Array|Object} collection The collection to iterate over.
 * @param {Function} iteratee The function invoked per iteration.
 * @returns {Array|Object} Returns `collection`.
 */
var baseEach = createBaseEach(baseForOwn);

module.exports = baseEach;

},{"./_baseForOwn":81,"./_createBaseEach":101}],79:[function(require,module,exports){
var baseEach = require('./_baseEach');

/**
 * The base implementation of `_.every` without support for iteratee shorthands.
 *
 * @private
 * @param {Array|Object} collection The collection to iterate over.
 * @param {Function} predicate The function invoked per iteration.
 * @returns {boolean} Returns `true` if all elements pass the predicate check,
 *  else `false`
 */
function baseEvery(collection, predicate) {
  var result = true;
  baseEach(collection, function(value, index, collection) {
    result = !!predicate(value, index, collection);
    return result;
  });
  return result;
}

module.exports = baseEvery;

},{"./_baseEach":78}],80:[function(require,module,exports){
var createBaseFor = require('./_createBaseFor');

/**
 * The base implementation of `baseForOwn` which iterates over `object`
 * properties returned by `keysFunc` and invokes `iteratee` for each property.
 * Iteratee functions may exit iteration early by explicitly returning `false`.
 *
 * @private
 * @param {Object} object The object to iterate over.
 * @param {Function} iteratee The function invoked per iteration.
 * @param {Function} keysFunc The function to get the keys of `object`.
 * @returns {Object} Returns `object`.
 */
var baseFor = createBaseFor();

module.exports = baseFor;

},{"./_createBaseFor":102}],81:[function(require,module,exports){
var baseFor = require('./_baseFor'),
    keys = require('./keys');

/**
 * The base implementation of `_.forOwn` without support for iteratee shorthands.
 *
 * @private
 * @param {Object} object The object to iterate over.
 * @param {Function} iteratee The function invoked per iteration.
 * @returns {Object} Returns `object`.
 */
function baseForOwn(object, iteratee) {
  return object && baseFor(object, iteratee, keys);
}

module.exports = baseForOwn;

},{"./_baseFor":80,"./keys":164}],82:[function(require,module,exports){
var castPath = require('./_castPath'),
    isKey = require('./_isKey'),
    toKey = require('./_toKey');

/**
 * The base implementation of `_.get` without support for default values.
 *
 * @private
 * @param {Object} object The object to query.
 * @param {Array|string} path The path of the property to get.
 * @returns {*} Returns the resolved value.
 */
function baseGet(object, path) {
  path = isKey(path, object) ? [path] : castPath(path);

  var index = 0,
      length = path.length;

  while (object != null && index < length) {
    object = object[toKey(path[index++])];
  }
  return (index && index == length) ? object : undefined;
}

module.exports = baseGet;

},{"./_castPath":97,"./_isKey":120,"./_toKey":140}],83:[function(require,module,exports){
var getPrototype = require('./_getPrototype');

/** Used for built-in method references. */
var objectProto = Object.prototype;

/** Used to check objects for own properties. */
var hasOwnProperty = objectProto.hasOwnProperty;

/**
 * The base implementation of `_.has` without support for deep paths.
 *
 * @private
 * @param {Object} object The object to query.
 * @param {Array|string} key The key to check.
 * @returns {boolean} Returns `true` if `key` exists, else `false`.
 */
function baseHas(object, key) {
  // Avoid a bug in IE 10-11 where objects with a [[Prototype]] of `null`,
  // that are composed entirely of index properties, return `false` for
  // `hasOwnProperty` checks of them.
  return hasOwnProperty.call(object, key) ||
    (typeof object == 'object' && key in object && getPrototype(object) === null);
}

module.exports = baseHas;

},{"./_getPrototype":109}],84:[function(require,module,exports){
/**
 * The base implementation of `_.hasIn` without support for deep paths.
 *
 * @private
 * @param {Object} object The object to query.
 * @param {Array|string} key The key to check.
 * @returns {boolean} Returns `true` if `key` exists, else `false`.
 */
function baseHasIn(object, key) {
  return key in Object(object);
}

module.exports = baseHasIn;

},{}],85:[function(require,module,exports){
var baseIsEqualDeep = require('./_baseIsEqualDeep'),
    isObject = require('./isObject'),
    isObjectLike = require('./isObjectLike');

/**
 * The base implementation of `_.isEqual` which supports partial comparisons
 * and tracks traversed objects.
 *
 * @private
 * @param {*} value The value to compare.
 * @param {*} other The other value to compare.
 * @param {Function} [customizer] The function to customize comparisons.
 * @param {boolean} [bitmask] The bitmask of comparison flags.
 *  The bitmask may be composed of the following flags:
 *     1 - Unordered comparison
 *     2 - Partial comparison
 * @param {Object} [stack] Tracks traversed `value` and `other` objects.
 * @returns {boolean} Returns `true` if the values are equivalent, else `false`.
 */
function baseIsEqual(value, other, customizer, bitmask, stack) {
  if (value === other) {
    return true;
  }
  if (value == null || other == null || (!isObject(value) && !isObjectLike(other))) {
    return value !== value && other !== other;
  }
  return baseIsEqualDeep(value, other, baseIsEqual, customizer, bitmask, stack);
}

module.exports = baseIsEqual;

},{"./_baseIsEqualDeep":86,"./isObject":159,"./isObjectLike":160}],86:[function(require,module,exports){
var Stack = require('./_Stack'),
    equalArrays = require('./_equalArrays'),
    equalByTag = require('./_equalByTag'),
    equalObjects = require('./_equalObjects'),
    getTag = require('./_getTag'),
    isArray = require('./isArray'),
    isHostObject = require('./_isHostObject'),
    isTypedArray = require('./isTypedArray');

/** Used to compose bitmasks for comparison styles. */
var PARTIAL_COMPARE_FLAG = 2;

/** `Object#toString` result references. */
var argsTag = '[object Arguments]',
    arrayTag = '[object Array]',
    objectTag = '[object Object]';

/** Used for built-in method references. */
var objectProto = Object.prototype;

/** Used to check objects for own properties. */
var hasOwnProperty = objectProto.hasOwnProperty;

/**
 * A specialized version of `baseIsEqual` for arrays and objects which performs
 * deep comparisons and tracks traversed objects enabling objects with circular
 * references to be compared.
 *
 * @private
 * @param {Object} object The object to compare.
 * @param {Object} other The other object to compare.
 * @param {Function} equalFunc The function to determine equivalents of values.
 * @param {Function} [customizer] The function to customize comparisons.
 * @param {number} [bitmask] The bitmask of comparison flags. See `baseIsEqual`
 *  for more details.
 * @param {Object} [stack] Tracks traversed `object` and `other` objects.
 * @returns {boolean} Returns `true` if the objects are equivalent, else `false`.
 */
function baseIsEqualDeep(object, other, equalFunc, customizer, bitmask, stack) {
  var objIsArr = isArray(object),
      othIsArr = isArray(other),
      objTag = arrayTag,
      othTag = arrayTag;

  if (!objIsArr) {
    objTag = getTag(object);
    objTag = objTag == argsTag ? objectTag : objTag;
  }
  if (!othIsArr) {
    othTag = getTag(other);
    othTag = othTag == argsTag ? objectTag : othTag;
  }
  var objIsObj = objTag == objectTag && !isHostObject(object),
      othIsObj = othTag == objectTag && !isHostObject(other),
      isSameTag = objTag == othTag;

  if (isSameTag && !objIsObj) {
    stack || (stack = new Stack);
    return (objIsArr || isTypedArray(object))
      ? equalArrays(object, other, equalFunc, customizer, bitmask, stack)
      : equalByTag(object, other, objTag, equalFunc, customizer, bitmask, stack);
  }
  if (!(bitmask & PARTIAL_COMPARE_FLAG)) {
    var objIsWrapped = objIsObj && hasOwnProperty.call(object, '__wrapped__'),
        othIsWrapped = othIsObj && hasOwnProperty.call(other, '__wrapped__');

    if (objIsWrapped || othIsWrapped) {
      var objUnwrapped = objIsWrapped ? object.value() : object,
          othUnwrapped = othIsWrapped ? other.value() : other;

      stack || (stack = new Stack);
      return equalFunc(objUnwrapped, othUnwrapped, customizer, bitmask, stack);
    }
  }
  if (!isSameTag) {
    return false;
  }
  stack || (stack = new Stack);
  return equalObjects(object, other, equalFunc, customizer, bitmask, stack);
}

module.exports = baseIsEqualDeep;

},{"./_Stack":62,"./_equalArrays":103,"./_equalByTag":104,"./_equalObjects":105,"./_getTag":110,"./_isHostObject":117,"./isArray":151,"./isTypedArray":163}],87:[function(require,module,exports){
var Stack = require('./_Stack'),
    baseIsEqual = require('./_baseIsEqual');

/** Used to compose bitmasks for comparison styles. */
var UNORDERED_COMPARE_FLAG = 1,
    PARTIAL_COMPARE_FLAG = 2;

/**
 * The base implementation of `_.isMatch` without support for iteratee shorthands.
 *
 * @private
 * @param {Object} object The object to inspect.
 * @param {Object} source The object of property values to match.
 * @param {Array} matchData The property names, values, and compare flags to match.
 * @param {Function} [customizer] The function to customize comparisons.
 * @returns {boolean} Returns `true` if `object` is a match, else `false`.
 */
function baseIsMatch(object, source, matchData, customizer) {
  var index = matchData.length,
      length = index,
      noCustomizer = !customizer;

  if (object == null) {
    return !length;
  }
  object = Object(object);
  while (index--) {
    var data = matchData[index];
    if ((noCustomizer && data[2])
          ? data[1] !== object[data[0]]
          : !(data[0] in object)
        ) {
      return false;
    }
  }
  while (++index < length) {
    data = matchData[index];
    var key = data[0],
        objValue = object[key],
        srcValue = data[1];

    if (noCustomizer && data[2]) {
      if (objValue === undefined && !(key in object)) {
        return false;
      }
    } else {
      var stack = new Stack;
      if (customizer) {
        var result = customizer(objValue, srcValue, key, object, source, stack);
      }
      if (!(result === undefined
            ? baseIsEqual(srcValue, objValue, customizer, UNORDERED_COMPARE_FLAG | PARTIAL_COMPARE_FLAG, stack)
            : result
          )) {
        return false;
      }
    }
  }
  return true;
}

module.exports = baseIsMatch;

},{"./_Stack":62,"./_baseIsEqual":85}],88:[function(require,module,exports){
var baseMatches = require('./_baseMatches'),
    baseMatchesProperty = require('./_baseMatchesProperty'),
    identity = require('./identity'),
    isArray = require('./isArray'),
    property = require('./property');

/**
 * The base implementation of `_.iteratee`.
 *
 * @private
 * @param {*} [value=_.identity] The value to convert to an iteratee.
 * @returns {Function} Returns the iteratee.
 */
function baseIteratee(value) {
  // Don't store the `typeof` result in a variable to avoid a JIT bug in Safari 9.
  // See https://bugs.webkit.org/show_bug.cgi?id=156034 for more details.
  if (typeof value == 'function') {
    return value;
  }
  if (value == null) {
    return identity;
  }
  if (typeof value == 'object') {
    return isArray(value)
      ? baseMatchesProperty(value[0], value[1])
      : baseMatches(value);
  }
  return property(value);
}

module.exports = baseIteratee;

},{"./_baseMatches":90,"./_baseMatchesProperty":91,"./identity":149,"./isArray":151,"./property":166}],89:[function(require,module,exports){
/* Built-in method references for those with the same name as other `lodash` methods. */
var nativeKeys = Object.keys;

/**
 * The base implementation of `_.keys` which doesn't skip the constructor
 * property of prototypes or treat sparse arrays as dense.
 *
 * @private
 * @param {Object} object The object to query.
 * @returns {Array} Returns the array of property names.
 */
function baseKeys(object) {
  return nativeKeys(Object(object));
}

module.exports = baseKeys;

},{}],90:[function(require,module,exports){
var baseIsMatch = require('./_baseIsMatch'),
    getMatchData = require('./_getMatchData'),
    matchesStrictComparable = require('./_matchesStrictComparable');

/**
 * The base implementation of `_.matches` which doesn't clone `source`.
 *
 * @private
 * @param {Object} source The object of property values to match.
 * @returns {Function} Returns the new function.
 */
function baseMatches(source) {
  var matchData = getMatchData(source);
  if (matchData.length == 1 && matchData[0][2]) {
    return matchesStrictComparable(matchData[0][0], matchData[0][1]);
  }
  return function(object) {
    return object === source || baseIsMatch(object, source, matchData);
  };
}

module.exports = baseMatches;

},{"./_baseIsMatch":87,"./_getMatchData":107,"./_matchesStrictComparable":130}],91:[function(require,module,exports){
var baseIsEqual = require('./_baseIsEqual'),
    get = require('./get'),
    hasIn = require('./hasIn'),
    isKey = require('./_isKey'),
    isStrictComparable = require('./_isStrictComparable'),
    matchesStrictComparable = require('./_matchesStrictComparable'),
    toKey = require('./_toKey');

/** Used to compose bitmasks for comparison styles. */
var UNORDERED_COMPARE_FLAG = 1,
    PARTIAL_COMPARE_FLAG = 2;

/**
 * The base implementation of `_.matchesProperty` which doesn't clone `srcValue`.
 *
 * @private
 * @param {string} path The path of the property to get.
 * @param {*} srcValue The value to match.
 * @returns {Function} Returns the new function.
 */
function baseMatchesProperty(path, srcValue) {
  if (isKey(path) && isStrictComparable(srcValue)) {
    return matchesStrictComparable(toKey(path), srcValue);
  }
  return function(object) {
    var objValue = get(object, path);
    return (objValue === undefined && objValue === srcValue)
      ? hasIn(object, path)
      : baseIsEqual(srcValue, objValue, undefined, UNORDERED_COMPARE_FLAG | PARTIAL_COMPARE_FLAG);
  };
}

module.exports = baseMatchesProperty;

},{"./_baseIsEqual":85,"./_isKey":120,"./_isStrictComparable":123,"./_matchesStrictComparable":130,"./_toKey":140,"./get":147,"./hasIn":148}],92:[function(require,module,exports){
/**
 * The base implementation of `_.property` without support for deep paths.
 *
 * @private
 * @param {string} key The key of the property to get.
 * @returns {Function} Returns the new function.
 */
function baseProperty(key) {
  return function(object) {
    return object == null ? undefined : object[key];
  };
}

module.exports = baseProperty;

},{}],93:[function(require,module,exports){
var baseGet = require('./_baseGet');

/**
 * A specialized version of `baseProperty` which supports deep paths.
 *
 * @private
 * @param {Array|string} path The path of the property to get.
 * @returns {Function} Returns the new function.
 */
function basePropertyDeep(path) {
  return function(object) {
    return baseGet(object, path);
  };
}

module.exports = basePropertyDeep;

},{"./_baseGet":82}],94:[function(require,module,exports){
/**
 * The base implementation of `_.times` without support for iteratee shorthands
 * or max array length checks.
 *
 * @private
 * @param {number} n The number of times to invoke `iteratee`.
 * @param {Function} iteratee The function invoked per iteration.
 * @returns {Array} Returns the array of results.
 */
function baseTimes(n, iteratee) {
  var index = -1,
      result = Array(n);

  while (++index < n) {
    result[index] = iteratee(index);
  }
  return result;
}

module.exports = baseTimes;

},{}],95:[function(require,module,exports){
var arrayMap = require('./_arrayMap');

/**
 * The base implementation of `_.toPairs` and `_.toPairsIn` which creates an array
 * of key-value pairs for `object` corresponding to the property names of `props`.
 *
 * @private
 * @param {Object} object The object to query.
 * @param {Array} props The property names to get values for.
 * @returns {Object} Returns the new array of key-value pairs.
 */
function baseToPairs(object, props) {
  return arrayMap(props, function(key) {
    return [key, object[key]];
  });
}

module.exports = baseToPairs;

},{"./_arrayMap":68}],96:[function(require,module,exports){
var Symbol = require('./_Symbol'),
    isSymbol = require('./isSymbol');

/** Used as references for various `Number` constants. */
var INFINITY = 1 / 0;

/** Used to convert symbols to primitives and strings. */
var symbolProto = Symbol ? Symbol.prototype : undefined,
    symbolToString = symbolProto ? symbolProto.toString : undefined;

/**
 * The base implementation of `_.toString` which doesn't convert nullish
 * values to empty strings.
 *
 * @private
 * @param {*} value The value to process.
 * @returns {string} Returns the string.
 */
function baseToString(value) {
  // Exit early for strings to avoid a performance hit in some environments.
  if (typeof value == 'string') {
    return value;
  }
  if (isSymbol(value)) {
    return symbolToString ? symbolToString.call(value) : '';
  }
  var result = (value + '');
  return (result == '0' && (1 / value) == -INFINITY) ? '-0' : result;
}

module.exports = baseToString;

},{"./_Symbol":63,"./isSymbol":162}],97:[function(require,module,exports){
var isArray = require('./isArray'),
    stringToPath = require('./_stringToPath');

/**
 * Casts `value` to a path array if it's not one.
 *
 * @private
 * @param {*} value The value to inspect.
 * @returns {Array} Returns the cast property path array.
 */
function castPath(value) {
  return isArray(value) ? value : stringToPath(value);
}

module.exports = castPath;

},{"./_stringToPath":139,"./isArray":151}],98:[function(require,module,exports){
/**
 * Checks if `value` is a global object.
 *
 * @private
 * @param {*} value The value to check.
 * @returns {null|Object} Returns `value` if it's a global object, else `null`.
 */
function checkGlobal(value) {
  return (value && value.Object === Object) ? value : null;
}

module.exports = checkGlobal;

},{}],99:[function(require,module,exports){
var assignValue = require('./_assignValue');

/**
 * Copies properties of `source` to `object`.
 *
 * @private
 * @param {Object} source The object to copy properties from.
 * @param {Array} props The property identifiers to copy.
 * @param {Object} [object={}] The object to copy properties to.
 * @param {Function} [customizer] The function to customize copied values.
 * @returns {Object} Returns `object`.
 */
function copyObject(source, props, object, customizer) {
  object || (object = {});

  var index = -1,
      length = props.length;

  while (++index < length) {
    var key = props[index];

    var newValue = customizer
      ? customizer(object[key], source[key], key, object, source)
      : source[key];

    assignValue(object, key, newValue);
  }
  return object;
}

module.exports = copyObject;

},{"./_assignValue":70}],100:[function(require,module,exports){
var isIterateeCall = require('./_isIterateeCall'),
    rest = require('./rest');

/**
 * Creates a function like `_.assign`.
 *
 * @private
 * @param {Function} assigner The function to assign values.
 * @returns {Function} Returns the new assigner function.
 */
function createAssigner(assigner) {
  return rest(function(object, sources) {
    var index = -1,
        length = sources.length,
        customizer = length > 1 ? sources[length - 1] : undefined,
        guard = length > 2 ? sources[2] : undefined;

    customizer = typeof customizer == 'function'
      ? (length--, customizer)
      : undefined;

    if (guard && isIterateeCall(sources[0], sources[1], guard)) {
      customizer = length < 3 ? undefined : customizer;
      length = 1;
    }
    object = Object(object);
    while (++index < length) {
      var source = sources[index];
      if (source) {
        assigner(object, source, index, customizer);
      }
    }
    return object;
  });
}

module.exports = createAssigner;

},{"./_isIterateeCall":119,"./rest":167}],101:[function(require,module,exports){
var isArrayLike = require('./isArrayLike');

/**
 * Creates a `baseEach` or `baseEachRight` function.
 *
 * @private
 * @param {Function} eachFunc The function to iterate over a collection.
 * @param {boolean} [fromRight] Specify iterating from right to left.
 * @returns {Function} Returns the new base function.
 */
function createBaseEach(eachFunc, fromRight) {
  return function(collection, iteratee) {
    if (collection == null) {
      return collection;
    }
    if (!isArrayLike(collection)) {
      return eachFunc(collection, iteratee);
    }
    var length = collection.length,
        index = fromRight ? length : -1,
        iterable = Object(collection);

    while ((fromRight ? index-- : ++index < length)) {
      if (iteratee(iterable[index], index, iterable) === false) {
        break;
      }
    }
    return collection;
  };
}

module.exports = createBaseEach;

},{"./isArrayLike":152}],102:[function(require,module,exports){
/**
 * Creates a base function for methods like `_.forIn` and `_.forOwn`.
 *
 * @private
 * @param {boolean} [fromRight] Specify iterating from right to left.
 * @returns {Function} Returns the new base function.
 */
function createBaseFor(fromRight) {
  return function(object, iteratee, keysFunc) {
    var index = -1,
        iterable = Object(object),
        props = keysFunc(object),
        length = props.length;

    while (length--) {
      var key = props[fromRight ? length : ++index];
      if (iteratee(iterable[key], key, iterable) === false) {
        break;
      }
    }
    return object;
  };
}

module.exports = createBaseFor;

},{}],103:[function(require,module,exports){
var arraySome = require('./_arraySome');

/** Used to compose bitmasks for comparison styles. */
var UNORDERED_COMPARE_FLAG = 1,
    PARTIAL_COMPARE_FLAG = 2;

/**
 * A specialized version of `baseIsEqualDeep` for arrays with support for
 * partial deep comparisons.
 *
 * @private
 * @param {Array} array The array to compare.
 * @param {Array} other The other array to compare.
 * @param {Function} equalFunc The function to determine equivalents of values.
 * @param {Function} customizer The function to customize comparisons.
 * @param {number} bitmask The bitmask of comparison flags. See `baseIsEqual`
 *  for more details.
 * @param {Object} stack Tracks traversed `array` and `other` objects.
 * @returns {boolean} Returns `true` if the arrays are equivalent, else `false`.
 */
function equalArrays(array, other, equalFunc, customizer, bitmask, stack) {
  var index = -1,
      isPartial = bitmask & PARTIAL_COMPARE_FLAG,
      isUnordered = bitmask & UNORDERED_COMPARE_FLAG,
      arrLength = array.length,
      othLength = other.length;

  if (arrLength != othLength && !(isPartial && othLength > arrLength)) {
    return false;
  }
  // Assume cyclic values are equal.
  var stacked = stack.get(array);
  if (stacked) {
    return stacked == other;
  }
  var result = true;
  stack.set(array, other);

  // Ignore non-index properties.
  while (++index < arrLength) {
    var arrValue = array[index],
        othValue = other[index];

    if (customizer) {
      var compared = isPartial
        ? customizer(othValue, arrValue, index, other, array, stack)
        : customizer(arrValue, othValue, index, array, other, stack);
    }
    if (compared !== undefined) {
      if (compared) {
        continue;
      }
      result = false;
      break;
    }
    // Recursively compare arrays (susceptible to call stack limits).
    if (isUnordered) {
      if (!arraySome(other, function(othValue) {
            return arrValue === othValue ||
              equalFunc(arrValue, othValue, customizer, bitmask, stack);
          })) {
        result = false;
        break;
      }
    } else if (!(
          arrValue === othValue ||
            equalFunc(arrValue, othValue, customizer, bitmask, stack)
        )) {
      result = false;
      break;
    }
  }
  stack['delete'](array);
  return result;
}

module.exports = equalArrays;

},{"./_arraySome":69}],104:[function(require,module,exports){
var Symbol = require('./_Symbol'),
    Uint8Array = require('./_Uint8Array'),
    equalArrays = require('./_equalArrays'),
    mapToArray = require('./_mapToArray'),
    setToArray = require('./_setToArray');

/** Used to compose bitmasks for comparison styles. */
var UNORDERED_COMPARE_FLAG = 1,
    PARTIAL_COMPARE_FLAG = 2;

/** `Object#toString` result references. */
var boolTag = '[object Boolean]',
    dateTag = '[object Date]',
    errorTag = '[object Error]',
    mapTag = '[object Map]',
    numberTag = '[object Number]',
    regexpTag = '[object RegExp]',
    setTag = '[object Set]',
    stringTag = '[object String]',
    symbolTag = '[object Symbol]';

var arrayBufferTag = '[object ArrayBuffer]',
    dataViewTag = '[object DataView]';

/** Used to convert symbols to primitives and strings. */
var symbolProto = Symbol ? Symbol.prototype : undefined,
    symbolValueOf = symbolProto ? symbolProto.valueOf : undefined;

/**
 * A specialized version of `baseIsEqualDeep` for comparing objects of
 * the same `toStringTag`.
 *
 * **Note:** This function only supports comparing values with tags of
 * `Boolean`, `Date`, `Error`, `Number`, `RegExp`, or `String`.
 *
 * @private
 * @param {Object} object The object to compare.
 * @param {Object} other The other object to compare.
 * @param {string} tag The `toStringTag` of the objects to compare.
 * @param {Function} equalFunc The function to determine equivalents of values.
 * @param {Function} customizer The function to customize comparisons.
 * @param {number} bitmask The bitmask of comparison flags. See `baseIsEqual`
 *  for more details.
 * @param {Object} stack Tracks traversed `object` and `other` objects.
 * @returns {boolean} Returns `true` if the objects are equivalent, else `false`.
 */
function equalByTag(object, other, tag, equalFunc, customizer, bitmask, stack) {
  switch (tag) {
    case dataViewTag:
      if ((object.byteLength != other.byteLength) ||
          (object.byteOffset != other.byteOffset)) {
        return false;
      }
      object = object.buffer;
      other = other.buffer;

    case arrayBufferTag:
      if ((object.byteLength != other.byteLength) ||
          !equalFunc(new Uint8Array(object), new Uint8Array(other))) {
        return false;
      }
      return true;

    case boolTag:
    case dateTag:
      // Coerce dates and booleans to numbers, dates to milliseconds and
      // booleans to `1` or `0` treating invalid dates coerced to `NaN` as
      // not equal.
      return +object == +other;

    case errorTag:
      return object.name == other.name && object.message == other.message;

    case numberTag:
      // Treat `NaN` vs. `NaN` as equal.
      return (object != +object) ? other != +other : object == +other;

    case regexpTag:
    case stringTag:
      // Coerce regexes to strings and treat strings, primitives and objects,
      // as equal. See http://www.ecma-international.org/ecma-262/6.0/#sec-regexp.prototype.tostring
      // for more details.
      return object == (other + '');

    case mapTag:
      var convert = mapToArray;

    case setTag:
      var isPartial = bitmask & PARTIAL_COMPARE_FLAG;
      convert || (convert = setToArray);

      if (object.size != other.size && !isPartial) {
        return false;
      }
      // Assume cyclic values are equal.
      var stacked = stack.get(object);
      if (stacked) {
        return stacked == other;
      }
      bitmask |= UNORDERED_COMPARE_FLAG;
      stack.set(object, other);

      // Recursively compare objects (susceptible to call stack limits).
      return equalArrays(convert(object), convert(other), equalFunc, customizer, bitmask, stack);

    case symbolTag:
      if (symbolValueOf) {
        return symbolValueOf.call(object) == symbolValueOf.call(other);
      }
  }
  return false;
}

module.exports = equalByTag;

},{"./_Symbol":63,"./_Uint8Array":64,"./_equalArrays":103,"./_mapToArray":129,"./_setToArray":133}],105:[function(require,module,exports){
var baseHas = require('./_baseHas'),
    keys = require('./keys');

/** Used to compose bitmasks for comparison styles. */
var PARTIAL_COMPARE_FLAG = 2;

/**
 * A specialized version of `baseIsEqualDeep` for objects with support for
 * partial deep comparisons.
 *
 * @private
 * @param {Object} object The object to compare.
 * @param {Object} other The other object to compare.
 * @param {Function} equalFunc The function to determine equivalents of values.
 * @param {Function} customizer The function to customize comparisons.
 * @param {number} bitmask The bitmask of comparison flags. See `baseIsEqual`
 *  for more details.
 * @param {Object} stack Tracks traversed `object` and `other` objects.
 * @returns {boolean} Returns `true` if the objects are equivalent, else `false`.
 */
function equalObjects(object, other, equalFunc, customizer, bitmask, stack) {
  var isPartial = bitmask & PARTIAL_COMPARE_FLAG,
      objProps = keys(object),
      objLength = objProps.length,
      othProps = keys(other),
      othLength = othProps.length;

  if (objLength != othLength && !isPartial) {
    return false;
  }
  var index = objLength;
  while (index--) {
    var key = objProps[index];
    if (!(isPartial ? key in other : baseHas(other, key))) {
      return false;
    }
  }
  // Assume cyclic values are equal.
  var stacked = stack.get(object);
  if (stacked) {
    return stacked == other;
  }
  var result = true;
  stack.set(object, other);

  var skipCtor = isPartial;
  while (++index < objLength) {
    key = objProps[index];
    var objValue = object[key],
        othValue = other[key];

    if (customizer) {
      var compared = isPartial
        ? customizer(othValue, objValue, key, other, object, stack)
        : customizer(objValue, othValue, key, object, other, stack);
    }
    // Recursively compare objects (susceptible to call stack limits).
    if (!(compared === undefined
          ? (objValue === othValue || equalFunc(objValue, othValue, customizer, bitmask, stack))
          : compared
        )) {
      result = false;
      break;
    }
    skipCtor || (skipCtor = key == 'constructor');
  }
  if (result && !skipCtor) {
    var objCtor = object.constructor,
        othCtor = other.constructor;

    // Non `Object` object instances with different constructors are not equal.
    if (objCtor != othCtor &&
        ('constructor' in object && 'constructor' in other) &&
        !(typeof objCtor == 'function' && objCtor instanceof objCtor &&
          typeof othCtor == 'function' && othCtor instanceof othCtor)) {
      result = false;
    }
  }
  stack['delete'](object);
  return result;
}

module.exports = equalObjects;

},{"./_baseHas":83,"./keys":164}],106:[function(require,module,exports){
var baseProperty = require('./_baseProperty');

/**
 * Gets the "length" property value of `object`.
 *
 * **Note:** This function is used to avoid a
 * [JIT bug](https://bugs.webkit.org/show_bug.cgi?id=142792) that affects
 * Safari on at least iOS 8.1-8.3 ARM64.
 *
 * @private
 * @param {Object} object The object to query.
 * @returns {*} Returns the "length" value.
 */
var getLength = baseProperty('length');

module.exports = getLength;

},{"./_baseProperty":92}],107:[function(require,module,exports){
var isStrictComparable = require('./_isStrictComparable'),
    toPairs = require('./toPairs');

/**
 * Gets the property names, values, and compare flags of `object`.
 *
 * @private
 * @param {Object} object The object to query.
 * @returns {Array} Returns the match data of `object`.
 */
function getMatchData(object) {
  var result = toPairs(object),
      length = result.length;

  while (length--) {
    result[length][2] = isStrictComparable(result[length][1]);
  }
  return result;
}

module.exports = getMatchData;

},{"./_isStrictComparable":123,"./toPairs":170}],108:[function(require,module,exports){
var isNative = require('./isNative');

/**
 * Gets the native function at `key` of `object`.
 *
 * @private
 * @param {Object} object The object to query.
 * @param {string} key The key of the method to get.
 * @returns {*} Returns the function if it's native, else `undefined`.
 */
function getNative(object, key) {
  var value = object[key];
  return isNative(value) ? value : undefined;
}

module.exports = getNative;

},{"./isNative":158}],109:[function(require,module,exports){
/* Built-in method references for those with the same name as other `lodash` methods. */
var nativeGetPrototype = Object.getPrototypeOf;

/**
 * Gets the `[[Prototype]]` of `value`.
 *
 * @private
 * @param {*} value The value to query.
 * @returns {null|Object} Returns the `[[Prototype]]`.
 */
function getPrototype(value) {
  return nativeGetPrototype(Object(value));
}

module.exports = getPrototype;

},{}],110:[function(require,module,exports){
var DataView = require('./_DataView'),
    Map = require('./_Map'),
    Promise = require('./_Promise'),
    Set = require('./_Set'),
    WeakMap = require('./_WeakMap'),
    toSource = require('./_toSource');

/** `Object#toString` result references. */
var mapTag = '[object Map]',
    objectTag = '[object Object]',
    promiseTag = '[object Promise]',
    setTag = '[object Set]',
    weakMapTag = '[object WeakMap]';

var dataViewTag = '[object DataView]';

/** Used for built-in method references. */
var objectProto = Object.prototype;

/**
 * Used to resolve the
 * [`toStringTag`](http://ecma-international.org/ecma-262/6.0/#sec-object.prototype.tostring)
 * of values.
 */
var objectToString = objectProto.toString;

/** Used to detect maps, sets, and weakmaps. */
var dataViewCtorString = toSource(DataView),
    mapCtorString = toSource(Map),
    promiseCtorString = toSource(Promise),
    setCtorString = toSource(Set),
    weakMapCtorString = toSource(WeakMap);

/**
 * Gets the `toStringTag` of `value`.
 *
 * @private
 * @param {*} value The value to query.
 * @returns {string} Returns the `toStringTag`.
 */
function getTag(value) {
  return objectToString.call(value);
}

// Fallback for data views, maps, sets, and weak maps in IE 11,
// for data views in Edge, and promises in Node.js.
if ((DataView && getTag(new DataView(new ArrayBuffer(1))) != dataViewTag) ||
    (Map && getTag(new Map) != mapTag) ||
    (Promise && getTag(Promise.resolve()) != promiseTag) ||
    (Set && getTag(new Set) != setTag) ||
    (WeakMap && getTag(new WeakMap) != weakMapTag)) {
  getTag = function(value) {
    var result = objectToString.call(value),
        Ctor = result == objectTag ? value.constructor : undefined,
        ctorString = Ctor ? toSource(Ctor) : undefined;

    if (ctorString) {
      switch (ctorString) {
        case dataViewCtorString: return dataViewTag;
        case mapCtorString: return mapTag;
        case promiseCtorString: return promiseTag;
        case setCtorString: return setTag;
        case weakMapCtorString: return weakMapTag;
      }
    }
    return result;
  };
}

module.exports = getTag;

},{"./_DataView":56,"./_Map":58,"./_Promise":60,"./_Set":61,"./_WeakMap":65,"./_toSource":141}],111:[function(require,module,exports){
var castPath = require('./_castPath'),
    isArguments = require('./isArguments'),
    isArray = require('./isArray'),
    isIndex = require('./_isIndex'),
    isKey = require('./_isKey'),
    isLength = require('./isLength'),
    isString = require('./isString'),
    toKey = require('./_toKey');

/**
 * Checks if `path` exists on `object`.
 *
 * @private
 * @param {Object} object The object to query.
 * @param {Array|string} path The path to check.
 * @param {Function} hasFunc The function to check properties.
 * @returns {boolean} Returns `true` if `path` exists, else `false`.
 */
function hasPath(object, path, hasFunc) {
  path = isKey(path, object) ? [path] : castPath(path);

  var result,
      index = -1,
      length = path.length;

  while (++index < length) {
    var key = toKey(path[index]);
    if (!(result = object != null && hasFunc(object, key))) {
      break;
    }
    object = object[key];
  }
  if (result) {
    return result;
  }
  var length = object ? object.length : 0;
  return !!length && isLength(length) && isIndex(key, length) &&
    (isArray(object) || isString(object) || isArguments(object));
}

module.exports = hasPath;

},{"./_castPath":97,"./_isIndex":118,"./_isKey":120,"./_toKey":140,"./isArguments":150,"./isArray":151,"./isLength":157,"./isString":161}],112:[function(require,module,exports){
var hashHas = require('./_hashHas');

/**
 * Removes `key` and its value from the hash.
 *
 * @private
 * @param {Object} hash The hash to modify.
 * @param {string} key The key of the value to remove.
 * @returns {boolean} Returns `true` if the entry was removed, else `false`.
 */
function hashDelete(hash, key) {
  return hashHas(hash, key) && delete hash[key];
}

module.exports = hashDelete;

},{"./_hashHas":114}],113:[function(require,module,exports){
var nativeCreate = require('./_nativeCreate');

/** Used to stand-in for `undefined` hash values. */
var HASH_UNDEFINED = '__lodash_hash_undefined__';

/** Used for built-in method references. */
var objectProto = Object.prototype;

/** Used to check objects for own properties. */
var hasOwnProperty = objectProto.hasOwnProperty;

/**
 * Gets the hash value for `key`.
 *
 * @private
 * @param {Object} hash The hash to query.
 * @param {string} key The key of the value to get.
 * @returns {*} Returns the entry value.
 */
function hashGet(hash, key) {
  if (nativeCreate) {
    var result = hash[key];
    return result === HASH_UNDEFINED ? undefined : result;
  }
  return hasOwnProperty.call(hash, key) ? hash[key] : undefined;
}

module.exports = hashGet;

},{"./_nativeCreate":131}],114:[function(require,module,exports){
var nativeCreate = require('./_nativeCreate');

/** Used for built-in method references. */
var objectProto = Object.prototype;

/** Used to check objects for own properties. */
var hasOwnProperty = objectProto.hasOwnProperty;

/**
 * Checks if a hash value for `key` exists.
 *
 * @private
 * @param {Object} hash The hash to query.
 * @param {string} key The key of the entry to check.
 * @returns {boolean} Returns `true` if an entry for `key` exists, else `false`.
 */
function hashHas(hash, key) {
  return nativeCreate ? hash[key] !== undefined : hasOwnProperty.call(hash, key);
}

module.exports = hashHas;

},{"./_nativeCreate":131}],115:[function(require,module,exports){
var nativeCreate = require('./_nativeCreate');

/** Used to stand-in for `undefined` hash values. */
var HASH_UNDEFINED = '__lodash_hash_undefined__';

/**
 * Sets the hash `key` to `value`.
 *
 * @private
 * @param {Object} hash The hash to modify.
 * @param {string} key The key of the value to set.
 * @param {*} value The value to set.
 */
function hashSet(hash, key, value) {
  hash[key] = (nativeCreate && value === undefined) ? HASH_UNDEFINED : value;
}

module.exports = hashSet;

},{"./_nativeCreate":131}],116:[function(require,module,exports){
var baseTimes = require('./_baseTimes'),
    isArguments = require('./isArguments'),
    isArray = require('./isArray'),
    isLength = require('./isLength'),
    isString = require('./isString');

/**
 * Creates an array of index keys for `object` values of arrays,
 * `arguments` objects, and strings, otherwise `null` is returned.
 *
 * @private
 * @param {Object} object The object to query.
 * @returns {Array|null} Returns index keys, else `null`.
 */
function indexKeys(object) {
  var length = object ? object.length : undefined;
  if (isLength(length) &&
      (isArray(object) || isString(object) || isArguments(object))) {
    return baseTimes(length, String);
  }
  return null;
}

module.exports = indexKeys;

},{"./_baseTimes":94,"./isArguments":150,"./isArray":151,"./isLength":157,"./isString":161}],117:[function(require,module,exports){
/**
 * Checks if `value` is a host object in IE < 9.
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a host object, else `false`.
 */
function isHostObject(value) {
  // Many host objects are `Object` objects that can coerce to strings
  // despite having improperly defined `toString` methods.
  var result = false;
  if (value != null && typeof value.toString != 'function') {
    try {
      result = !!(value + '');
    } catch (e) {}
  }
  return result;
}

module.exports = isHostObject;

},{}],118:[function(require,module,exports){
/** Used as references for various `Number` constants. */
var MAX_SAFE_INTEGER = 9007199254740991;

/** Used to detect unsigned integer values. */
var reIsUint = /^(?:0|[1-9]\d*)$/;

/**
 * Checks if `value` is a valid array-like index.
 *
 * @private
 * @param {*} value The value to check.
 * @param {number} [length=MAX_SAFE_INTEGER] The upper bounds of a valid index.
 * @returns {boolean} Returns `true` if `value` is a valid index, else `false`.
 */
function isIndex(value, length) {
  length = length == null ? MAX_SAFE_INTEGER : length;
  return !!length &&
    (typeof value == 'number' || reIsUint.test(value)) &&
    (value > -1 && value % 1 == 0 && value < length);
}

module.exports = isIndex;

},{}],119:[function(require,module,exports){
var eq = require('./eq'),
    isArrayLike = require('./isArrayLike'),
    isIndex = require('./_isIndex'),
    isObject = require('./isObject');

/**
 * Checks if the given arguments are from an iteratee call.
 *
 * @private
 * @param {*} value The potential iteratee value argument.
 * @param {*} index The potential iteratee index or key argument.
 * @param {*} object The potential iteratee object argument.
 * @returns {boolean} Returns `true` if the arguments are from an iteratee call,
 *  else `false`.
 */
function isIterateeCall(value, index, object) {
  if (!isObject(object)) {
    return false;
  }
  var type = typeof index;
  if (type == 'number'
        ? (isArrayLike(object) && isIndex(index, object.length))
        : (type == 'string' && index in object)
      ) {
    return eq(object[index], value);
  }
  return false;
}

module.exports = isIterateeCall;

},{"./_isIndex":118,"./eq":145,"./isArrayLike":152,"./isObject":159}],120:[function(require,module,exports){
var isArray = require('./isArray'),
    isSymbol = require('./isSymbol');

/** Used to match property names within property paths. */
var reIsDeepProp = /\.|\[(?:[^[\]]*|(["'])(?:(?!\1)[^\\]|\\.)*?\1)\]/,
    reIsPlainProp = /^\w*$/;

/**
 * Checks if `value` is a property name and not a property path.
 *
 * @private
 * @param {*} value The value to check.
 * @param {Object} [object] The object to query keys on.
 * @returns {boolean} Returns `true` if `value` is a property name, else `false`.
 */
function isKey(value, object) {
  if (isArray(value)) {
    return false;
  }
  var type = typeof value;
  if (type == 'number' || type == 'symbol' || type == 'boolean' ||
      value == null || isSymbol(value)) {
    return true;
  }
  return reIsPlainProp.test(value) || !reIsDeepProp.test(value) ||
    (object != null && value in Object(object));
}

module.exports = isKey;

},{"./isArray":151,"./isSymbol":162}],121:[function(require,module,exports){
/**
 * Checks if `value` is suitable for use as unique object key.
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is suitable, else `false`.
 */
function isKeyable(value) {
  var type = typeof value;
  return (type == 'string' || type == 'number' || type == 'symbol' || type == 'boolean')
    ? (value !== '__proto__')
    : (value === null);
}

module.exports = isKeyable;

},{}],122:[function(require,module,exports){
/** Used for built-in method references. */
var objectProto = Object.prototype;

/**
 * Checks if `value` is likely a prototype object.
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a prototype, else `false`.
 */
function isPrototype(value) {
  var Ctor = value && value.constructor,
      proto = (typeof Ctor == 'function' && Ctor.prototype) || objectProto;

  return value === proto;
}

module.exports = isPrototype;

},{}],123:[function(require,module,exports){
var isObject = require('./isObject');

/**
 * Checks if `value` is suitable for strict equality comparisons, i.e. `===`.
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` if suitable for strict
 *  equality comparisons, else `false`.
 */
function isStrictComparable(value) {
  return value === value && !isObject(value);
}

module.exports = isStrictComparable;

},{"./isObject":159}],124:[function(require,module,exports){
var Hash = require('./_Hash'),
    Map = require('./_Map');

/**
 * Removes all key-value entries from the map.
 *
 * @private
 * @name clear
 * @memberOf MapCache
 */
function mapClear() {
  this.__data__ = {
    'hash': new Hash,
    'map': Map ? new Map : [],
    'string': new Hash
  };
}

module.exports = mapClear;

},{"./_Hash":57,"./_Map":58}],125:[function(require,module,exports){
var Map = require('./_Map'),
    assocDelete = require('./_assocDelete'),
    hashDelete = require('./_hashDelete'),
    isKeyable = require('./_isKeyable');

/**
 * Removes `key` and its value from the map.
 *
 * @private
 * @name delete
 * @memberOf MapCache
 * @param {string} key The key of the value to remove.
 * @returns {boolean} Returns `true` if the entry was removed, else `false`.
 */
function mapDelete(key) {
  var data = this.__data__;
  if (isKeyable(key)) {
    return hashDelete(typeof key == 'string' ? data.string : data.hash, key);
  }
  return Map ? data.map['delete'](key) : assocDelete(data.map, key);
}

module.exports = mapDelete;

},{"./_Map":58,"./_assocDelete":71,"./_hashDelete":112,"./_isKeyable":121}],126:[function(require,module,exports){
var Map = require('./_Map'),
    assocGet = require('./_assocGet'),
    hashGet = require('./_hashGet'),
    isKeyable = require('./_isKeyable');

/**
 * Gets the map value for `key`.
 *
 * @private
 * @name get
 * @memberOf MapCache
 * @param {string} key The key of the value to get.
 * @returns {*} Returns the entry value.
 */
function mapGet(key) {
  var data = this.__data__;
  if (isKeyable(key)) {
    return hashGet(typeof key == 'string' ? data.string : data.hash, key);
  }
  return Map ? data.map.get(key) : assocGet(data.map, key);
}

module.exports = mapGet;

},{"./_Map":58,"./_assocGet":72,"./_hashGet":113,"./_isKeyable":121}],127:[function(require,module,exports){
var Map = require('./_Map'),
    assocHas = require('./_assocHas'),
    hashHas = require('./_hashHas'),
    isKeyable = require('./_isKeyable');

/**
 * Checks if a map value for `key` exists.
 *
 * @private
 * @name has
 * @memberOf MapCache
 * @param {string} key The key of the entry to check.
 * @returns {boolean} Returns `true` if an entry for `key` exists, else `false`.
 */
function mapHas(key) {
  var data = this.__data__;
  if (isKeyable(key)) {
    return hashHas(typeof key == 'string' ? data.string : data.hash, key);
  }
  return Map ? data.map.has(key) : assocHas(data.map, key);
}

module.exports = mapHas;

},{"./_Map":58,"./_assocHas":73,"./_hashHas":114,"./_isKeyable":121}],128:[function(require,module,exports){
var Map = require('./_Map'),
    assocSet = require('./_assocSet'),
    hashSet = require('./_hashSet'),
    isKeyable = require('./_isKeyable');

/**
 * Sets the map `key` to `value`.
 *
 * @private
 * @name set
 * @memberOf MapCache
 * @param {string} key The key of the value to set.
 * @param {*} value The value to set.
 * @returns {Object} Returns the map cache instance.
 */
function mapSet(key, value) {
  var data = this.__data__;
  if (isKeyable(key)) {
    hashSet(typeof key == 'string' ? data.string : data.hash, key, value);
  } else if (Map) {
    data.map.set(key, value);
  } else {
    assocSet(data.map, key, value);
  }
  return this;
}

module.exports = mapSet;

},{"./_Map":58,"./_assocSet":75,"./_hashSet":115,"./_isKeyable":121}],129:[function(require,module,exports){
/**
 * Converts `map` to an array.
 *
 * @private
 * @param {Object} map The map to convert.
 * @returns {Array} Returns the converted array.
 */
function mapToArray(map) {
  var index = -1,
      result = Array(map.size);

  map.forEach(function(value, key) {
    result[++index] = [key, value];
  });
  return result;
}

module.exports = mapToArray;

},{}],130:[function(require,module,exports){
/**
 * A specialized version of `matchesProperty` for source values suitable
 * for strict equality comparisons, i.e. `===`.
 *
 * @private
 * @param {string} key The key of the property to get.
 * @param {*} srcValue The value to match.
 * @returns {Function} Returns the new function.
 */
function matchesStrictComparable(key, srcValue) {
  return function(object) {
    if (object == null) {
      return false;
    }
    return object[key] === srcValue &&
      (srcValue !== undefined || (key in Object(object)));
  };
}

module.exports = matchesStrictComparable;

},{}],131:[function(require,module,exports){
var getNative = require('./_getNative');

/* Built-in method references that are verified to be native. */
var nativeCreate = getNative(Object, 'create');

module.exports = nativeCreate;

},{"./_getNative":108}],132:[function(require,module,exports){
(function (global){
var checkGlobal = require('./_checkGlobal');

/** Used to determine if values are of the language type `Object`. */
var objectTypes = {
  'function': true,
  'object': true
};

/** Detect free variable `exports`. */
var freeExports = (objectTypes[typeof exports] && exports && !exports.nodeType)
  ? exports
  : undefined;

/** Detect free variable `module`. */
var freeModule = (objectTypes[typeof module] && module && !module.nodeType)
  ? module
  : undefined;

/** Detect free variable `global` from Node.js. */
var freeGlobal = checkGlobal(freeExports && freeModule && typeof global == 'object' && global);

/** Detect free variable `self`. */
var freeSelf = checkGlobal(objectTypes[typeof self] && self);

/** Detect free variable `window`. */
var freeWindow = checkGlobal(objectTypes[typeof window] && window);

/** Detect `this` as the global object. */
var thisGlobal = checkGlobal(objectTypes[typeof this] && this);

/**
 * Used as a reference to the global object.
 *
 * The `this` value is used if it's the global object to avoid Greasemonkey's
 * restricted `window` object, otherwise the `window` object is used.
 */
var root = freeGlobal ||
  ((freeWindow !== (thisGlobal && thisGlobal.window)) && freeWindow) ||
    freeSelf || thisGlobal || Function('return this')();

module.exports = root;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./_checkGlobal":98}],133:[function(require,module,exports){
/**
 * Converts `set` to an array.
 *
 * @private
 * @param {Object} set The set to convert.
 * @returns {Array} Returns the converted array.
 */
function setToArray(set) {
  var index = -1,
      result = Array(set.size);

  set.forEach(function(value) {
    result[++index] = value;
  });
  return result;
}

module.exports = setToArray;

},{}],134:[function(require,module,exports){
/**
 * Removes all key-value entries from the stack.
 *
 * @private
 * @name clear
 * @memberOf Stack
 */
function stackClear() {
  this.__data__ = { 'array': [], 'map': null };
}

module.exports = stackClear;

},{}],135:[function(require,module,exports){
var assocDelete = require('./_assocDelete');

/**
 * Removes `key` and its value from the stack.
 *
 * @private
 * @name delete
 * @memberOf Stack
 * @param {string} key The key of the value to remove.
 * @returns {boolean} Returns `true` if the entry was removed, else `false`.
 */
function stackDelete(key) {
  var data = this.__data__,
      array = data.array;

  return array ? assocDelete(array, key) : data.map['delete'](key);
}

module.exports = stackDelete;

},{"./_assocDelete":71}],136:[function(require,module,exports){
var assocGet = require('./_assocGet');

/**
 * Gets the stack value for `key`.
 *
 * @private
 * @name get
 * @memberOf Stack
 * @param {string} key The key of the value to get.
 * @returns {*} Returns the entry value.
 */
function stackGet(key) {
  var data = this.__data__,
      array = data.array;

  return array ? assocGet(array, key) : data.map.get(key);
}

module.exports = stackGet;

},{"./_assocGet":72}],137:[function(require,module,exports){
var assocHas = require('./_assocHas');

/**
 * Checks if a stack value for `key` exists.
 *
 * @private
 * @name has
 * @memberOf Stack
 * @param {string} key The key of the entry to check.
 * @returns {boolean} Returns `true` if an entry for `key` exists, else `false`.
 */
function stackHas(key) {
  var data = this.__data__,
      array = data.array;

  return array ? assocHas(array, key) : data.map.has(key);
}

module.exports = stackHas;

},{"./_assocHas":73}],138:[function(require,module,exports){
var MapCache = require('./_MapCache'),
    assocSet = require('./_assocSet');

/** Used as the size to enable large array optimizations. */
var LARGE_ARRAY_SIZE = 200;

/**
 * Sets the stack `key` to `value`.
 *
 * @private
 * @name set
 * @memberOf Stack
 * @param {string} key The key of the value to set.
 * @param {*} value The value to set.
 * @returns {Object} Returns the stack cache instance.
 */
function stackSet(key, value) {
  var data = this.__data__,
      array = data.array;

  if (array) {
    if (array.length < (LARGE_ARRAY_SIZE - 1)) {
      assocSet(array, key, value);
    } else {
      data.array = null;
      data.map = new MapCache(array);
    }
  }
  var map = data.map;
  if (map) {
    map.set(key, value);
  }
  return this;
}

module.exports = stackSet;

},{"./_MapCache":59,"./_assocSet":75}],139:[function(require,module,exports){
var memoize = require('./memoize'),
    toString = require('./toString');

/** Used to match property names within property paths. */
var rePropName = /[^.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]/g;

/** Used to match backslashes in property paths. */
var reEscapeChar = /\\(\\)?/g;

/**
 * Converts `string` to a property path array.
 *
 * @private
 * @param {string} string The string to convert.
 * @returns {Array} Returns the property path array.
 */
var stringToPath = memoize(function(string) {
  var result = [];
  toString(string).replace(rePropName, function(match, number, quote, string) {
    result.push(quote ? string.replace(reEscapeChar, '$1') : (number || match));
  });
  return result;
});

module.exports = stringToPath;

},{"./memoize":165,"./toString":171}],140:[function(require,module,exports){
var isSymbol = require('./isSymbol');

/** Used as references for various `Number` constants. */
var INFINITY = 1 / 0;

/**
 * Converts `value` to a string key if it's not a string or symbol.
 *
 * @private
 * @param {*} value The value to inspect.
 * @returns {string|symbol} Returns the key.
 */
function toKey(value) {
  if (typeof value == 'string' || isSymbol(value)) {
    return value;
  }
  var result = (value + '');
  return (result == '0' && (1 / value) == -INFINITY) ? '-0' : result;
}

module.exports = toKey;

},{"./isSymbol":162}],141:[function(require,module,exports){
/** Used to resolve the decompiled source of functions. */
var funcToString = Function.prototype.toString;

/**
 * Converts `func` to its source code.
 *
 * @private
 * @param {Function} func The function to process.
 * @returns {string} Returns the source code.
 */
function toSource(func) {
  if (func != null) {
    try {
      return funcToString.call(func);
    } catch (e) {}
    try {
      return (func + '');
    } catch (e) {}
  }
  return '';
}

module.exports = toSource;

},{}],142:[function(require,module,exports){
var assignValue = require('./_assignValue'),
    copyObject = require('./_copyObject'),
    createAssigner = require('./_createAssigner'),
    isArrayLike = require('./isArrayLike'),
    isPrototype = require('./_isPrototype'),
    keys = require('./keys');

/** Used for built-in method references. */
var objectProto = Object.prototype;

/** Used to check objects for own properties. */
var hasOwnProperty = objectProto.hasOwnProperty;

/** Built-in value references. */
var propertyIsEnumerable = objectProto.propertyIsEnumerable;

/** Detect if properties shadowing those on `Object.prototype` are non-enumerable. */
var nonEnumShadows = !propertyIsEnumerable.call({ 'valueOf': 1 }, 'valueOf');

/**
 * Assigns own enumerable string keyed properties of source objects to the
 * destination object. Source objects are applied from left to right.
 * Subsequent sources overwrite property assignments of previous sources.
 *
 * **Note:** This method mutates `object` and is loosely based on
 * [`Object.assign`](https://mdn.io/Object/assign).
 *
 * @static
 * @memberOf _
 * @since 0.10.0
 * @category Object
 * @param {Object} object The destination object.
 * @param {...Object} [sources] The source objects.
 * @returns {Object} Returns `object`.
 * @see _.assignIn
 * @example
 *
 * function Foo() {
 *   this.c = 3;
 * }
 *
 * function Bar() {
 *   this.e = 5;
 * }
 *
 * Foo.prototype.d = 4;
 * Bar.prototype.f = 6;
 *
 * _.assign({ 'a': 1 }, new Foo, new Bar);
 * // => { 'a': 1, 'c': 3, 'e': 5 }
 */
var assign = createAssigner(function(object, source) {
  if (nonEnumShadows || isPrototype(source) || isArrayLike(source)) {
    copyObject(source, keys(source), object);
    return;
  }
  for (var key in source) {
    if (hasOwnProperty.call(source, key)) {
      assignValue(object, key, source[key]);
    }
  }
});

module.exports = assign;

},{"./_assignValue":70,"./_copyObject":99,"./_createAssigner":100,"./_isPrototype":122,"./isArrayLike":152,"./keys":164}],143:[function(require,module,exports){
/**
 * Creates a function that returns `value`.
 *
 * @static
 * @memberOf _
 * @since 2.4.0
 * @category Util
 * @param {*} value The value to return from the new function.
 * @returns {Function} Returns the new function.
 * @example
 *
 * var object = { 'user': 'fred' };
 * var getter = _.constant(object);
 *
 * getter() === object;
 * // => true
 */
function constant(value) {
  return function() {
    return value;
  };
}

module.exports = constant;

},{}],144:[function(require,module,exports){
var baseAssign = require('./_baseAssign'),
    baseCreate = require('./_baseCreate');

/**
 * Creates an object that inherits from the `prototype` object. If a
 * `properties` object is given, its own enumerable string keyed properties
 * are assigned to the created object.
 *
 * @static
 * @memberOf _
 * @since 2.3.0
 * @category Object
 * @param {Object} prototype The object to inherit from.
 * @param {Object} [properties] The properties to assign to the object.
 * @returns {Object} Returns the new object.
 * @example
 *
 * function Shape() {
 *   this.x = 0;
 *   this.y = 0;
 * }
 *
 * function Circle() {
 *   Shape.call(this);
 * }
 *
 * Circle.prototype = _.create(Shape.prototype, {
 *   'constructor': Circle
 * });
 *
 * var circle = new Circle;
 * circle instanceof Circle;
 * // => true
 *
 * circle instanceof Shape;
 * // => true
 */
function create(prototype, properties) {
  var result = baseCreate(prototype);
  return properties ? baseAssign(result, properties) : result;
}

module.exports = create;

},{"./_baseAssign":76,"./_baseCreate":77}],145:[function(require,module,exports){
/**
 * Performs a
 * [`SameValueZero`](http://ecma-international.org/ecma-262/6.0/#sec-samevaluezero)
 * comparison between two values to determine if they are equivalent.
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Lang
 * @param {*} value The value to compare.
 * @param {*} other The other value to compare.
 * @returns {boolean} Returns `true` if the values are equivalent, else `false`.
 * @example
 *
 * var object = { 'user': 'fred' };
 * var other = { 'user': 'fred' };
 *
 * _.eq(object, object);
 * // => true
 *
 * _.eq(object, other);
 * // => false
 *
 * _.eq('a', 'a');
 * // => true
 *
 * _.eq('a', Object('a'));
 * // => false
 *
 * _.eq(NaN, NaN);
 * // => true
 */
function eq(value, other) {
  return value === other || (value !== value && other !== other);
}

module.exports = eq;

},{}],146:[function(require,module,exports){
var arrayEvery = require('./_arrayEvery'),
    baseEvery = require('./_baseEvery'),
    baseIteratee = require('./_baseIteratee'),
    isArray = require('./isArray'),
    isIterateeCall = require('./_isIterateeCall');

/**
 * Checks if `predicate` returns truthy for **all** elements of `collection`.
 * Iteration is stopped once `predicate` returns falsey. The predicate is
 * invoked with three arguments: (value, index|key, collection).
 *
 * @static
 * @memberOf _
 * @since 0.1.0
 * @category Collection
 * @param {Array|Object} collection The collection to iterate over.
 * @param {Array|Function|Object|string} [predicate=_.identity]
 *  The function invoked per iteration.
 * @param- {Object} [guard] Enables use as an iteratee for methods like `_.map`.
 * @returns {boolean} Returns `true` if all elements pass the predicate check,
 *  else `false`.
 * @example
 *
 * _.every([true, 1, null, 'yes'], Boolean);
 * // => false
 *
 * var users = [
 *   { 'user': 'barney', 'age': 36, 'active': false },
 *   { 'user': 'fred',   'age': 40, 'active': false }
 * ];
 *
 * // The `_.matches` iteratee shorthand.
 * _.every(users, { 'user': 'barney', 'active': false });
 * // => false
 *
 * // The `_.matchesProperty` iteratee shorthand.
 * _.every(users, ['active', false]);
 * // => true
 *
 * // The `_.property` iteratee shorthand.
 * _.every(users, 'active');
 * // => false
 */
function every(collection, predicate, guard) {
  var func = isArray(collection) ? arrayEvery : baseEvery;
  if (guard && isIterateeCall(collection, predicate, guard)) {
    predicate = undefined;
  }
  return func(collection, baseIteratee(predicate, 3));
}

module.exports = every;

},{"./_arrayEvery":67,"./_baseEvery":79,"./_baseIteratee":88,"./_isIterateeCall":119,"./isArray":151}],147:[function(require,module,exports){
var baseGet = require('./_baseGet');

/**
 * Gets the value at `path` of `object`. If the resolved value is
 * `undefined`, the `defaultValue` is used in its place.
 *
 * @static
 * @memberOf _
 * @since 3.7.0
 * @category Object
 * @param {Object} object The object to query.
 * @param {Array|string} path The path of the property to get.
 * @param {*} [defaultValue] The value returned for `undefined` resolved values.
 * @returns {*} Returns the resolved value.
 * @example
 *
 * var object = { 'a': [{ 'b': { 'c': 3 } }] };
 *
 * _.get(object, 'a[0].b.c');
 * // => 3
 *
 * _.get(object, ['a', '0', 'b', 'c']);
 * // => 3
 *
 * _.get(object, 'a.b.c', 'default');
 * // => 'default'
 */
function get(object, path, defaultValue) {
  var result = object == null ? undefined : baseGet(object, path);
  return result === undefined ? defaultValue : result;
}

module.exports = get;

},{"./_baseGet":82}],148:[function(require,module,exports){
var baseHasIn = require('./_baseHasIn'),
    hasPath = require('./_hasPath');

/**
 * Checks if `path` is a direct or inherited property of `object`.
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Object
 * @param {Object} object The object to query.
 * @param {Array|string} path The path to check.
 * @returns {boolean} Returns `true` if `path` exists, else `false`.
 * @example
 *
 * var object = _.create({ 'a': _.create({ 'b': 2 }) });
 *
 * _.hasIn(object, 'a');
 * // => true
 *
 * _.hasIn(object, 'a.b');
 * // => true
 *
 * _.hasIn(object, ['a', 'b']);
 * // => true
 *
 * _.hasIn(object, 'b');
 * // => false
 */
function hasIn(object, path) {
  return object != null && hasPath(object, path, baseHasIn);
}

module.exports = hasIn;

},{"./_baseHasIn":84,"./_hasPath":111}],149:[function(require,module,exports){
/**
 * This method returns the first argument given to it.
 *
 * @static
 * @since 0.1.0
 * @memberOf _
 * @category Util
 * @param {*} value Any value.
 * @returns {*} Returns `value`.
 * @example
 *
 * var object = { 'user': 'fred' };
 *
 * _.identity(object) === object;
 * // => true
 */
function identity(value) {
  return value;
}

module.exports = identity;

},{}],150:[function(require,module,exports){
var isArrayLikeObject = require('./isArrayLikeObject');

/** `Object#toString` result references. */
var argsTag = '[object Arguments]';

/** Used for built-in method references. */
var objectProto = Object.prototype;

/** Used to check objects for own properties. */
var hasOwnProperty = objectProto.hasOwnProperty;

/**
 * Used to resolve the
 * [`toStringTag`](http://ecma-international.org/ecma-262/6.0/#sec-object.prototype.tostring)
 * of values.
 */
var objectToString = objectProto.toString;

/** Built-in value references. */
var propertyIsEnumerable = objectProto.propertyIsEnumerable;

/**
 * Checks if `value` is likely an `arguments` object.
 *
 * @static
 * @memberOf _
 * @since 0.1.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is correctly classified,
 *  else `false`.
 * @example
 *
 * _.isArguments(function() { return arguments; }());
 * // => true
 *
 * _.isArguments([1, 2, 3]);
 * // => false
 */
function isArguments(value) {
  // Safari 8.1 incorrectly makes `arguments.callee` enumerable in strict mode.
  return isArrayLikeObject(value) && hasOwnProperty.call(value, 'callee') &&
    (!propertyIsEnumerable.call(value, 'callee') || objectToString.call(value) == argsTag);
}

module.exports = isArguments;

},{"./isArrayLikeObject":153}],151:[function(require,module,exports){
/**
 * Checks if `value` is classified as an `Array` object.
 *
 * @static
 * @memberOf _
 * @since 0.1.0
 * @type {Function}
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is correctly classified,
 *  else `false`.
 * @example
 *
 * _.isArray([1, 2, 3]);
 * // => true
 *
 * _.isArray(document.body.children);
 * // => false
 *
 * _.isArray('abc');
 * // => false
 *
 * _.isArray(_.noop);
 * // => false
 */
var isArray = Array.isArray;

module.exports = isArray;

},{}],152:[function(require,module,exports){
var getLength = require('./_getLength'),
    isFunction = require('./isFunction'),
    isLength = require('./isLength');

/**
 * Checks if `value` is array-like. A value is considered array-like if it's
 * not a function and has a `value.length` that's an integer greater than or
 * equal to `0` and less than or equal to `Number.MAX_SAFE_INTEGER`.
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is array-like, else `false`.
 * @example
 *
 * _.isArrayLike([1, 2, 3]);
 * // => true
 *
 * _.isArrayLike(document.body.children);
 * // => true
 *
 * _.isArrayLike('abc');
 * // => true
 *
 * _.isArrayLike(_.noop);
 * // => false
 */
function isArrayLike(value) {
  return value != null && isLength(getLength(value)) && !isFunction(value);
}

module.exports = isArrayLike;

},{"./_getLength":106,"./isFunction":156,"./isLength":157}],153:[function(require,module,exports){
var isArrayLike = require('./isArrayLike'),
    isObjectLike = require('./isObjectLike');

/**
 * This method is like `_.isArrayLike` except that it also checks if `value`
 * is an object.
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is an array-like object,
 *  else `false`.
 * @example
 *
 * _.isArrayLikeObject([1, 2, 3]);
 * // => true
 *
 * _.isArrayLikeObject(document.body.children);
 * // => true
 *
 * _.isArrayLikeObject('abc');
 * // => false
 *
 * _.isArrayLikeObject(_.noop);
 * // => false
 */
function isArrayLikeObject(value) {
  return isObjectLike(value) && isArrayLike(value);
}

module.exports = isArrayLikeObject;

},{"./isArrayLike":152,"./isObjectLike":160}],154:[function(require,module,exports){
var constant = require('./constant'),
    root = require('./_root');

/** Used to determine if values are of the language type `Object`. */
var objectTypes = {
  'function': true,
  'object': true
};

/** Detect free variable `exports`. */
var freeExports = (objectTypes[typeof exports] && exports && !exports.nodeType)
  ? exports
  : undefined;

/** Detect free variable `module`. */
var freeModule = (objectTypes[typeof module] && module && !module.nodeType)
  ? module
  : undefined;

/** Detect the popular CommonJS extension `module.exports`. */
var moduleExports = (freeModule && freeModule.exports === freeExports)
  ? freeExports
  : undefined;

/** Built-in value references. */
var Buffer = moduleExports ? root.Buffer : undefined;

/**
 * Checks if `value` is a buffer.
 *
 * @static
 * @memberOf _
 * @since 4.3.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a buffer, else `false`.
 * @example
 *
 * _.isBuffer(new Buffer(2));
 * // => true
 *
 * _.isBuffer(new Uint8Array(2));
 * // => false
 */
var isBuffer = !Buffer ? constant(false) : function(value) {
  return value instanceof Buffer;
};

module.exports = isBuffer;

},{"./_root":132,"./constant":143}],155:[function(require,module,exports){
var getTag = require('./_getTag'),
    isArguments = require('./isArguments'),
    isArray = require('./isArray'),
    isArrayLike = require('./isArrayLike'),
    isBuffer = require('./isBuffer'),
    isFunction = require('./isFunction'),
    isObjectLike = require('./isObjectLike'),
    isString = require('./isString'),
    keys = require('./keys');

/** `Object#toString` result references. */
var mapTag = '[object Map]',
    setTag = '[object Set]';

/** Used for built-in method references. */
var objectProto = Object.prototype;

/** Used to check objects for own properties. */
var hasOwnProperty = objectProto.hasOwnProperty;

/** Built-in value references. */
var propertyIsEnumerable = objectProto.propertyIsEnumerable;

/** Detect if properties shadowing those on `Object.prototype` are non-enumerable. */
var nonEnumShadows = !propertyIsEnumerable.call({ 'valueOf': 1 }, 'valueOf');

/**
 * Checks if `value` is an empty object, collection, map, or set.
 *
 * Objects are considered empty if they have no own enumerable string keyed
 * properties.
 *
 * Array-like values such as `arguments` objects, arrays, buffers, strings, or
 * jQuery-like collections are considered empty if they have a `length` of `0`.
 * Similarly, maps and sets are considered empty if they have a `size` of `0`.
 *
 * @static
 * @memberOf _
 * @since 0.1.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is empty, else `false`.
 * @example
 *
 * _.isEmpty(null);
 * // => true
 *
 * _.isEmpty(true);
 * // => true
 *
 * _.isEmpty(1);
 * // => true
 *
 * _.isEmpty([1, 2, 3]);
 * // => false
 *
 * _.isEmpty({ 'a': 1 });
 * // => false
 */
function isEmpty(value) {
  if (isArrayLike(value) &&
      (isArray(value) || isString(value) || isFunction(value.splice) ||
        isArguments(value) || isBuffer(value))) {
    return !value.length;
  }
  if (isObjectLike(value)) {
    var tag = getTag(value);
    if (tag == mapTag || tag == setTag) {
      return !value.size;
    }
  }
  for (var key in value) {
    if (hasOwnProperty.call(value, key)) {
      return false;
    }
  }
  return !(nonEnumShadows && keys(value).length);
}

module.exports = isEmpty;

},{"./_getTag":110,"./isArguments":150,"./isArray":151,"./isArrayLike":152,"./isBuffer":154,"./isFunction":156,"./isObjectLike":160,"./isString":161,"./keys":164}],156:[function(require,module,exports){
var isObject = require('./isObject');

/** `Object#toString` result references. */
var funcTag = '[object Function]',
    genTag = '[object GeneratorFunction]';

/** Used for built-in method references. */
var objectProto = Object.prototype;

/**
 * Used to resolve the
 * [`toStringTag`](http://ecma-international.org/ecma-262/6.0/#sec-object.prototype.tostring)
 * of values.
 */
var objectToString = objectProto.toString;

/**
 * Checks if `value` is classified as a `Function` object.
 *
 * @static
 * @memberOf _
 * @since 0.1.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is correctly classified,
 *  else `false`.
 * @example
 *
 * _.isFunction(_);
 * // => true
 *
 * _.isFunction(/abc/);
 * // => false
 */
function isFunction(value) {
  // The use of `Object#toString` avoids issues with the `typeof` operator
  // in Safari 8 which returns 'object' for typed array and weak map constructors,
  // and PhantomJS 1.9 which returns 'function' for `NodeList` instances.
  var tag = isObject(value) ? objectToString.call(value) : '';
  return tag == funcTag || tag == genTag;
}

module.exports = isFunction;

},{"./isObject":159}],157:[function(require,module,exports){
/** Used as references for various `Number` constants. */
var MAX_SAFE_INTEGER = 9007199254740991;

/**
 * Checks if `value` is a valid array-like length.
 *
 * **Note:** This function is loosely based on
 * [`ToLength`](http://ecma-international.org/ecma-262/6.0/#sec-tolength).
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a valid length,
 *  else `false`.
 * @example
 *
 * _.isLength(3);
 * // => true
 *
 * _.isLength(Number.MIN_VALUE);
 * // => false
 *
 * _.isLength(Infinity);
 * // => false
 *
 * _.isLength('3');
 * // => false
 */
function isLength(value) {
  return typeof value == 'number' &&
    value > -1 && value % 1 == 0 && value <= MAX_SAFE_INTEGER;
}

module.exports = isLength;

},{}],158:[function(require,module,exports){
var isFunction = require('./isFunction'),
    isHostObject = require('./_isHostObject'),
    isObject = require('./isObject'),
    toSource = require('./_toSource');

/**
 * Used to match `RegExp`
 * [syntax characters](http://ecma-international.org/ecma-262/6.0/#sec-patterns).
 */
var reRegExpChar = /[\\^$.*+?()[\]{}|]/g;

/** Used to detect host constructors (Safari). */
var reIsHostCtor = /^\[object .+?Constructor\]$/;

/** Used for built-in method references. */
var objectProto = Object.prototype;

/** Used to resolve the decompiled source of functions. */
var funcToString = Function.prototype.toString;

/** Used to check objects for own properties. */
var hasOwnProperty = objectProto.hasOwnProperty;

/** Used to detect if a method is native. */
var reIsNative = RegExp('^' +
  funcToString.call(hasOwnProperty).replace(reRegExpChar, '\\$&')
  .replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, '$1.*?') + '$'
);

/**
 * Checks if `value` is a native function.
 *
 * @static
 * @memberOf _
 * @since 3.0.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a native function,
 *  else `false`.
 * @example
 *
 * _.isNative(Array.prototype.push);
 * // => true
 *
 * _.isNative(_);
 * // => false
 */
function isNative(value) {
  if (!isObject(value)) {
    return false;
  }
  var pattern = (isFunction(value) || isHostObject(value)) ? reIsNative : reIsHostCtor;
  return pattern.test(toSource(value));
}

module.exports = isNative;

},{"./_isHostObject":117,"./_toSource":141,"./isFunction":156,"./isObject":159}],159:[function(require,module,exports){
/**
 * Checks if `value` is the
 * [language type](http://www.ecma-international.org/ecma-262/6.0/#sec-ecmascript-language-types)
 * of `Object`. (e.g. arrays, functions, objects, regexes, `new Number(0)`, and `new String('')`)
 *
 * @static
 * @memberOf _
 * @since 0.1.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is an object, else `false`.
 * @example
 *
 * _.isObject({});
 * // => true
 *
 * _.isObject([1, 2, 3]);
 * // => true
 *
 * _.isObject(_.noop);
 * // => true
 *
 * _.isObject(null);
 * // => false
 */
function isObject(value) {
  var type = typeof value;
  return !!value && (type == 'object' || type == 'function');
}

module.exports = isObject;

},{}],160:[function(require,module,exports){
/**
 * Checks if `value` is object-like. A value is object-like if it's not `null`
 * and has a `typeof` result of "object".
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is object-like, else `false`.
 * @example
 *
 * _.isObjectLike({});
 * // => true
 *
 * _.isObjectLike([1, 2, 3]);
 * // => true
 *
 * _.isObjectLike(_.noop);
 * // => false
 *
 * _.isObjectLike(null);
 * // => false
 */
function isObjectLike(value) {
  return !!value && typeof value == 'object';
}

module.exports = isObjectLike;

},{}],161:[function(require,module,exports){
var isArray = require('./isArray'),
    isObjectLike = require('./isObjectLike');

/** `Object#toString` result references. */
var stringTag = '[object String]';

/** Used for built-in method references. */
var objectProto = Object.prototype;

/**
 * Used to resolve the
 * [`toStringTag`](http://ecma-international.org/ecma-262/6.0/#sec-object.prototype.tostring)
 * of values.
 */
var objectToString = objectProto.toString;

/**
 * Checks if `value` is classified as a `String` primitive or object.
 *
 * @static
 * @since 0.1.0
 * @memberOf _
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is correctly classified,
 *  else `false`.
 * @example
 *
 * _.isString('abc');
 * // => true
 *
 * _.isString(1);
 * // => false
 */
function isString(value) {
  return typeof value == 'string' ||
    (!isArray(value) && isObjectLike(value) && objectToString.call(value) == stringTag);
}

module.exports = isString;

},{"./isArray":151,"./isObjectLike":160}],162:[function(require,module,exports){
var isObjectLike = require('./isObjectLike');

/** `Object#toString` result references. */
var symbolTag = '[object Symbol]';

/** Used for built-in method references. */
var objectProto = Object.prototype;

/**
 * Used to resolve the
 * [`toStringTag`](http://ecma-international.org/ecma-262/6.0/#sec-object.prototype.tostring)
 * of values.
 */
var objectToString = objectProto.toString;

/**
 * Checks if `value` is classified as a `Symbol` primitive or object.
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is correctly classified,
 *  else `false`.
 * @example
 *
 * _.isSymbol(Symbol.iterator);
 * // => true
 *
 * _.isSymbol('abc');
 * // => false
 */
function isSymbol(value) {
  return typeof value == 'symbol' ||
    (isObjectLike(value) && objectToString.call(value) == symbolTag);
}

module.exports = isSymbol;

},{"./isObjectLike":160}],163:[function(require,module,exports){
var isLength = require('./isLength'),
    isObjectLike = require('./isObjectLike');

/** `Object#toString` result references. */
var argsTag = '[object Arguments]',
    arrayTag = '[object Array]',
    boolTag = '[object Boolean]',
    dateTag = '[object Date]',
    errorTag = '[object Error]',
    funcTag = '[object Function]',
    mapTag = '[object Map]',
    numberTag = '[object Number]',
    objectTag = '[object Object]',
    regexpTag = '[object RegExp]',
    setTag = '[object Set]',
    stringTag = '[object String]',
    weakMapTag = '[object WeakMap]';

var arrayBufferTag = '[object ArrayBuffer]',
    dataViewTag = '[object DataView]',
    float32Tag = '[object Float32Array]',
    float64Tag = '[object Float64Array]',
    int8Tag = '[object Int8Array]',
    int16Tag = '[object Int16Array]',
    int32Tag = '[object Int32Array]',
    uint8Tag = '[object Uint8Array]',
    uint8ClampedTag = '[object Uint8ClampedArray]',
    uint16Tag = '[object Uint16Array]',
    uint32Tag = '[object Uint32Array]';

/** Used to identify `toStringTag` values of typed arrays. */
var typedArrayTags = {};
typedArrayTags[float32Tag] = typedArrayTags[float64Tag] =
typedArrayTags[int8Tag] = typedArrayTags[int16Tag] =
typedArrayTags[int32Tag] = typedArrayTags[uint8Tag] =
typedArrayTags[uint8ClampedTag] = typedArrayTags[uint16Tag] =
typedArrayTags[uint32Tag] = true;
typedArrayTags[argsTag] = typedArrayTags[arrayTag] =
typedArrayTags[arrayBufferTag] = typedArrayTags[boolTag] =
typedArrayTags[dataViewTag] = typedArrayTags[dateTag] =
typedArrayTags[errorTag] = typedArrayTags[funcTag] =
typedArrayTags[mapTag] = typedArrayTags[numberTag] =
typedArrayTags[objectTag] = typedArrayTags[regexpTag] =
typedArrayTags[setTag] = typedArrayTags[stringTag] =
typedArrayTags[weakMapTag] = false;

/** Used for built-in method references. */
var objectProto = Object.prototype;

/**
 * Used to resolve the
 * [`toStringTag`](http://ecma-international.org/ecma-262/6.0/#sec-object.prototype.tostring)
 * of values.
 */
var objectToString = objectProto.toString;

/**
 * Checks if `value` is classified as a typed array.
 *
 * @static
 * @memberOf _
 * @since 3.0.0
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is correctly classified,
 *  else `false`.
 * @example
 *
 * _.isTypedArray(new Uint8Array);
 * // => true
 *
 * _.isTypedArray([]);
 * // => false
 */
function isTypedArray(value) {
  return isObjectLike(value) &&
    isLength(value.length) && !!typedArrayTags[objectToString.call(value)];
}

module.exports = isTypedArray;

},{"./isLength":157,"./isObjectLike":160}],164:[function(require,module,exports){
var baseHas = require('./_baseHas'),
    baseKeys = require('./_baseKeys'),
    indexKeys = require('./_indexKeys'),
    isArrayLike = require('./isArrayLike'),
    isIndex = require('./_isIndex'),
    isPrototype = require('./_isPrototype');

/**
 * Creates an array of the own enumerable property names of `object`.
 *
 * **Note:** Non-object values are coerced to objects. See the
 * [ES spec](http://ecma-international.org/ecma-262/6.0/#sec-object.keys)
 * for more details.
 *
 * @static
 * @since 0.1.0
 * @memberOf _
 * @category Object
 * @param {Object} object The object to query.
 * @returns {Array} Returns the array of property names.
 * @example
 *
 * function Foo() {
 *   this.a = 1;
 *   this.b = 2;
 * }
 *
 * Foo.prototype.c = 3;
 *
 * _.keys(new Foo);
 * // => ['a', 'b'] (iteration order is not guaranteed)
 *
 * _.keys('hi');
 * // => ['0', '1']
 */
function keys(object) {
  var isProto = isPrototype(object);
  if (!(isProto || isArrayLike(object))) {
    return baseKeys(object);
  }
  var indexes = indexKeys(object),
      skipIndexes = !!indexes,
      result = indexes || [],
      length = result.length;

  for (var key in object) {
    if (baseHas(object, key) &&
        !(skipIndexes && (key == 'length' || isIndex(key, length))) &&
        !(isProto && key == 'constructor')) {
      result.push(key);
    }
  }
  return result;
}

module.exports = keys;

},{"./_baseHas":83,"./_baseKeys":89,"./_indexKeys":116,"./_isIndex":118,"./_isPrototype":122,"./isArrayLike":152}],165:[function(require,module,exports){
var MapCache = require('./_MapCache');

/** Used as the `TypeError` message for "Functions" methods. */
var FUNC_ERROR_TEXT = 'Expected a function';

/**
 * Creates a function that memoizes the result of `func`. If `resolver` is
 * provided, it determines the cache key for storing the result based on the
 * arguments provided to the memoized function. By default, the first argument
 * provided to the memoized function is used as the map cache key. The `func`
 * is invoked with the `this` binding of the memoized function.
 *
 * **Note:** The cache is exposed as the `cache` property on the memoized
 * function. Its creation may be customized by replacing the `_.memoize.Cache`
 * constructor with one whose instances implement the
 * [`Map`](http://ecma-international.org/ecma-262/6.0/#sec-properties-of-the-map-prototype-object)
 * method interface of `delete`, `get`, `has`, and `set`.
 *
 * @static
 * @memberOf _
 * @since 0.1.0
 * @category Function
 * @param {Function} func The function to have its output memoized.
 * @param {Function} [resolver] The function to resolve the cache key.
 * @returns {Function} Returns the new memoizing function.
 * @example
 *
 * var object = { 'a': 1, 'b': 2 };
 * var other = { 'c': 3, 'd': 4 };
 *
 * var values = _.memoize(_.values);
 * values(object);
 * // => [1, 2]
 *
 * values(other);
 * // => [3, 4]
 *
 * object.a = 2;
 * values(object);
 * // => [1, 2]
 *
 * // Modify the result cache.
 * values.cache.set(object, ['a', 'b']);
 * values(object);
 * // => ['a', 'b']
 *
 * // Replace `_.memoize.Cache`.
 * _.memoize.Cache = WeakMap;
 */
function memoize(func, resolver) {
  if (typeof func != 'function' || (resolver && typeof resolver != 'function')) {
    throw new TypeError(FUNC_ERROR_TEXT);
  }
  var memoized = function() {
    var args = arguments,
        key = resolver ? resolver.apply(this, args) : args[0],
        cache = memoized.cache;

    if (cache.has(key)) {
      return cache.get(key);
    }
    var result = func.apply(this, args);
    memoized.cache = cache.set(key, result);
    return result;
  };
  memoized.cache = new (memoize.Cache || MapCache);
  return memoized;
}

// Assign cache to `_.memoize`.
memoize.Cache = MapCache;

module.exports = memoize;

},{"./_MapCache":59}],166:[function(require,module,exports){
var baseProperty = require('./_baseProperty'),
    basePropertyDeep = require('./_basePropertyDeep'),
    isKey = require('./_isKey'),
    toKey = require('./_toKey');

/**
 * Creates a function that returns the value at `path` of a given object.
 *
 * @static
 * @memberOf _
 * @since 2.4.0
 * @category Util
 * @param {Array|string} path The path of the property to get.
 * @returns {Function} Returns the new function.
 * @example
 *
 * var objects = [
 *   { 'a': { 'b': 2 } },
 *   { 'a': { 'b': 1 } }
 * ];
 *
 * _.map(objects, _.property('a.b'));
 * // => [2, 1]
 *
 * _.map(_.sortBy(objects, _.property(['a', 'b'])), 'a.b');
 * // => [1, 2]
 */
function property(path) {
  return isKey(path) ? baseProperty(toKey(path)) : basePropertyDeep(path);
}

module.exports = property;

},{"./_baseProperty":92,"./_basePropertyDeep":93,"./_isKey":120,"./_toKey":140}],167:[function(require,module,exports){
var apply = require('./_apply'),
    toInteger = require('./toInteger');

/** Used as the `TypeError` message for "Functions" methods. */
var FUNC_ERROR_TEXT = 'Expected a function';

/* Built-in method references for those with the same name as other `lodash` methods. */
var nativeMax = Math.max;

/**
 * Creates a function that invokes `func` with the `this` binding of the
 * created function and arguments from `start` and beyond provided as
 * an array.
 *
 * **Note:** This method is based on the
 * [rest parameter](https://mdn.io/rest_parameters).
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Function
 * @param {Function} func The function to apply a rest parameter to.
 * @param {number} [start=func.length-1] The start position of the rest parameter.
 * @returns {Function} Returns the new function.
 * @example
 *
 * var say = _.rest(function(what, names) {
 *   return what + ' ' + _.initial(names).join(', ') +
 *     (_.size(names) > 1 ? ', & ' : '') + _.last(names);
 * });
 *
 * say('hello', 'fred', 'barney', 'pebbles');
 * // => 'hello fred, barney, & pebbles'
 */
function rest(func, start) {
  if (typeof func != 'function') {
    throw new TypeError(FUNC_ERROR_TEXT);
  }
  start = nativeMax(start === undefined ? (func.length - 1) : toInteger(start), 0);
  return function() {
    var args = arguments,
        index = -1,
        length = nativeMax(args.length - start, 0),
        array = Array(length);

    while (++index < length) {
      array[index] = args[start + index];
    }
    switch (start) {
      case 0: return func.call(this, array);
      case 1: return func.call(this, args[0], array);
      case 2: return func.call(this, args[0], args[1], array);
    }
    var otherArgs = Array(start + 1);
    index = -1;
    while (++index < start) {
      otherArgs[index] = args[index];
    }
    otherArgs[start] = array;
    return apply(func, this, otherArgs);
  };
}

module.exports = rest;

},{"./_apply":66,"./toInteger":168}],168:[function(require,module,exports){
var toNumber = require('./toNumber');

/** Used as references for various `Number` constants. */
var INFINITY = 1 / 0,
    MAX_INTEGER = 1.7976931348623157e+308;

/**
 * Converts `value` to an integer.
 *
 * **Note:** This function is loosely based on
 * [`ToInteger`](http://www.ecma-international.org/ecma-262/6.0/#sec-tointeger).
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Lang
 * @param {*} value The value to convert.
 * @returns {number} Returns the converted integer.
 * @example
 *
 * _.toInteger(3);
 * // => 3
 *
 * _.toInteger(Number.MIN_VALUE);
 * // => 0
 *
 * _.toInteger(Infinity);
 * // => 1.7976931348623157e+308
 *
 * _.toInteger('3');
 * // => 3
 */
function toInteger(value) {
  if (!value) {
    return value === 0 ? value : 0;
  }
  value = toNumber(value);
  if (value === INFINITY || value === -INFINITY) {
    var sign = (value < 0 ? -1 : 1);
    return sign * MAX_INTEGER;
  }
  var remainder = value % 1;
  return value === value ? (remainder ? value - remainder : value) : 0;
}

module.exports = toInteger;

},{"./toNumber":169}],169:[function(require,module,exports){
var isFunction = require('./isFunction'),
    isObject = require('./isObject'),
    isSymbol = require('./isSymbol');

/** Used as references for various `Number` constants. */
var NAN = 0 / 0;

/** Used to match leading and trailing whitespace. */
var reTrim = /^\s+|\s+$/g;

/** Used to detect bad signed hexadecimal string values. */
var reIsBadHex = /^[-+]0x[0-9a-f]+$/i;

/** Used to detect binary string values. */
var reIsBinary = /^0b[01]+$/i;

/** Used to detect octal string values. */
var reIsOctal = /^0o[0-7]+$/i;

/** Built-in method references without a dependency on `root`. */
var freeParseInt = parseInt;

/**
 * Converts `value` to a number.
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Lang
 * @param {*} value The value to process.
 * @returns {number} Returns the number.
 * @example
 *
 * _.toNumber(3);
 * // => 3
 *
 * _.toNumber(Number.MIN_VALUE);
 * // => 5e-324
 *
 * _.toNumber(Infinity);
 * // => Infinity
 *
 * _.toNumber('3');
 * // => 3
 */
function toNumber(value) {
  if (typeof value == 'number') {
    return value;
  }
  if (isSymbol(value)) {
    return NAN;
  }
  if (isObject(value)) {
    var other = isFunction(value.valueOf) ? value.valueOf() : value;
    value = isObject(other) ? (other + '') : other;
  }
  if (typeof value != 'string') {
    return value === 0 ? value : +value;
  }
  value = value.replace(reTrim, '');
  var isBinary = reIsBinary.test(value);
  return (isBinary || reIsOctal.test(value))
    ? freeParseInt(value.slice(2), isBinary ? 2 : 8)
    : (reIsBadHex.test(value) ? NAN : +value);
}

module.exports = toNumber;

},{"./isFunction":156,"./isObject":159,"./isSymbol":162}],170:[function(require,module,exports){
var baseToPairs = require('./_baseToPairs'),
    keys = require('./keys');

/**
 * Creates an array of own enumerable string keyed-value pairs for `object`
 * which can be consumed by `_.fromPairs`.
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @alias entries
 * @category Object
 * @param {Object} object The object to query.
 * @returns {Array} Returns the new array of key-value pairs.
 * @example
 *
 * function Foo() {
 *   this.a = 1;
 *   this.b = 2;
 * }
 *
 * Foo.prototype.c = 3;
 *
 * _.toPairs(new Foo);
 * // => [['a', 1], ['b', 2]] (iteration order is not guaranteed)
 */
function toPairs(object) {
  return baseToPairs(object, keys(object));
}

module.exports = toPairs;

},{"./_baseToPairs":95,"./keys":164}],171:[function(require,module,exports){
var baseToString = require('./_baseToString');

/**
 * Converts `value` to a string. An empty string is returned for `null`
 * and `undefined` values. The sign of `-0` is preserved.
 *
 * @static
 * @memberOf _
 * @since 4.0.0
 * @category Lang
 * @param {*} value The value to process.
 * @returns {string} Returns the string.
 * @example
 *
 * _.toString(null);
 * // => ''
 *
 * _.toString(-0);
 * // => '-0'
 *
 * _.toString([1, 2, 3]);
 * // => '1,2,3'
 */
function toString(value) {
  return value == null ? '' : baseToString(value);
}

module.exports = toString;

},{"./_baseToString":96}]},{},[6])(6)
});