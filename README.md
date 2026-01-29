# XMLFiesta

[![npm version][npm-image]][npm-url]
[![Bower version][bower-image]][bower-url]
[![Build Status][travis-image]][travis-url]
[![Coverage Status][coveralls-image]][coveralls-url]

Version: 1.7.1

Electronic signed document XML Protocol **reader** and validator for Node & Browser.

**Supported validation modes:**

- **Standard**: Documents without a `blockchain` node (signatures and document integrity).
- **Tracked**: Documents with a `blockchain` node (plus on-chain data; Liquid only).
- **Transfers**: For tracked XMLs, validation of the `transfers` node (holder changes on the chain).

## Install

## Browser - Bower

```
bower install xml-fiesta --save
```

## NodeJS - NPM

```bash
npm install xml-fiesta --save
```

## Concepts and definitions

- **Standard XML**: Document without a `blockchain` node. Validation checks signatures and document integrity only (no on-chain data).
- **Tracked XML**: Document that includes a `blockchain` node. Validation compares XML data with on-chain data (asset, hash, transfers).
- **Blockchain track**: The on-chain history for the asset referenced in the XML (used to verify that the document matches the chain).
- **Mainnet**: Liquid production network (real assets). Used by default when parsing tracked XML.
- **Testnet**: Liquid test network (no real value). Enable by passing `true` as the second argument to `Document.fromXml()`.
- **LBTC**: Liquid Bitcoin network; fully supported via Blockstream API.
- **LTC**: Legacy network identifier; some blockchain validations are skipped.
- **oHashValid**: Whether the original hash in the XML matches the computed document hash (integrity check).
- **Transfer**: Change of holder/ownership of the asset on the blockchain. **Endorser** = previous holder; **endorsee** = new holder.

## Usage

```javascript
var fs = require("fs");
var XMLFiesta = require("xml-fiesta");
var xml = __dirname + "/spec/fixtures/example_signed_cr-v1.0.0.xml";

fs.readFile(xml, function (err, data) {
  // Document.fromXml returns a promise
  var parsed = XMLFiesta.Document.fromXml(data);
  parsed.then(function (result) {
    var doc = result.document;
    doc.file(); // ASCII File
    doc.file("hex"); // HEX File
    doc.file("base64"); // Base64 File
    var signatures = doc.signatures();
    var signature = signatures[0];
    signature.certificate();
    signature.sig(); // HEX signature
    signature.sig("base64"); // Base64 signature
    signature.signedAt(); // ~ 2016-05-03T00:51:05+00:00
    signature.valid(); // true
    signature.signer;
    // {
    //   id: 'AAA010101AAA',
    //   name: 'ACCEM SERVICIOS EMPRESARIALES SC',
    //   email: 'some@email.com'
    // }

    doc.validSignatures(); // true

    doc.record; // -> XMLFiesta::ConservancyRecord
    // validates that the record is valid
    doc.record.valid();
    // validates that the record timestamp is the same as the xml
    doc.record.equalTimestamps();
    // validates that the archive of the record was signed with the user certificate
    doc.record.validArchiveHash();
  });
});
```

## Validations API

You can validate a parsed XML instance by calling `validate()` (exposed on the object returned by `Document.fromXml`).

```javascript
const { Document } = require("xml-fiesta");

async function validateXml(xmlString, rootCertificates) {
  const parsed = await Document.fromXml(xmlString);

  const result = await parsed.validate({ rootCertificates });

  if (result.mode === "standard") {
    return result.standard; // { isValid, document, signatures }
  }

  return result.tracked; // { isValid, showLimitData, oHashValid, asset, document, signatures, transfers }
}
```

## Tracked XML (blockchain-backed)

An XML is considered **tracked** when it includes the `blockchain` node. For tracked documents, `Document.fromXml` will try to load the **blockchain track** during parsing (so the validation can compare XML data vs on-chain data).

### Blockchain support

- **LBTC**: Supported via Liquid (Blockstream API).
- **LTC**: Not supported; some blockchain validations are skipped for legacy reasons.

### Network / testnet

**Testnet** is a separate Liquid network used for testing (no real value). Mainnet is the production network where real assets live.

`Document.fromXml(xmlString, useTestnet)` accepts a second boolean argument:

- **Omit it or pass `false`** (default): uses Liquid **mainnet** for blockchain lookups.
- **Pass `true`**: uses Liquid **testnet** for blockchain lookups.

Example: `Document.fromXml(xmlString, true)` enables testnet; `Document.fromXml(xmlString)` uses mainnet.

### Node.js note (fetch required)

Liquid tracking uses `fetch()` under the hood. In Node.js you must provide a global `fetch` implementation.

## Transfers (tracked XML)

Tracked XMLs can include a `transfers` node. When validating a tracked XML, transfers are validated when:

- `tracked.showLimitData` is `false`, and
- the document network is not `LTC`.

When transfers are validated, the result includes `tracked.transfers` with per-transfer validation results:

- Holder binding integrity (endorser = previous holder, endorsee = new holder).
- Consistency with blockchain addresses.
- Transfer signatures validation.
- Transfer document validations.

You can also access transfers directly from a parsed tracked document:

```javascript
const { Document } = require("xml-fiesta");

async function listTransfers(xmlString) {
  const { document } = await Document.fromXml(xmlString);
  const transfers = await document.transfers();
  return transfers.map((t) => ({
    prevAddress: t.prevAddress,
    currentAddress: t.currentAddress,
  }));
}
```

## OpenSSL validations

Optional manual checks: you can validate a certificate against a Certificate Authority using OpenSSL. See [this gist](https://gist.github.com/genaromadrid/9075d315e949fb4b3760db5c36c9a8ca) for details.

## Development

Just run `grunt` in the root of this project and start developing, the terminal will run the tests on each change.

## Test

Run `npm test` or `grunt test`. The coverage info is still pending.

## Build and publish

- Run `grunt build` to generate the files to bower.
- Run `grunt bump` to bump versions in bower and npm.

[npm-url]: https://badge.fury.io/js/xml-fiesta
[npm-image]: https://badge.fury.io/js/xml-fiesta.svg
[bower-image]: https://badge.fury.io/bo/xml-fiesta.svg
[bower-url]: https://badge.fury.io/bo/xml-fiesta
[travis-image]: https://travis-ci.org/Mifiel/xml-fiesta-js.svg?branch=master
[travis-url]: https://travis-ci.org/Mifiel/xml-fiesta-js
[coveralls-image]: https://coveralls.io/repos/github/Mifiel/xml-fiesta-js/badge.svg?branch=master
[coveralls-url]: https://coveralls.io/github/Mifiel/xml-fiesta-js?branch=master
