# XMLFiesta

Version: 0.0.1

Electronic signed document XML Protocol for Node & Browser

## Install

## Browser - Bower

```
bower install xml-fiesta --save
```

## NodeJS - NPM

```bash
npm install xml-fiesta --save
```

## Usage

```javascript
var fs        = require('fs');
var XMLFiesta = require('xml-fiesta');
var xml = "#{__dirname}/spec/fixtures/example_signed.xml";

fs.readFile(xml, function(err, data) {
  doc = XMLFiesta.Document.fromXml(data)
  doc.pdf() // ASCII PDF
  doc.pdf('hex') // HEX PDF
  doc.pdf('base64') // Base64 PDF
  signatures = doc.signatures()
  signature = signatures[0]
  signature.certificate()
  signature.sig() // HEX signature
  signature.sig('base64') // Base64 signature
  signature.signedAt() // 2016-05-03T00:51:05+00:00
  signature.valid() // true
  signature.signer
  // {
  //   id: 'AAA010101AAA',
  //   name: 'ACCEM SERVICIOS EMPRESARIALES SC',
  //   email: 'some@email.com'
  // }

  doc.validSignatures() // true
});

```

## OpenSSL validations

Please read [this gist](https://gist.github.com/genaromadrid/9075d315e949fb4b3760db5c36c9a8ca) to see how to Validate a Certificate against a Certificate authority using OpenSSL.

## Development

Just run `grunt` in the root of this project and start developing, the terminal will run the tests on each change.

## Test

Run `npm test` or `grunt test`. The coverage info is still pending.

## Build and publish

- Run `grunt build` to generate the files to bower.
- Run `grunt bump` to bump versions in bower and npm.
