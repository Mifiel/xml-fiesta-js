# Changelog

## v1.3.4
- Remove geolocation on canonical xml

## v1.3.3
- Remove window line-endings on canonical string

## v1.3.2
- Upgrade xml-crypto to fix a bug that didnt create the canonical xml correctly

## v1.3.0
- Remove coffeescript in favor of typescript
- Allow to pass encrypted XMLs
- Allow an XML to have multiple signers with the same email / rfc
- Add encrypted documents validations

## v1.2.0
- Add support for NOM2016

## v1.1.0
- Add support to version 1 of XMLFiesta protocol
- Deprecate some methods
- Small buf fixes

TODO: change every method or property that implies that a PDF is always signing. In XMLFiesta protocol version 1 you can sign any document (image, pdf, video, etc.)

## v1.0.0
- Breaking change: Document.fromXml now returns a promise
- Move xml reader to XMLFiesta::XML
- Archive validations on Conservancy Record

## v0.0.6
- Dont throw exceptions on conservancy record when certificates are invalid
- Allow to verify a conservancy record cert against a CA certificate
- Minor fixes

## v0.0.5
- Add conservancy record parser and validator
    + Validates record timestamp against given timestamp
    + validates record signature against CA certificate
- Bug Fixes

## v0.0.4
- Bug fix htat prevented instanciate more than 1 certificate or signature in the same app.

## v0.0.3
- npm packaging
