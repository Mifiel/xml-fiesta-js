fs = require 'fs'
XML = require '../src/xml'
common = require '../src/common'
expect = require('expect.js')

describe 'XML', ->

  beforeEach (done) ->
    xmlExample = "#{__dirname}/fixtures/example_signed_cr.xml"
    xmlString = fs.readFileSync(xmlExample)
    this.xml = new XML()
    this.xml.parse(xmlString).then ->
      done()

  describe 'original xml hash', (done) ->
    originalXmlHash = '3e585f9cc5397f4f3295d6a4' +
                      'd650762e009b5db606e70417e5fb342f0ab07b7c'

    it 'should be the sha256 of the XML', ->
      calculated = common.sha256(this.xml.canonical())
      expect(calculated).to.be originalXmlHash
