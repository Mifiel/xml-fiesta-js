import { expect } from "chai";
const fs = require("fs");

import XML from "../src/xml";
import { sha256 } from "../src/common";

describe("XML", () => {
  describe("v0", () => {
    let xml: XML;

    beforeEach((done) => {
      const xmlExample = `${__dirname}/fixtures/example_signed_cr.xml`;
      const xmlString = fs.readFileSync(xmlExample, "utf8");
      xml = new XML();
      xml.parse(xmlString).then(() => done());
    });

    describe("original xml hash", () => {
      const originalXmlHash =
        "3e585f9cc5397f4f3295d6a4d650762e009b5db606e70417e5fb342f0ab07b7c";

      it("should be the sha256 of the XML", () => {
        const calculated = sha256(xml.canonical());
        expect(calculated).to.eq(originalXmlHash);
      });
    });
  });

  describe("v1", () => {
    let xml;
    const readFile = async (nameFile = "example_signed_cr-v1.0.0.xml") => {
      const xmlExample = `${__dirname}/fixtures/${nameFile}`;
      const xmlString = fs.readFileSync(xmlExample, "utf8");
      xml = new XML();
      await xml.parse(xmlString);
    };

    describe("original xml hash", () => {
      const originalXmlHash =
        "5e67870434d6cf3006fd87c6" + "0f58b493e505eac18d4ac48ad671dbb3396b5ca4";

      it("should be the sha256 of the XML", async () => {
        await readFile();
        const calculated = sha256(xml.canonical());
        expect(calculated).to.eq(originalXmlHash);
      });
    });

    describe("transfer and blockchain nodes", () => {
      const originalXmlHash =
        "e5087df06b81111cdc13d7766e8105189d9c90df11d34ca0a045108046f4cd78";

      it("should be the sha256 of the XML and the xml canonical shouldn't have 'blockchain' and 'transfer' nodes", async () => {
        await readFile("example_signed_transfer.xml");
        const xmlCanonical = xml.canonical();
        const calculated = sha256(xmlCanonical);

        expect(xmlCanonical).not.includes("<blockchain name=");
        expect(xmlCanonical).not.includes("<transfers");
        expect(calculated).to.eq(originalXmlHash);
      });
    });
  });
});
