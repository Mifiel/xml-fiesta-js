import { expect } from "chai";
import Document from "../src/document";

const fs = require("fs");

describe("Validations", () => {
  describe("standard XML", () => {
    it("should expose validate() on fromXml result and return standard mode", async () => {
      const xmlExample = `${__dirname}/fixtures/example_signed_cr.xml`;
      const xmlBuffer = fs.readFileSync(xmlExample);

      const parsed = await Document.fromXml(xmlBuffer);
      expect(parsed.validate).to.be.a("function");

      // This fixture is a valid signed XML, but without root certificates passed
      // the certificate chain validation will fail and the result should not be "success".
      const result = await parsed.validate({ rootCertificates: [] });
      expect(result).to.have.property("mode");
      if (result.mode !== "standard") {
        throw new Error(`Expected standard mode, got: ${result.mode}`);
      }
      expect(result).to.have.property("standard");
      expect(result.standard).to.have.property("document");
      expect(result.standard).to.have.property("signatures");
      expect(result.standard.signatures).to.be.an("array");
    });
  });
});
