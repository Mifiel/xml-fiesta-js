import { expect } from "chai";

import XML from "../src/xml";
import { parseVersion, compareVersions, gteVersion, ltVersion } from "../src/version";

describe("semver comparison", () => {
  describe("compareVersions", () => {
    it("orders multi-digit components without collisions", () => {
      expect(compareVersions("2.4.10", "2.5.0")).to.eq(-1);
      expect(compareVersions("2.5.0", "2.4.10")).to.eq(1);
      expect(compareVersions("2.5.10", "2.6.0")).to.eq(-1);
      expect(compareVersions("2.15.0", "3.5.0")).to.eq(-1);
      expect(compareVersions("2.5.0", "2.5.0")).to.eq(0);
    });

    it("treats missing components as zero", () => {
      expect(compareVersions("2.5", "2.5.0")).to.eq(0);
      expect(compareVersions("2", "2.0.0")).to.eq(0);
    });

    it("rejects malformed versions explicitly", () => {
      expect(() => parseVersion("")).to.throw();
      expect(() => parseVersion("abc")).to.throw();
      expect(() => parseVersion("1.2.3.4")).to.throw();
      expect(() => parseVersion("1.x")).to.throw();
      expect(() => parseVersion(null)).to.throw();
    });
  });

  describe("gteVersion", () => {
    it("holds the documented gate thresholds", () => {
      expect(gteVersion("2.5.0", "2.5.0")).to.eq(true);
      expect(gteVersion("2.4.10", "2.5.0")).to.eq(false);
      expect(gteVersion("1.0.0", "1.0.0")).to.eq(true);
      expect(gteVersion("0.0.2", "1.0.0")).to.eq(false);
      expect(ltVersion("2.4.10", "2.5.0")).to.eq(true);
      expect(ltVersion("2.5.0", "2.5.0")).to.eq(false);
      expect(ltVersion("0.0.2", "1.0.0")).to.eq(true);
    });
  });

  describe("XML version gates", () => {
    const buildEdoc = (version: string): any => ({
      $: { version, signed: "true" },
      file: [
        {
          $: {
            name: "example.pdf",
            contentType: "application/pdf",
            originalHash: "abc123",
          },
          _: "file-content",
        },
      ],
      signers: [
        {
          signer: [
            {
              $: { id: "AAA010101AAA", name: "Some signer" },
              certificate: [{ _: "Q0VSVERBVEE=" }],
              signature: [
                {
                  $: { signedAt: "2016-06-07T23:56:08+00:00" },
                  _: "U0lH",
                },
              ],
            },
          ],
        },
      ],
    });

    it("uses the legacy pdf element below 1.0.0", () => {
      const xml = XML.parseByElectronicDocument({
        $: { version: "0.0.2", signed: "true" },
        pdf: [
          {
            $: {
              name: "example.pdf",
              contentType: "application/pdf",
              originalHash: "abc123",
            },
            _: "file-content",
          },
        ],
      });
      expect(xml.fileElementName).to.eq("pdf");
    });

    it("strips signer certificates at 2.5.0 but keeps them at 2.4.10", () => {
      const below = XML.parseByElectronicDocument(buildEdoc("2.4.10"));
      const at = XML.parseByElectronicDocument(buildEdoc("2.5.0"));
      expect(below.canonical()).to.include("Q0VSVERBVEE=");
      expect(at.canonical()).to.not.include("Q0VSVERBVEE=");
    });

    it("rejects malformed versions at parse time", () => {
      expect(() =>
        XML.parseByElectronicDocument(buildEdoc("abc")),
      ).to.throw();
    });
  });
});
