import { expect } from "chai";
const fs = require("fs");

import Signature from "../src/signature";
import Document from "../src/document";
import { b64toHex } from "../src/common";
import XML from "../src/xml";

describe("Document", function () {
  const sigB64 =
    "pC/+NvlV5Wsr9Mg4T7EUq/qEx7T0PUb+fz6c13kUziuH2N9BrCRpD/C7JPMU pcoVab3wnbBXCSnUYUXcG95k88zHqz0uBv9nzvh+AGZTzCPyxiiLDZtsuYjs Q6GN/O6g95Ngm4Q/UHVSoS2Sr+VhTRgEnweeffC1nSZU5q5cVd8DkrUNr2ek mtA8dgR+6Vt6LSnjqdQWISfHB2o34E3dI/QuQg+18OOGY6OZZw+jAVQ9m6WU Uxwateton07AaNVFTOOBPKCHcrAqfcvarv/guhxVTmHM/JKb2MpydkBiAvEd cGZaKmV0tK5ptMkVogAy1HkEkG9TgmI0/8qnmAVNlw==";
  const sig = b64toHex(sigB64);
  const signers = [
    {
      email: "some@gmail.com",
      signature: sig,
      cer: null,
      signedAt: new Date(),
    },
  ];

  const getCer = () => {
    const data = fs.readFileSync(`${__dirname}/fixtures/FIEL_AAA010101AAA.cer`);
    return data;
  };

  beforeEach((done) => {
    const data = getCer();
    signers[0].cer = data.toString("hex");
    done();
  });

  describe("initialize", function () {
    describe("without signers", () =>
      it("should be OK", function () {
        const doc = new Document("cGRmLWJhc2U2NC1jb250ZW50", {});
        expect(doc.signers).to.be.empty;
      }));

    describe("without cer", () => {
      it("should raise error", () => {
        try {
          new Document("cGRmLWJhc2U2NC1jb250ZW50", {
            signers: [
              {
                email: signers[0].email,
                signature: signers[0].signature,
              },
            ],
          });
        } catch (err) {
          expect(err.name).to.equal("InvalidSignerError");
        }
      });
    });
  });

  describe("methods", function () {
    let doc;
    beforeEach(
      () => (doc = new Document("cGRmLWJhc2U2NC1jb250ZW50", { signers }))
    );

    describe(".file", function () {
      it("should be defined", () => expect(doc.file).to.be.a("function"));

      it("should be an ascci string", function () {
        const file = doc.file();
        expect(file).to.equal("pdf-base64-content");
      });

      describe("with unkown format", () => {
        it("should throw Exception", () => {
          try {
            doc.file("blah");
          } catch (err) {
            expect(err.name).to.equal("ArgumentError");
          }
        });
      });

      describe("with base64 format", () => {
        it("should throw Exception", () => {
          expect(doc.file("base64")).to.equal("cGRmLWJhc2U2NC1jb250ZW50");
        });
      });
    });

    describe(".signers", function () {
      it("should be defined", () => expect(doc.signers).to.be.an("array"));

      it("should have signers", () =>
        expect(doc.signers[0].email).to.equal(signers[0].email));
    });

    describe(".signatures", function () {
      it("should be defined", () => expect(doc.signatures).to.be.a("function"));

      it("should have Signature objects", () => {
        expect(doc.signatures()[0]).to.be.an.instanceof(Signature);
      });

      it("should have 1 Signature", () =>
        expect(doc.signatures().length).to.eq(1));
    });

    describe(".validSignatures", () =>
      it("should be defined", () =>
        expect(doc.validSignatures).to.be.a("function")));

    describe(".isSimpleTrackedDocument", () => {
      let blockchainBindingCertificate;

      beforeEach(() => {
        const data = getCer();
        signers[0].cer = data.toString("hex");
        blockchainBindingCertificate = {
          certificate: [{ _: data.toString("base64") }],
        };
      });

      it("should be defined", () => {
        expect(doc.isSimpleTrackedDocument).to.be.a("function");
      });

      it("should return true when it's tracked and certificate of blockchain->binding is a rootCertificate", () => {
        doc.tracked = true;
        doc.blockchainBinding = blockchainBindingCertificate;
        const result = doc.isSimpleTrackedDocument([
          { cer_hex: signers[0].cer },
        ]);

        expect(result).to.be.true;
      });

      it("should return false when it's tracked and certificate of blockchain->binding is not a rootCertificate", () => {
        doc.tracked = true;
        doc.blockchainBinding = blockchainBindingCertificate;
        const result = doc.isSimpleTrackedDocument([{ cer_hex: "1234567890" }]);

        expect(result).to.be.false;
      });

      it("should return error when it's not tracked", () => {
        doc.tracked = false;

        expect(() => doc.isSimpleTrackedDocument([])).to.throw(
          Error,
          "Document is not tracked"
        );
      });
    });

    describe(".isValidHashInTrackedDocument", () => {
      beforeEach(() => {});

      it("should return true when it's a valid hash", () => {
        doc.tracked = true;
        doc.originalHash = "hash";
        doc.validHashInBlockchainBinding = () => true;
        doc.blockchainBinding = {
          signature: [{ $: { plaintext: "hash|xassetx|xaddressx" } }],
        };

        const result = doc.isValidHashInTrackedDocument([]);

        expect(result).to.deep.equal({ isValid: true });
      });

      it("should return false with error_code:'integrity' when originalHash doesn't match with plaintext", () => {
        doc.tracked = true;
        doc.originalHash = "hash";
        doc.validHashInBlockchainBinding = () => true;
        doc.blockchainBinding = {
          signature: [{ $: { plaintext: "diferentHash|xassetx|xaddressx" } }],
        };

        const result = doc.isValidHashInTrackedDocument([]);
        expect(result).to.deep.equal({
          isValid: false,
          error_code: "integrity",
        });
      });

      it("should return false with error_code:'integrity' when validHashInBlockchainBinding function return false", () => {
        doc.tracked = true;
        doc.originalHash = "hash";
        doc.validHashInBlockchainBinding = () => false;
        doc.blockchainBinding = {
          signature: [{ $: { plaintext: "hash|xassetx|xaddressx" } }],
        };

        const result = doc.isValidHashInTrackedDocument([]);
        expect(result).to.deep.equal({
          isValid: false,
          error_code: "integrity",
        });
      });

      it("should return error when it's not tracked", () => {
        doc.tracked = false;

        expect(() => doc.isValidHashInTrackedDocument([])).to.throw(
          Error,
          "Document is not tracked"
        );
      });
    });

    describe(".validHashInBlockchainBinding", () => {
      const cerB64 =
        "MIIDiDCCAnCgAwIBAgIUMjAwMDEwMDAwMDAyMDAwNDkxNDMwDQYJKoZIhvcN AQEFBQAwMjELMAkGA1UEBhMCTlgxDzANBgNVBAoMBk1pZmllbDESMBAGA1UE AwwJTWlmaWVsIENBMB4XDTIyMDMwNDE5MjQxNVoXDTI0MDMwMzE5MjQxNVow gZYxDzANBgNVBAMMBk1pZmllbDEPMA0GA1UEKQwGTWlmaWVsMQ8wDQYDVQQK DAZNaWZpZWwxCzAJBgNVBAYTAk1YMSMwIQYJKoZIhvcNAQkBFhRzaW1wbGVz aWdAbWlmaWVsLmNvbTESMBAGA1UELQwJTUlGSUVMUkZDMRswGQYDVQQFExJI RUdUNzYxMDAzTURGTlNSMDgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK AoIBAQC2ZbXPoqA9wZNrlAgnXsTg4Dhi6bcKgA04LrtL7o80J84C/ILggvZU Y/bMGLs7Z9LVdsEjKqA1zPc44REIDE1jal/FUYNjd/hQeLDE+oE2aD5JlN4g AZokOE6b6Wc+VFnoY9tQ8Ur8RA07a2Mdd2fDhBjTNwSKOrktYdPnqrMOPfzI 1FgHzmq3HgoCp7YSFEKyR5WaqEkq4tLD2wGeGnF0JHsVk6ePkxm4A6vFLIyo 5JXp1oJKWmglux4tITtT2R7BHRocIkv4FJlHUlHFQ6cAKhaLLhnoz/s/VTkW TKT1z2AK0CaZxvnF8YpbuMTSo6hVhkyXOdd0BOh3YmxISzG/AgMBAAGjMTAv MA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUpNxvPqm43Li6GjSsyJpDDsAU AkUwDQYJKoZIhvcNAQEFBQADggEBAL4lvnNTHDXsAb6Qqg72SivT8CJSLOnQ 1Q389PvnbWg33tmiJ5Aoo92cqnnhr6SeGwZz+44V9W6z+vN1/G1PrYd+WUvk r2BqUwlQmrssgFq8FfjALMYOXCdzeqwl0i9OPV1atNSSXShyvmc4+Isqaveo QLnAA+GySLO4jxc2i+TMVv9kYXGZcN+P7PzaCnqgVqm5kw/GA8gkX7K7lr3j xTznSWyE7KAoh4LZgD5wLqeT6W9ZvHM+E6dPgpToZC5j32+yTsR3oJUQO8uE gWzhCDgSYhFzdzC7h0WkdFbHauiUNuQpvWiTcb2IDSfC/wEpV4CpB3jjcEPY wf5jRxcBOCM=";
      let blockchainBindingCertificate;

      beforeEach(() => {
        blockchainBindingCertificate = {
          certificate: [
            {
              _: cerB64,
            },
          ],
          signature: [
            { $: { signedAt: "2023-10-31T21:10:30+00:00" }, _: sigB64 },
          ],
        };
      });

      it("should return true when hash is valid in the blockchain->binding", () => {
        doc.tracked = true;
        doc.blockchainBinding = blockchainBindingCertificate;
        doc.isSimpleTrackedDocument = () => true;

        const result = doc.validHashInBlockchainBinding(
          [{ cer_hex: b64toHex(cerB64) }],
          "8reEBQPpXpC9koGmHgzypHd8D22zHHMX9o|Nombre de tu empresa"
        );

        expect(result).to.be.true;
      });

      it("should return error when it's not tracked", () => {
        doc.tracked = false;

        expect(() => doc.validHashInBlockchainBinding([], "hash")).to.throw(
          Error,
          "Document is not tracked"
        );
      });
    });

    describe(".getStatusTrackedDocument", () => {
      it("should return 'error' when asset is not valid", () => {
        doc.tracked = true;
        doc.isValidAssetId = () => ({ isValid: false });

        const result = doc.getStatusTrackedDocument([]);
        expect(result).to.be.equal("error");
      });

      it("should return 'updated' when the blockchain has the same number of transfers as the XML", () => {
        doc.tracked = true;
        doc.isValidAssetId = () => ({ isValid: true });
        doc.transfersXml = ["one"];
        doc.blockchainTrack = { transfers: ["one"] };

        const result = doc.getStatusTrackedDocument([]);
        expect(result).to.be.equal("updated");
      });

      it("should return 'no_updated' when the blockchain has the different number of transfers as the XML", () => {
        doc.tracked = true;
        doc.isValidAssetId = () => ({ isValid: true });
        doc.transfersXml = ["one"];
        doc.blockchainTrack = { transfers: ["one", "two"] };

        const result = doc.getStatusTrackedDocument([]);
        expect(result).to.be.equal("not_updated");
      });

      it("should return error when it's not tracked", () => {
        doc.tracked = false;

        expect(() => doc.getStatusTrackedDocument([])).to.throw(
          Error,
          "Document is not tracked"
        );
      });
    });

    describe(".isValidAssetId", () => {
      const blockchainBinding = {
        signature: [
          {
            $: {
              plaintext:
                "5ddad7ccfda1c16741f479bc25a37c4d696cde4bf460ee159c62ca9770f85d36|e987478ae6567604b3904c2432dc114bcb69a4c9b212538d58f7d0a867746005|Gu3drgeBxaY7STyY8QsqJqVapHZv3avWDY",
            },
          },
        ],
      };

      it("should return {isValid:true} when asset in blockchain->binding is valid", () => {
        doc.tracked = true;
        doc.blockchainTrack = [];
        doc.blockchainBinding = blockchainBinding;
        doc.assetId =
          "e987478ae6567604b3904c2432dc114bcb69a4c9b212538d58f7d0a867746005";
        doc.validHashInBlockchainBinding = () => true;
        const result = doc.isValidAssetId([]);

        expect(result).to.deep.equal({ isValid: true });
      });

      it("should return {isValid:false, error_code:'integrity'} when asset in blockchain->binding is valid but assetId is different than plaintext", () => {
        doc.tracked = true;
        doc.blockchainTrack = [];
        doc.blockchainBinding = blockchainBinding;
        doc.assetId = "some";
        doc.validHashInBlockchainBinding = () => true;
        const result = doc.isValidAssetId([]);

        expect(result).to.deep.equal({
          isValid: false,
          error_code: "integrity",
        });
      });

      it("should return {isValid:false, error_code:'not_found'} when asset in blockchain->binding is valid but blockchainTrack is null", () => {
        doc.tracked = true;
        doc.blockchainTrack = null;
        doc.blockchainBinding = blockchainBinding;
        doc.assetId =
          "e987478ae6567604b3904c2432dc114bcb69a4c9b212538d58f7d0a867746005";
        doc.validHashInBlockchainBinding = () => true;
        const result = doc.isValidAssetId([]);

        expect(result).to.deep.equal({
          isValid: false,
          error_code: "not_found",
        });
      });

      it("should return error when it's not tracked", () => {
        doc.tracked = false;

        expect(() => doc.isValidAssetId([])).to.throw(
          Error,
          "Document is not tracked"
        );
      });
    });
  });

  describe("fromXml v0.0.1+", function () {
    describe("with valid xml", function () {
      const originalHash =
        "73c818b60eea60e6c1a1e5688a37" + "3c6b8376ca4ea2ff269695fe6eeef134b3c8";
      let doc;
      let parsedOHash;
      let xmlInstance: XML;
      beforeEach(function (done) {
        const xmlExample = `${__dirname}/fixtures/example_signed_cr.xml`;
        const xml = fs.readFileSync(xmlExample, "utf8");
        const parsedP = Document.fromXml(xml);
        parsedP.then(
          function (parsed) {
            xmlInstance = parsed.xml;
            doc = parsed.document;
            parsedOHash = parsed.xmlOriginalHash;
            done();
          },
          function (err) {
            console.log("Error", err.stack);
            done();
          }
        );
      });

      it("should parse the xml", function () {
        const xmlSigners = doc.signers;
        const signer = xmlSigners[0];

        expect(xmlInstance).not.to.be.empty;
        expect(doc).to.be.an.instanceof(Document);
        expect(doc.pdfBuffer()).not.to.be.null;
        expect(doc.pdf()).not.to.be.null;
        expect(doc.originalHash).to.equal(originalHash);
        expect(parsedOHash).to.equal(originalHash);
        expect(xmlSigners).not.to.be.empty;
        expect(signer.email).to.equal("genmadrid@gmail.com");
      });

      describe(".signatures", function () {
        it("should have Signature objects", () =>
          expect(doc.signatures()[0]).to.be.an.instanceof(Signature));

        it("should have 1 Signature", () =>
          expect(doc.signatures().length).to.equal(1));
      });

      describe(".validSignatures", () =>
        it("should be true", () => expect(doc.validSignatures()).to.be.true));

      describe(".conservancyRecord.validArchiveHash", () =>
        it("should be true", () =>
          expect(doc.conservancyRecord.validArchiveHash()).to.be.true));
    });
  });

  describe("fromXml v1.0.0+", function () {
    describe("with valid xml", function () {
      const originalHash =
        "73c818b60eea60e6c1a1e5688a37" + "3c6b8376ca4ea2ff269695fe6eeef134b3c8";
      let doc;
      let parsedOHash;
      beforeEach(function (done) {
        const xmlExample = `${__dirname}/fixtures/example_signed_cr-v1.0.0.xml`;
        const xml = fs.readFileSync(xmlExample, "utf8");
        const parsedP = Document.fromXml(xml);
        parsedP.then(
          function (parsed) {
            doc = parsed.document;
            parsedOHash = parsed.xmlOriginalHash;
            done();
          },
          function (err) {
            console.log("Error", err.stack);
            done();
          }
        );
      });

      it("should parse the xml", function () {
        const xmlSigners = doc.signers;
        const signer = xmlSigners[0];

        expect(doc).to.be.an.instanceof(Document);
        expect(doc.pdfBuffer()).not.to.be.null;
        expect(doc.pdf()).not.to.be.null;
        expect(doc.originalHash).to.equal(originalHash);
        expect(parsedOHash).to.equal(originalHash);
        expect(xmlSigners).not.to.be.empty;
        expect(signer.email).to.equal("genmadrid@gmail.com");
      });

      describe(".signatures", function () {
        it("should have Signature objects", () =>
          expect(doc.signatures()[0]).to.be.an.instanceof(Signature));

        it("should have 1 Signature", () =>
          expect(doc.signatures().length).to.eq(1));
      });

      describe(".validSignatures", () =>
        it("should be true", () => expect(doc.validSignatures()).to.be.true));

      describe(".conservancyRecord.validArchiveHash", () =>
        it("should be true", () =>
          expect(doc.conservancyRecord.validArchiveHash()).to.be.true));
    });
  });

  describe("fromXml NOM151-2016", function () {
    describe("with valid xml", function () {
      const originalHash =
        "e1899493f5cea98b4aadece50fb0e" + "08f5523a342cb2925dc50ef604c6d9d7357";
      let doc;
      let parsedOHash;
      beforeEach(function (done) {
        const xmlExample = `${__dirname}/fixtures/NOM151-2016.xml`;
        const xml = fs.readFileSync(xmlExample, "utf8");
        const parsedP = Document.fromXml(xml);
        parsedP.then(
          function (parsed) {
            doc = parsed.document;
            parsedOHash = parsed.xmlOriginalHash;
            done();
          },
          function (err) {
            console.log("Error", err.stack);
            done();
          }
        );
      });

      it("should parse the xml", function () {
        const xmlSigners = doc.signers;
        const signer = xmlSigners[0];

        expect(doc).to.be.an.instanceof(Document);
        expect(doc.pdfBuffer()).not.to.be.null;
        expect(doc.pdf()).not.to.be.null;
        expect(doc.originalHash).to.equal(originalHash);
        expect(parsedOHash).to.equal(originalHash);
        expect(xmlSigners).not.to.be.empty;
        expect(signer.email).to.equal("genmadrid@gmail.com");
      });

      describe(".signatures", function () {
        it("should have Signature objects", () =>
          expect(doc.signatures()[0]).to.be.an.instanceof(Signature));

        it("should have 1 Signature", () =>
          expect(doc.signatures().length).to.equal(1));
      });

      describe(".validSignatures", () => {
        it("should be true", () => expect(doc.validSignatures()).to.be.true);
      });

      describe(".conservancyRecord.validArchiveHash", () => {
        it("should be true", () => {
          expect(doc.conservancyRecord.validArchiveHash()).to.be.true;
        });
      });
    });
  });
});
