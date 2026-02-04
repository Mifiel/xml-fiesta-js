const fs = require("fs");
import { expect } from "chai";
import Certificate from "../src/certificate";

const intermediate = fs
  .readFileSync(`${__dirname}/../docs/AC2_Sat.crt`)
  .toString();
const cert = fs
  .readFileSync(`${__dirname}/fixtures/production-certificate.pem`)
  .toString();

describe("Basic certificate validation", () =>
  it("should be true", function () {
    const pemHex = Buffer.from(cert, "utf8").toString("hex");
    const certificate = new Certificate(null, pemHex);
    expect(certificate.validParent(intermediate)).to.be.true;
  }));
