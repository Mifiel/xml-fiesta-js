import { expect } from "chai";
import { parseDate } from "../src/common";

describe("parseDate", () => {
  it("parses Advantage GeneralizedTime with fractions", () => {
    expect(parseDate("20180809203832.930Z").toISOString()).to.equal(
      "2018-08-09T20:38:32.000Z",
    );
  });

  it("parses Advantage UTCTime with fractions", () => {
    expect(parseDate("180809203832.930Z").toISOString()).to.equal(
      "2018-08-09T20:38:32.000Z",
    );
  });

  it("parses OpenSSL GeneralizedTime without fractions", () => {
    expect(parseDate("20260831120000Z").toISOString()).to.equal(
      "2026-08-31T12:00:00.000Z",
    );
  });

  it("parses OpenSSL UTCTime without fractions", () => {
    expect(parseDate("260831120000Z").toISOString()).to.equal(
      "2026-08-31T12:00:00.000Z",
    );
  });
});
