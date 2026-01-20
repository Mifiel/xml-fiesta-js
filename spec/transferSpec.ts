import { expect } from "chai";
import Transfer from "../src/transfer";
import { b64toHex } from "../src/common";

describe("Transfer", () => {
  const xmlMock = { file: () => "file" };
  const transferData = {
    prevAddress: "a12344567890",
    currentAddress: "b987654321",
    dataBlockchain: {
      prevAddress: "a12344567890",
      currentAddress: "b987654321",
    },
  };
  const cerB64 =
    "MIIDiDCCAnCgAwIBAgIUMjAwMDEwMDAwMDAyMDAwNDkxNDMwDQYJKoZIhvcN AQEFBQAwMjELMAkGA1UEBhMCTlgxDzANBgNVBAoMBk1pZmllbDESMBAGA1UE AwwJTWlmaWVsIENBMB4XDTIyMDMwNDE5MjQxNVoXDTI0MDMwMzE5MjQxNVow gZYxDzANBgNVBAMMBk1pZmllbDEPMA0GA1UEKQwGTWlmaWVsMQ8wDQYDVQQK DAZNaWZpZWwxCzAJBgNVBAYTAk1YMSMwIQYJKoZIhvcNAQkBFhRzaW1wbGVz aWdAbWlmaWVsLmNvbTESMBAGA1UELQwJTUlGSUVMUkZDMRswGQYDVQQFExJI RUdUNzYxMDAzTURGTlNSMDgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK AoIBAQC2ZbXPoqA9wZNrlAgnXsTg4Dhi6bcKgA04LrtL7o80J84C/ILggvZU Y/bMGLs7Z9LVdsEjKqA1zPc44REIDE1jal/FUYNjd/hQeLDE+oE2aD5JlN4g AZokOE6b6Wc+VFnoY9tQ8Ur8RA07a2Mdd2fDhBjTNwSKOrktYdPnqrMOPfzI 1FgHzmq3HgoCp7YSFEKyR5WaqEkq4tLD2wGeGnF0JHsVk6ePkxm4A6vFLIyo 5JXp1oJKWmglux4tITtT2R7BHRocIkv4FJlHUlHFQ6cAKhaLLhnoz/s/VTkW TKT1z2AK0CaZxvnF8YpbuMTSo6hVhkyXOdd0BOh3YmxISzG/AgMBAAGjMTAv MA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUpNxvPqm43Li6GjSsyJpDDsAU AkUwDQYJKoZIhvcNAQEFBQADggEBAL4lvnNTHDXsAb6Qqg72SivT8CJSLOnQ 1Q389PvnbWg33tmiJ5Aoo92cqnnhr6SeGwZz+44V9W6z+vN1/G1PrYd+WUvk r2BqUwlQmrssgFq8FfjALMYOXCdzeqwl0i9OPV1atNSSXShyvmc4+Isqaveo QLnAA+GySLO4jxc2i+TMVv9kYXGZcN+P7PzaCnqgVqm5kw/GA8gkX7K7lr3j xTznSWyE7KAoh4LZgD5wLqeT6W9ZvHM+E6dPgpToZC5j32+yTsR3oJUQO8uE gWzhCDgSYhFzdzC7h0WkdFbHauiUNuQpvWiTcb2IDSfC/wEpV4CpB3jjcEPY wf5jRxcBOCM=";
  const cerHex = b64toHex(cerB64);
  const holder = {
    $: { name: "Nombre de tu empresa" },
    binding: [
      {
        signature: [
          {
            $: {
              plaintext:
                "8reEBQPpXpC9koGmHgzypHd8D22zHHMX9o|Nombre de tu empresa",
              signedAt: "2023-10-31T21:10:30+00:00",
            },
            _: "pC/+NvlV5Wsr9Mg4T7EUq/qEx7T0PUb+fz6c13kUziuH2N9BrCRpD/C7JPMU pcoVab3wnbBXCSnUYUXcG95k88zHqz0uBv9nzvh+AGZTzCPyxiiLDZtsuYjs Q6GN/O6g95Ngm4Q/UHVSoS2Sr+VhTRgEnweeffC1nSZU5q5cVd8DkrUNr2ek mtA8dgR+6Vt6LSnjqdQWISfHB2o34E3dI/QuQg+18OOGY6OZZw+jAVQ9m6WU Uxwateton07AaNVFTOOBPKCHcrAqfcvarv/guhxVTmHM/JKb2MpydkBiAvEd cGZaKmV0tK5ptMkVogAy1HkEkG9TgmI0/8qnmAVNlw==",
          },
        ],
        certificate: [
          {
            _: cerB64,
          },
        ],
      },
    ],
  };

  const rootCertificates = [
    {
      cer_hex: cerHex,
    },
  ];

  describe("constructor", () => {
    it("should set prevAddress, currentAddress, and dataBlockchain", () => {
      const transfer = new Transfer(
        xmlMock,
        { options: "options" },
        transferData
      );
      expect(transfer.prevAddress).to.equal(transferData.prevAddress);
      expect(transfer.currentAddress).to.equal(transferData.currentAddress);
      expect(transfer.dataBlockchain).to.equal(transferData.dataBlockchain);
    });
  });

  describe("validEndorser", () => {
    it("should return valid result for a valid endorser", () => {
      const transfer = new Transfer(
        xmlMock,
        { options: "options" },
        transferData
      );
      transfer.prevHolder = holder;

      const result = transfer.validEndorser(rootCertificates);

      expect(result.isValid).to.be.true;
    });

    it("should return integrity error for an endorser modified", () => {
      const transfer = new Transfer(
        xmlMock,
        { options: "options" },
        transferData
      );

      transfer.prevHolder = {
        ...holder,
        binding: [
          {
            ...holder.binding[0],
            signature: [
              {
                ...holder.binding[0].signature[0],
                $: {
                  ...holder.binding[0].signature[0].$,
                  plaintext: "8reEBQPpXpC9koGmHgzypHd8D22zHHMX9o|Modified",
                },
              },
            ],
          },
        ],
      };

      const result = transfer.validEndorser(rootCertificates);
      expect(result.isValid).to.be.false;
      expect(result.error_code).to.equal("integrity");
    });

    it("should return inconsistent_with_blockchain error when blockchain data is diferent than xml", () => {
      const transfer = new Transfer(
        xmlMock,
        { options: "options" },
        {
          ...transferData,
          dataBlockchain: {
            ...transferData.dataBlockchain,
            prevAddress: "some",
          },
        }
      );
      transfer.prevHolder = holder;

      const result = transfer.validEndorser(rootCertificates);
      expect(result.isValid).to.be.false;
      expect(result.error_code).to.equal("inconsistent_with_blockchain");
    });
  });

  describe("validEndorsee", () => {
    it("should return valid result for a valid endorsee", () => {
      const transfer = new Transfer(
        xmlMock,
        { options: "options" },
        transferData
      );
      transfer.currentHolder = holder;

      const result = transfer.validEndorsee(rootCertificates);

      expect(result.isValid).to.be.true;
    });

    it("should return integrity error for an endorsee modified", () => {
      const transfer = new Transfer(
        xmlMock,
        { options: "options" },
        transferData
      );

      transfer.currentHolder = {
        ...holder,
        binding: [
          {
            ...holder.binding[0],
            signature: [
              {
                ...holder.binding[0].signature[0],
                $: {
                  ...holder.binding[0].signature[0].$,
                  plaintext: "8reEBQPpXpC9koGmHgzypHd8D22zHHMX9o|Modified",
                },
              },
            ],
          },
        ],
      };

      const result = transfer.validEndorsee(rootCertificates);
      expect(result.isValid).to.be.false;
      expect(result.error_code).to.equal("integrity");
    });

    it("should return inconsistent_with_blockchain error when blockchain data is different than xml", () => {
      const transfer = new Transfer(
        xmlMock,
        { options: "options" },
        {
          ...transferData,
          dataBlockchain: {
            ...transferData.dataBlockchain,
            currentAddress: "some",
          },
        }
      );
      transfer.currentHolder = holder;

      const result = transfer.validEndorsee(rootCertificates);
      expect(result.isValid).to.be.false;
      expect(result.error_code).to.equal("inconsistent_with_blockchain");
    });
  });
});
