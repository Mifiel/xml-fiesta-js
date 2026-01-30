import { CertificateError } from "./errors";
import { hextoAscii } from "./common";
import { ASN1HEX } from "./asn1hex";
import * as forge from "node-forge";

function isRsaPublicKey(
  key: forge.pki.PublicKey,
): key is forge.pki.rsa.PublicKey {
  return (
    typeof (key as forge.pki.rsa.PublicKey).verify === "function" &&
    typeof (key as forge.pki.rsa.PublicKey).n?.bitLength === "function"
  );
}

// OIDs not in forge; register so subject.attributes get a friendly name/shortName.
// 2.5.4.41 = name (X.520); 2.5.4.45 = unstructuredIdentifier (SAT/FIEL "UI").
if (!forge.pki.oids["2.5.4.41"]) forge.pki.oids["2.5.4.41"] = "name";
if (!forge.pki.oids["2.5.4.45"])
  forge.pki.oids["2.5.4.45"] = "unstructuredIdentifier";

/** Resolves subject key from forge shortName/name for API compatibility. Checks both for robustness. */
function resolveSubjectKey(
  shortName: string | undefined,
  name: string | undefined,
): string | null {
  const s = shortName ?? "";
  const n = name ?? "";
  if (n === "givenName" || s === "GN") return "name";
  if (n === "streetAddress" || s === "street") return "street";
  if (n === "unstructuredIdentifier" || s === "UI") return "UI";
  return null;
}

/** Derives "SHA256withRSA" style string from forge.pki.oids[signatureOid] (e.g. sha256WithRSAEncryption). */
function signatureOidToAlg(oid: string): string {
  const name = forge.pki.oids[oid];
  if (!name || typeof name !== "string") return "SHA256withRSA";
  const m = name.match(/^(.+?)WithRSA(?:Encryption|Signature)?$/i);
  if (!m) return "SHA256withRSA";
  const hash = m[1].toUpperCase();
  return `${hash}withRSA`;
}

function bytesToHex(bytes: string) {
  return forge.util.bytesToHex(bytes);
}

function derHexToPem(hex: string, label: string) {
  const b64 = Buffer.from(hex, "hex").toString("base64");
  const wrapped = b64.replace(/(.{64})/g, "$1\r\n").trim();
  return `-----BEGIN ${label}-----\r\n${wrapped}\r\n-----END ${label}-----\r\n`;
}

function mdForAlg(alg: string) {
  switch (alg) {
    case "SHA1withRSA":
      return forge.md.sha1.create();
    case "SHA384withRSA":
      return forge.md.sha384.create();
    case "SHA512withRSA":
      return forge.md.sha512.create();
    case "SHA256withRSA":
    default:
      return forge.md.sha256.create();
  }
}

function normalizeRsaSignatureBytes(
  publicKey: forge.pki.rsa.PublicKey,
  signatureBytes: string,
) {
  try {
    const bits = publicKey.n.bitLength();
    const keyBytes = Math.ceil(bits / 8);
    let sig = signatureBytes;
    while (sig.length > keyBytes && sig.charCodeAt(0) === 0x00) {
      sig = sig.slice(1);
    }
    return sig;
  } catch {
    return signatureBytes;
  }
}

function isExpectedRsaVerifyError(error: Error) {
  const msg = String(error?.message || "");
  // node-forge throws for invalid PKCS#1 v1.5 padding/signature.
  return (
    msg.includes("Encryption block is invalid") ||
    msg.includes("Encrypted message length is invalid")
  );
}

const certFirstBytes =
  "2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494";

export default class Certificate {
  binaryString: string | null;
  pem: string;
  certificate: forge.pki.Certificate;
  subject: Record<string, string>;
  hex: string;
  pubKey: forge.pki.rsa.PublicKey | null;

  constructor(binaryString: string | null, hexString?: string) {
    let hex = binaryString
      ? Buffer.from(binaryString).toString("hex")
      : hexString;

    this.binaryString = binaryString;
    this.pubKey = null;

    if (
      (!binaryString && !hex) ||
      (binaryString && binaryString.length === 0) ||
      (hex && !ASN1HEX.isASN1HEX(hex) && !hex.startsWith(certFirstBytes))
    ) {
      throw new CertificateError("The certificate is not valid.");
    }

    if (hex.startsWith(certFirstBytes)) {
      this.pem = Buffer.from(hex, "hex").toString("utf8");
    } else {
      this.pem = derHexToPem(hex, "CERTIFICATE");
    }

    this.certificate = forge.pki.certificateFromPem(this.pem);

    // Keep the original hex when it was provided as DER hex. When PEM-in-hex
    // is provided, compute DER hex from the parsed certificate.
    if (hex.startsWith(certFirstBytes)) {
      const asn1 = forge.pki.certificateToAsn1(this.certificate);
      this.hex = bytesToHex(forge.asn1.toDer(asn1).getBytes());
    } else {
      this.hex = hex.toLowerCase();
    }

    this.subject = this.buildSubjectObject();
  }

  toBinaryString() {
    return this.binaryString;
  }

  toHex() {
    return this.hex;
  }

  toPem() {
    return this.pem;
  }

  getX509() {
    return this.certificate;
  }

  getSerialNumberHex() {
    let serial = (this.certificate && this.certificate.serialNumber) || "";
    serial = String(serial).toLowerCase();
    if (serial.length % 2 === 1) serial = `0${serial}`;
    return serial;
  }

  getSerialNumber() {
    return hextoAscii(this.getSerialNumberHex());
  }

  getSubject() {
    return this.subject;
  }

  /** Returns subject email (E = emailAddress in X.500). */
  email() {
    return this.subject.E;
  }

  owner() {
    return this.subject.name;
  }

  owner_id() {
    const identifier = this.getUniqueIdentifier();
    return identifier?.[0];
  }

  getUniqueIdentifier() {
    if (this.subject.UI) {
      return this.subject.UI.split(" / ");
    } else {
      return null;
    }
  }

  getRSAPublicKey() {
    if (this.pubKey) {
      return this.pubKey;
    }
    const pk = this.certificate.publicKey;
    if (!isRsaPublicKey(pk)) {
      throw new CertificateError("The certificate public key is not RSA.");
    }
    return (this.pubKey = pk);
  }

  verifyString(string: string, signedHexString: string, alg?: string) {
    try {
      if (alg == null) {
        alg = "SHA256withRSA";
      }
      const md = mdForAlg(alg);
      md.update(string, "utf8");
      let signatureBytes = forge.util.hexToBytes(signedHexString);
      const pk = this.getRSAPublicKey();
      signatureBytes = normalizeRsaSignatureBytes(pk, signatureBytes);
      return pk.verify(md.digest().getBytes(), signatureBytes);
    } catch (error) {
      if (!isExpectedRsaVerifyError(error)) {
        console.error(error);
      }
      return false;
    }
  }

  verifyHexString(hexString: string, signedHexString: string, alg?: string) {
    try {
      if (alg == null) {
        alg = "SHA256withRSA";
      }
      const md = mdForAlg(alg);
      md.update(forge.util.hexToBytes(hexString));
      let signatureBytes = forge.util.hexToBytes(signedHexString);
      const pk = this.getRSAPublicKey();
      signatureBytes = normalizeRsaSignatureBytes(pk, signatureBytes);
      return pk.verify(md.digest().getBytes(), signatureBytes);
    } catch (error) {
      if (!isExpectedRsaVerifyError(error)) {
        console.error(error);
      }
      return false;
    }
  }

  getUniqueIdentifierString(joinVal) {
    joinVal = joinVal ? joinVal : ", ";
    const identifiers = this.getUniqueIdentifier();
    return identifiers.join(joinVal);
  }

  hasExpired() {
    const notAfter: Date = this.certificate.validity.notAfter;
    const isExpired = notAfter.getTime() < new Date().getTime();

    if (isExpired) {
      console.error("Certificate: The certificate has expired", {
        notAfter: notAfter.toISOString(),
        currentTime: new Date().toISOString(),
      });
    }

    return isExpired;
  }

  isValidOn(date) {
    const notAfter: Date = this.certificate.validity.notAfter;
    const notBefore: Date = this.certificate.validity.notBefore;

    const isValid =
      notAfter.getTime() >= date.getTime() &&
      date.getTime() >= notBefore.getTime();

    if (!isValid) {
      console.error(
        "Certificate: The certificate is not valid on the given date",
        {
          notAfter: notAfter.toISOString(),
          notBefore: notBefore.toISOString(),
          givenDate: date.toISOString(),
        },
      );
    }

    return isValid;
  }

  algorithm() {
    const oid =
      this.certificate.signatureOid || this.certificate.siginfo?.algorithmOid;
    return signatureOidToAlg(String(oid));
  }

  tbsCertificate() {
    // 1st child of SEQ is tbsCert
    return ASN1HEX.getDecendantHexTLVByNthList(this.hex, 0, [0]);
  }

  signature() {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
    const children = ASN1HEX.getPosArrayOfChildren_AtObj(this.hex, 0);
    // X.509 requires exactly 3 elements; fewer means invalid certificate structure.
    if (children.length < 3) {
      throw new Error("Invalid X.509 certificate structure");
    }
    // Third child is signatureValue (BIT STRING); get its value in hex.
    const bitStringV = ASN1HEX.getHexOfV_AtObj(this.hex, children[2]);
    // BIT STRING value starts with one "unused bits" byte (0x00 = 0 unused bits); strip it to get raw signature hex.
    return bitStringV.startsWith("00") ? bitStringV.slice(2) : bitStringV;
  }

  isCa(rootCaHex) {
    return this.hex === rootCaHex;
  }

  validParent(rootCaPem, rootCaHex = null) {
    try {
      let rootCaCert: Certificate;
      if (rootCaHex) {
        rootCaCert = new Certificate(null, rootCaHex);
      } else {
        const parsed = forge.pki.certificateFromPem(rootCaPem);
        const basic = parsed.getExtension?.("basicConstraints") as
          | { cA?: boolean }
          | undefined;
        const isCa = Boolean(basic?.cA);
        if (!isCa) return false;
        const asn1 = forge.pki.certificateToAsn1(parsed);
        const derHex = bytesToHex(forge.asn1.toDer(asn1).getBytes());
        rootCaCert = new Certificate(null, derHex);
      }

      return rootCaCert.verifyHexString(
        this.tbsCertificate(),
        this.signature(),
        this.algorithm(),
      );
    } catch (error) {
      console.error(error);
      return false;
    }
  }

  private buildSubjectObject(): Record<string, string> {
    const out: Record<string, string> = {};
    const attrs = this.certificate?.subject?.attributes || [];
    for (const attr of attrs) {
      const key =
        resolveSubjectKey(attr.shortName, attr.name) ??
        attr.shortName ??
        attr.name ??
        attr.type;
      out[key] = String(attr.value);
    }
    if (!out.name) {
      out.name = out.O ?? out.CN;
    }
    return out;
  }
}
