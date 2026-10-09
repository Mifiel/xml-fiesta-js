import Certificate from "./certificate";
import { ArgumentError } from "./errors";

export type OcspOutcome =
  | "valid"
  | "outside-validity"
  | "absent"
  | "undecodable";

export interface OcspValidationResult {
  outcome: OcspOutcome;
  isValid: boolean;
  producedAt?: string;
  signedAt?: string;
  certNotBefore?: string;
  certNotAfter?: string;
  reason?: string;
}

export interface OcspTimesInput {
  /** Signer certificate DER hex (provides the validity window). */
  signerCertHex: string;
  /**
   * When the revocation check was produced — the `revocation-status-checked`
   * auditTrail event `@timestamp` (see extractOcspProducedAt). Absent when
   * the signer carries no revocation evidence.
   */
  producedAt?: string | Date | null;
  /** Signature @signedAt value (ISO 8601) or Date. */
  signedAt: string | Date;
}

function signerEvents(signer: any): any[] {
  if (!signer || typeof signer !== "object") {
    return [];
  }
  const events: any[] =
    (signer.auditTrail &&
      signer.auditTrail[0] &&
      signer.auditTrail[0].event) ||
    signer.event ||
    [];

  return Array.isArray(events) ? events : [];
}

function revocationCheckedEvents(signer: any): any[] {
  return signerEvents(signer).filter(
    (event: any) =>
      event && event.$ && event.$.name === "revocation-status-checked",
  );
}

/**
 * Extracts the `@timestamp` of the signer's `revocation-status-checked`
 * auditTrail event — the moment the revocation check was produced.
 * Returns null when the signer carries no such event.
 */
export function extractOcspProducedAt(signer: any): string | null {
  for (const event of revocationCheckedEvents(signer)) {
    if (event && event.$ && typeof event.$.timestamp === "string") {
      return event.$.timestamp;
    }
  }

  return null;
}

function parseDate(value: string | Date, what: string): Date {
  const date: Date = value instanceof Date ? value : new Date(value);
  if (isNaN(date.getTime())) {
    throw new ArgumentError(`${what} is not a valid date: "${value}"`);
  }

  return date;
}

/**
 * Verifies that both the revocation-check time (producedAt) and the
 * signature time (signedAt) fall within the signer certificate validity
 * window. Never throws for domain-level outcomes: missing evidence,
 * undecodable inputs and window violations are returned as distinct
 * non-passing outcomes.
 */
export function validateOcspTimes(input: OcspTimesInput): OcspValidationResult {
  let signerCertificate: Certificate;
  try {
    signerCertificate = new Certificate(null, input.signerCertHex);
  } catch (error) {
    return {
      outcome: "undecodable",
      isValid: false,
      reason: `signer certificate is not valid: ${(error as Error).message}`,
    };
  }
  const notBefore: Date = signerCertificate.getX509().validity.notBefore;
  const notAfter: Date = signerCertificate.getX509().validity.notAfter;

  if (input.producedAt == null) {
    return {
      outcome: "absent",
      isValid: false,
      reason: "signer has no revocation-status-checked evidence in its auditTrail",
    };
  }

  let producedAt: Date;
  let signedAt: Date;
  try {
    producedAt = parseDate(input.producedAt, "OCSP producedAt");
    signedAt = parseDate(input.signedAt, "signature signedAt");
  } catch (error) {
    return {
      outcome: "undecodable",
      isValid: false,
      reason: (error as Error).message,
    };
  }

  const withinWindow = (date: Date): boolean =>
    date.getTime() >= notBefore.getTime() &&
    date.getTime() <= notAfter.getTime();
  if (!withinWindow(producedAt) || !withinWindow(signedAt)) {
    return {
      outcome: "outside-validity",
      isValid: false,
      producedAt: producedAt.toISOString(),
      signedAt: signedAt.toISOString(),
      certNotBefore: notBefore.toISOString(),
      certNotAfter: notAfter.toISOString(),
      reason:
        "OCSP producedAt and signature signedAt must both fall within " +
        "the signer certificate validity window",
    };
  }

  return {
    outcome: "valid",
    isValid: true,
    producedAt: producedAt.toISOString(),
    signedAt: signedAt.toISOString(),
    certNotBefore: notBefore.toISOString(),
    certNotAfter: notAfter.toISOString(),
  };
}
