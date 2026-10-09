import { ArgumentError } from "./errors";

export type ParsedVersion = [number, number, number];

/**
 * Parses a dotted version string (e.g. "2.5.0", "2.5") into its numeric
 * components. Missing trailing components default to 0.
 *
 * Throws an ArgumentError for anything that cannot be interpreted as a
 * version instead of silently producing a wrong ordering.
 */
export function parseVersion(version: string): ParsedVersion {
  if (typeof version !== "string") {
    throw new ArgumentError(`version must be a string, got ${typeof version}`);
  }
  const trimmed: string = version.trim();
  if (trimmed.length === 0) {
    throw new ArgumentError("version must not be empty");
  }
  const parts: string[] = trimmed.split(".");
  if (parts.length < 1 || parts.length > 3) {
    throw new ArgumentError(`version has an unexpected shape: "${version}"`);
  }
  const numbers: number[] = parts.map((part: string) => {
    if (!/^\d+$/.test(part)) {
      throw new ArgumentError(`version component is not numeric: "${version}"`);
    }
    const value: number = parseInt(part, 10);
    if (!Number.isSafeInteger(value)) {
      throw new ArgumentError(`version component is out of range: "${version}"`);
    }

    return value;
  });
  while (numbers.length < 3) {
    numbers.push(0);
  }

  return [numbers[0], numbers[1], numbers[2]];
}

function toParsedVersion(version: string | ParsedVersion): ParsedVersion {
  if (Array.isArray(version)) {
    return version;
  }

  return parseVersion(version);
}

/**
 * Total ordering over versions. Returns -1, 0 or 1. Multi-digit
 * components never collide (e.g. "2.4.10" < "2.5.0").
 */
export function compareVersions(
  a: string | ParsedVersion,
  b: string | ParsedVersion,
): -1 | 0 | 1 {
  const left: ParsedVersion = toParsedVersion(a);
  const right: ParsedVersion = toParsedVersion(b);
  for (let index: number = 0; index < 3; index++) {
    if (left[index] < right[index]) {
      return -1;
    }
    if (left[index] > right[index]) {
      return 1;
    }
  }

  return 0;
}

/**
 * Convenience check used by the XML version gates, e.g.
 * `gteVersion(version, "2.5.0")`.
 */
export function gteVersion(
  version: string | ParsedVersion,
  threshold: string | ParsedVersion,
): boolean {
  return compareVersions(version, threshold) >= 0;
}

/**
 * Symmetric counterpart of gteVersion, e.g.
 * `ltVersion(version, "1.0.0")`.
 */
export function ltVersion(
  version: string | ParsedVersion,
  threshold: string | ParsedVersion,
): boolean {
  return compareVersions(version, threshold) < 0;
}
