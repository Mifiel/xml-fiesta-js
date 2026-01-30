import * as forge from "node-forge";

type Asn1Node = {
  /** Hex string position (0-based, byte-aligned) */
  start: number;
  /** Total node length in bytes (tag + length + value) */
  length: number;
  /** Hex string position where the value starts (0-based, byte-aligned) */
  valueStart: number;
  /** Value length in bytes */
  valueLength: number;
  /** Whether the node is constructed */
  constructed: boolean;
  /** First tag byte (only supports low-tag-number for now) */
  tagByte: number;
};

function assertHexPosition(pos: number) {
  if (!Number.isInteger(pos)) {
    throw new Error("ASN.1 position must be an integer hex index");
  }
  if (pos < 0) {
    throw new Error("ASN.1 position must be >= 0");
  }
  if (pos % 2 !== 0) {
    throw new Error("ASN.1 position must be byte-aligned (even hex index)");
  }
}

function isHexString(hex: string) {
  return (
    typeof hex === "string" &&
    hex.length % 2 === 0 &&
    /^[0-9a-fA-F]*$/.test(hex)
  );
}

function readByte(hex: string, hexPos: number) {
  const b = hex.slice(hexPos, hexPos + 2);
  if (b.length !== 2) {
    throw new Error("Unexpected end of ASN.1 data");
  }
  return parseInt(b, 16);
}

function readLength(
  hex: string,
  atHexPos: number,
): { length: number; bytesRead: number } {
  const first = readByte(hex, atHexPos);
  if ((first & 0x80) === 0) {
    return { length: first, bytesRead: 1 };
  }
  const n = first & 0x7f;
  if (n === 0) {
    throw new Error("Indefinite length is not supported in DER");
  }
  let len = 0;
  for (let i = 0; i < n; i++) {
    len = (len << 8) | readByte(hex, atHexPos + (1 + i) * 2);
  }
  return { length: len, bytesRead: 1 + n };
}

function parseNodeAt(hex: string, startPos: number): Asn1Node {
  if (!isHexString(hex)) {
    throw new Error("Invalid hex string");
  }
  assertHexPosition(startPos);
  const tagByte = readByte(hex, startPos);
  const constructed = (tagByte & 0x20) !== 0;
  const tagNumber = tagByte & 0x1f;
  if (tagNumber === 0x1f) {
    // High-tag-number form not needed for this project’s fixtures; fail loudly.
    throw new Error("High-tag-number form is not supported");
  }

  const { length: valueLength, bytesRead: lenBytes } = readLength(
    hex,
    startPos + 2,
  );
  const headerBytes = 1 + lenBytes;
  const valueStart = startPos + headerBytes * 2;
  const totalLength = headerBytes + valueLength;
  const endPos = startPos + totalLength * 2;

  if (endPos > hex.length) {
    throw new Error("ASN.1 length exceeds input size");
  }

  return {
    start: startPos,
    length: totalLength,
    valueStart,
    valueLength,
    constructed,
    tagByte,
  };
}

function childPositions(hex: string, objPos: number): number[] {
  assertHexPosition(objPos);
  const node = parseNodeAt(hex, objPos);
  if (!node.constructed) {
    // jsrsasign's ASN1HEX helpers are often used on OCTET STRING wrappers that
    // encapsulate another DER TLV (common in CMS/PKCS#7 structures). To keep
    // behavior compatible, expose the embedded TLV as a single "child" when
    // the wrapper contains a well-formed ASN.1 object that spans the full value.
    //
    // OCTET STRING: 0x04 <len> <DER...>
    // BIT STRING:   0x03 <len> <unusedBitsByte> <DER...>
    let candidateStart: number | null = null;
    if (node.tagByte === 0x04) {
      candidateStart = node.valueStart;
    } else if (node.tagByte === 0x03) {
      if (node.valueLength >= 2) candidateStart = node.valueStart + 2;
    }

    if (candidateStart != null) {
      try {
        const embedded = parseNodeAt(hex, candidateStart);
        const wrapperEnd = node.valueStart + node.valueLength * 2;
        const embeddedEnd = embedded.start + embedded.length * 2;
        if (embedded.start === candidateStart && embeddedEnd === wrapperEnd) {
          return [candidateStart];
        }
      } catch {
        // ignore
      }
    }

    return [];
  }
  const out: number[] = [];
  let cursor = node.valueStart;
  const end = node.valueStart + node.valueLength * 2;
  while (cursor < end) {
    const child = parseNodeAt(hex, cursor);
    out.push(child.start);
    cursor = child.start + child.length * 2;
  }
  if (cursor !== end) {
    throw new Error("ASN.1 children do not align with container length");
  }
  return out;
}

function hexOfTLVAt(hex: string, objPos: number): string {
  assertHexPosition(objPos);
  const node = parseNodeAt(hex, objPos);
  const end = node.start + node.length * 2;
  return hex.slice(node.start, end);
}

function hexOfVAt(hex: string, objPos: number): string {
  assertHexPosition(objPos);
  const node = parseNodeAt(hex, objPos);
  const end = node.valueStart + node.valueLength * 2;
  return hex.slice(node.valueStart, end);
}

function descendantPosByNthList(
  hex: string,
  startPos: number,
  nthList: number[],
): number {
  let pos = startPos;
  for (const nth of nthList) {
    const children = childPositions(hex, pos);
    if (nth < 0 || nth >= children.length) {
      throw new Error("ASN.1 descendant index is out of range");
    }
    pos = children[nth];
  }
  return pos;
}

/**
 * Minimal subset of `jsrsasign.ASN1HEX` used by this library.
 * Positions are expressed as hex string indices (0-based), like `jsrsasign`.
 */
export const ASN1HEX = {
  isASN1HEX(hex: string) {
    if (!isHexString(hex)) return false;
    try {
      // Prefer node-forge to validate overall DER structure and ensure the
      // entire input is consumed. If the input is BER (eg. indefinite length),
      // re-encoding to DER will differ and this will correctly return false.
      const bytes = forge.util.hexToBytes(hex);
      const asn1 = forge.asn1.fromDer(bytes);
      const der = forge.asn1.toDer(asn1).getBytes();
      return der.length === bytes.length;
    } catch {
      return false;
    }
  },

  getPosArrayOfChildren_AtObj(hex: string, pos: number) {
    return childPositions(hex, pos);
  },

  getHexOfTLV_AtObj(hex: string, pos: number) {
    return hexOfTLVAt(hex, pos);
  },

  getHexOfV_AtObj(hex: string, pos: number) {
    return hexOfVAt(hex, pos);
  },

  getDecendantHexTLVByNthList(hex: string, pos: number, nthList: number[]) {
    const targetPos = descendantPosByNthList(hex, pos, nthList);
    return hexOfTLVAt(hex, targetPos);
  },

  getDecendantHexVByNthList(hex: string, pos: number, nthList: number[]) {
    const targetPos = descendantPosByNthList(hex, pos, nthList);
    return hexOfVAt(hex, targetPos);
  },
};
