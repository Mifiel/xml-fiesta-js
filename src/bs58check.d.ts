declare module "bs58check" {
  export function encode(payload: Buffer): string;
  export function decode(value: string): Buffer;
}
