import Liquid from "./liquid";

export type Network = "LBTC" | "LTC";

export class Blockchain {
  static init = (network: Network) => {
    switch (network) {
      case "LBTC":
        return new Liquid();

      default:
        throw new Error("Unsupported blockchain");
    }
  };
}
