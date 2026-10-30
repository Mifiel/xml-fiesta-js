import Liquid from "./liquid";
import Litecoin from "./litecoin";

export type Network = "LBTC" | "LTC";

export class Blockchain {
  static init = (network: Network) => {
    switch (network) {
      case "LBTC":
        return new Liquid();

      case "LTC":
        return new Litecoin();

      default:
        throw new Error("Unsupported blockchain");
    }
  };
}
