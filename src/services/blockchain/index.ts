import Liquid from "./liquid";

type Network = 'LBTC'

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

