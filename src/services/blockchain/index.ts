import Liquid from "./liquid";

type BlockchainName = 'LBTC'

export class Blockchain {
  static init = (blockchainName: BlockchainName) => {
    switch (blockchainName) {
      case "LBTC":
        return new Liquid();

      default:
        throw new Error("Unsupported blockchain");
    }
  };
}

