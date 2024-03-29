type GetTxDataResult = {
  index: number;
  address: string
};

type GetTxOutspentsResult = {
  spent: boolean;
  txid: string
};

export type GetTransfersByTxIdResult = {
  prevTxid: string;
  txid: string;
  prevAddress: string;
  currentAddress: string;
};

export type GetBlockchainTrackResult = {
  asset: string;
  transfers: GetTransfersByTxIdResult[]
};

export default class Liquid {
  private BASE_URL = "https://blockstream.info/liquid/api";

  useTestnet() {
    this.BASE_URL = "https://blockstream.info/liquidtestnet/api";
  }

  getTxData = async (txid: string, asset: string): Promise<GetTxDataResult> => {
    const { vout } = await fetch(`${this.BASE_URL}/tx/${txid}`).then(
      (response) => response.json()
    );

    const indextTx = vout.findIndex(
      ({ asset: assetLiquid }) => assetLiquid === asset
    );

    return {
      index: indextTx,
      address: vout[indextTx].scriptpubkey_address,
    };
  };

  getTxtOutspents = async (txid: string): Promise<GetTxOutspentsResult[]> => {
    return fetch(`${this.BASE_URL}/tx/${txid}/outspends`).then((response) =>
      response.json()
    );
  };

  getTransfersByTxId = async (
    asset: string,
    txid: string,
    prevAddress?: string,
    prevTxid?: string,
  ): Promise<GetTransfersByTxIdResult[]> => {
    const { index: indexTx, address: currentAddress } = await this.getTxData(
      txid,
      asset
    );
    const outspends = await this.getTxtOutspents(txid);
    const currentOutspends = outspends[indexTx];

    if (!currentOutspends.spent) {
      return [{ currentAddress, prevAddress, txid, prevTxid }];
    } else {
      const transfers = await this.getTransfersByTxId(
        asset,
        currentOutspends.txid,
        currentAddress,
        txid
      );
      return [{ currentAddress, prevAddress, txid, prevTxid }, ...transfers];
    }
  };

  getBlockchainTrack = async (
    asset: string
  ): Promise<GetBlockchainTrackResult | null> => {
    const response = await fetch(`${this.BASE_URL}/asset/${asset}`);

    if (!response.ok) {
      // 400 = bad request o 404 = not found
      if (response.status === 404 || response.status === 400) {
        return null;
      }

      throw new Error(`Error de red: ${response.status}`);
    }

    const { issuance_txin } = await response.json();
    const { txid } = issuance_txin;

    const data = await this.getTransfersByTxId(asset, txid);
    // @ts-ignore
    const [_, ...transfers] = data;

    return {
      asset,
      transfers,
    };
  };
}