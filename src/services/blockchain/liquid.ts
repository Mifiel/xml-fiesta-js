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
  network?: "LTC" | "LBTC";
};

export type GetBlockchainTrackResult = {
  asset: string;
  transfers: GetTransfersByTxIdResult[]
};

export type LiquidAsset = {
  issuanceTransactionId: string;
  issuedAmount: number;
};

export type LiquidTransactionOutput = {
  address?: string;
  assetId: string;
  value: number;
};

export type LiquidTransaction = {
  transactionId: string;
  outputs: LiquidTransactionOutput[];
};

export default class Liquid {
  private BASE_URL = "https://blockstream.info/liquid/api";

  useTestnet() {
    this.BASE_URL = "https://blockstream.info/liquidtestnet/api";
  }

  getAsset = async (assetId: string): Promise<LiquidAsset | null> => {
    const response = await fetch(
      `${this.BASE_URL}/asset/${encodeURIComponent(assetId)}`,
    );

    if (response.status === 404 || response.status === 400) {
      return null;
    }
    if (!response.ok) {
      throw new Error(`Error de red: ${response.status}`);
    }

    const data = await response.json();
    return {
      issuanceTransactionId: data.issuance_txin.txid,
      issuedAmount: data.chain_stats.issued_amount,
    };
  };

  getTransaction = async (
    transactionId: string,
  ): Promise<LiquidTransaction | null> => {
    const response = await fetch(
      `${this.BASE_URL}/tx/${encodeURIComponent(transactionId)}`,
    );

    if (response.status === 404 || response.status === 400) {
      return null;
    }
    if (!response.ok) {
      throw new Error(`Error de red: ${response.status}`);
    }

    const data = await response.json();
    return {
      transactionId: data.txid,
      outputs: (data.vout || []).map((output) => ({
        address: output.scriptpubkey_address,
        assetId: output.asset,
        value: output.value,
      })),
    };
  };

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

    const currentTransfer: GetTransfersByTxIdResult = {
      currentAddress,
      prevAddress,
      txid,
      prevTxid,
      network: "LBTC",
    };

    if (!currentOutspends.spent) {
      return [currentTransfer];
    } else {
      const transfers = await this.getTransfersByTxId(
        asset,
        currentOutspends.txid,
        currentAddress,
        txid
      );
      return [currentTransfer, ...transfers];
    }
  };

  getBlockchainTrack = async (
    asset: string,
    _firstHolderAddress?: string,
  ): Promise<GetBlockchainTrackResult | null> => {
    const liquidAsset = await this.getAsset(asset);
    if (!liquidAsset) {
      return null;
    }

    const data = await this.getTransfersByTxId(
      asset,
      liquidAsset.issuanceTransactionId,
    );
    // @ts-ignore
    const [_, ...transfers] = data;

    return {
      asset,
      transfers,
    };
  };
}