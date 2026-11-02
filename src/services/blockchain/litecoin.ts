import { createHash } from "crypto";
import ColoredCoinTransaction = require("cc-transaction");
import {
  decode as decodeBase58Check,
  encode as encodeBase58Check,
} from "bs58check";
import { GetBlockchainTrackResult, GetTransfersByTxIdResult } from "./liquid";

export type LitecoinInput = {
  previousTransactionId: string;
  previousOutputIndex: number;
  value: number;
  addresses: string[];
};

export type LitecoinOutput = {
  value: number;
  addresses: string[];
  scriptType?: string;
  scriptHex?: string;
  dataHex?: string;
  spentByTransactionId?: string;
};

export type LitecoinTransaction = {
  transactionId: string;
  inputs: LitecoinInput[];
  outputs: LitecoinOutput[];
  hasMoreOutputs?: boolean;
  blockHeight?: number;
};

type ColoredCoinData = ReturnType<typeof ColoredCoinTransaction.fromHex>;

type ColoredOutput = {
  transaction: LitecoinTransaction;
  outputIndex: number;
};

const ASSET_PREFIX_BY_POLICY = {
  aggregatable: "20ce",
  hybrid: "2102",
  dispersed: "20e4",
};

export default class Litecoin {
  private BASE_URL = "https://api.blockcypher.com/v1/ltc/main";

  useTestnet() {
    // BlockCypher exposes Litecoin mainnet only. Keep the mainnet URL.
  }

  getBlockchainTrack = async (
    asset: string,
    firstHolderAddress?: string,
  ): Promise<GetBlockchainTrackResult | null> => {
    if (!firstHolderAddress) {
      return null;
    }

    const transactionCache = new Map<string, LitecoinTransaction>();
    const issuanceOutput = await this.findIssuanceOutput(
      asset,
      firstHolderAddress,
      transactionCache,
    );
    if (!issuanceOutput) {
      return null;
    }

    const data = await this.getTransfersByTxId(
      asset,
      issuanceOutput.transaction.transactionId,
      issuanceOutput.outputIndex,
      undefined,
      undefined,
      transactionCache,
    );
    const [, ...transfers] = data;

    return {
      asset,
      transfers,
      issuance: {
        transactionId: issuanceOutput.transaction.transactionId,
        outputIndex: issuanceOutput.outputIndex,
        address: firstHolderAddress,
      },
    };
  };

  getTransfersByTxId = async (
    asset: string,
    txid: string,
    outputIndex: number,
    prevAddress?: string,
    prevTxid?: string,
    transactionCache: Map<string, LitecoinTransaction> = new Map(),
  ): Promise<GetTransfersByTxIdResult[]> => {
    const transaction = await this.getTransaction(txid, transactionCache);
    if (!transaction) {
      return [];
    }

    const currentAddress =
      this.readOutputAddress(transaction.outputs[outputIndex]) || prevAddress;
    const spentByTransactionId =
      transaction.outputs[outputIndex]?.spentByTransactionId;

    const currentTransfer: GetTransfersByTxIdResult = {
      currentAddress,
      prevAddress,
      txid,
      prevTxid,
      outputIndex,
      network: "LTC",
    };

    if (!spentByTransactionId) {
      return [currentTransfer];
    }

    const spendingTransaction = await this.getTransaction(
      spentByTransactionId,
      transactionCache,
    );
    if (!spendingTransaction) {
      return [currentTransfer];
    }

    const coloredCoinData = this.readColoredCoinData(spendingTransaction);
    if (!coloredCoinData || coloredCoinData.type !== "transfer") {
      return [currentTransfer];
    }

    const inputIndex = spendingTransaction.inputs.findIndex(
      (input) =>
        input.previousTransactionId === txid &&
        input.previousOutputIndex === outputIndex,
    );
    if (inputIndex === -1) {
      return [currentTransfer];
    }

    const nextOutputIndex = coloredCoinData.payments.find(
      (payment) => payment.input === inputIndex && payment.amount === 1,
    )?.output;

    if (nextOutputIndex === undefined) {
      return [currentTransfer];
    }

    const nextTransfers = await this.getTransfersByTxId(
      asset,
      spendingTransaction.transactionId,
      nextOutputIndex,
      currentAddress,
      txid,
      transactionCache,
    );

    return [currentTransfer, ...nextTransfers];
  };

  private findIssuanceOutput = async (
    assetId: string,
    holderAddress: string,
    transactionCache: Map<string, LitecoinTransaction>,
  ): Promise<ColoredOutput | null> => {
    const addressTransactions =
      await this.getAddressTransactions(holderAddress);
    const candidates: ColoredOutput[] = [];

    for (const addressTransaction of addressTransactions) {
      const transaction = await this.ensureCompleteTransaction(
        addressTransaction,
        transactionCache,
      );
      if (!transaction) {
        continue;
      }

      const coloredCoinData = this.readColoredCoinData(transaction);
      if (
        !coloredCoinData ||
        coloredCoinData.type !== "issuance" ||
        this.deriveAssetId(transaction, coloredCoinData) !== assetId
      ) {
        continue;
      }

      for (const payment of coloredCoinData.payments) {
        if (
          payment.amount === 1 &&
          this.outputMatchesHolder(
            transaction.outputs[payment.output],
            holderAddress,
          )
        ) {
          candidates.push({
            transaction,
            outputIndex: payment.output,
          });
        }
      }
    }

    return candidates.length === 1 ? candidates[0] : null;
  };

  getAddressTransactions = async (
    address: string,
  ): Promise<LitecoinTransaction[]> => {
    const transactions: LitecoinTransaction[] = [];
    let before: number | undefined;

    for (;;) {
      const params = new URLSearchParams({ limit: "50" });
      if (before !== undefined) {
        params.set("before", String(before));
      }

      const response = await fetch(
        `${this.BASE_URL}/addrs/${encodeURIComponent(address)}/full?${params}`,
      );

      if (response.status === 400 || response.status === 404) {
        return transactions;
      }
      if (!response.ok) {
        throw new Error(`Error de red: ${response.status}`);
      }

      const data = await response.json();
      const pageTransactions = (data.txs || []).map(this.normalizeTransaction);
      transactions.push(...pageTransactions);

      if (!data.hasMore || pageTransactions.length === 0) {
        break;
      }

      const confirmedHeights = pageTransactions
        .map((transaction) => transaction.blockHeight)
        .filter((height): height is number => typeof height === "number" && height > 0);

      if (confirmedHeights.length === 0) {
        break;
      }

      const oldestHeight = Math.min(...confirmedHeights);
      if (before !== undefined && oldestHeight >= before) {
        break;
      }
      before = oldestHeight;
    }

    const transactionCache = new Map<string, LitecoinTransaction>();
    const completeTransactions: LitecoinTransaction[] = [];
    for (const transaction of transactions) {
      const completeTransaction = await this.ensureCompleteTransaction(
        transaction,
        transactionCache,
      );
      if (completeTransaction) {
        completeTransactions.push(completeTransaction);
      }
    }

    return completeTransactions;
  };

  private ensureCompleteTransaction = async (
    transaction: LitecoinTransaction,
    transactionCache: Map<string, LitecoinTransaction>,
  ): Promise<LitecoinTransaction | null> => {
    if (!transaction.hasMoreOutputs) {
      this.rememberTransaction(transactionCache, transaction);
      return transaction;
    }

    return this.getTransaction(transaction.transactionId, transactionCache);
  };

  private getTransaction = async (
    transactionId: string,
    transactionCache: Map<string, LitecoinTransaction>,
  ): Promise<LitecoinTransaction | null> => {
    const cachedTransaction = transactionCache.get(transactionId);
    if (cachedTransaction && !cachedTransaction.hasMoreOutputs) {
      return cachedTransaction;
    }

    let nextUrl: string | null =
      `${this.BASE_URL}/txs/${encodeURIComponent(transactionId)}?limit=1000`;
    let baseTransaction: any = null;
    const outputs = [];

    while (nextUrl) {
      const response = await fetch(nextUrl);

      if (response.status === 400 || response.status === 404) {
        return null;
      }
      if (!response.ok) {
        throw new Error(`Error de red: ${response.status}`);
      }

      const data = await response.json();
      if (Array.isArray(data)) {
        outputs.push(...data);
        nextUrl = null;
        continue;
      }

      if (!baseTransaction) {
        baseTransaction = data;
      }
      outputs.push(...(data.outputs || []));
      nextUrl = data.next_outputs || null;
    }

    if (!baseTransaction) {
      return null;
    }

    const transaction = this.normalizeTransaction({
      ...baseTransaction,
      outputs,
      next_outputs: undefined,
    });
    this.rememberTransaction(transactionCache, transaction);
    return transaction;
  };

  private rememberTransaction = (
    transactionCache: Map<string, LitecoinTransaction>,
    transaction: LitecoinTransaction,
  ) => {
    transactionCache.set(transaction.transactionId, transaction);
  };

  private normalizeTransaction = (transaction): LitecoinTransaction => ({
    transactionId: transaction.hash,
    inputs: (transaction.inputs || []).map((input) => ({
      previousTransactionId: input.prev_hash,
      previousOutputIndex: input.output_index,
      value: input.output_value,
      addresses: input.addresses || [],
    })),
    outputs: (transaction.outputs || []).map((output) => ({
      value: output.value,
      addresses: output.addresses || [],
      scriptType: output.script_type,
      scriptHex: output.script,
      dataHex: output.data_hex,
      spentByTransactionId: output.spent_by,
    })),
    hasMoreOutputs: Boolean(transaction.next_outputs),
    blockHeight: transaction.block_height,
  });

  private readColoredCoinData = (
    transaction: LitecoinTransaction,
  ): ColoredCoinData | null => {
    const dataHex = transaction.outputs.find(({ dataHex }) =>
      dataHex?.toLowerCase().startsWith("4343"),
    )?.dataHex;

    if (!dataHex) {
      return null;
    }

    try {
      return ColoredCoinTransaction.fromHex(Buffer.from(dataHex, "hex"));
    } catch (_error) {
      return null;
    }
  };

  private deriveAssetId = (
    transaction: LitecoinTransaction,
    coloredCoinData: ColoredCoinData,
  ): string | null => {
    const firstInput = transaction.inputs[0];
    const prefix = ASSET_PREFIX_BY_POLICY[coloredCoinData.aggregationPolicy];

    if (
      !coloredCoinData.lockStatus ||
      !firstInput ||
      !prefix ||
      coloredCoinData.divisibility === undefined
    ) {
      return null;
    }

    const assetSeed = `${firstInput.previousTransactionId}:${firstInput.previousOutputIndex}`;
    const hash160 = createHash("ripemd160")
      .update(createHash("sha256").update(assetSeed).digest())
      .digest();
    const divisibility = Buffer.alloc(2);
    divisibility.writeUInt16BE(coloredCoinData.divisibility);

    return encodeBase58Check(
      Buffer.concat([Buffer.from(prefix, "hex"), hash160, divisibility]),
    );
  };

  private outputMatchesHolder = (
    output: LitecoinOutput,
    holderAddress: string,
  ): boolean => {
    if (!output) {
      return false;
    }
    if (output.addresses.includes(holderAddress)) {
      return true;
    }

    const coloredAddressHash = this.readColoredAddressHash(holderAddress);
    return Boolean(
      coloredAddressHash &&
      output.scriptHex?.toLowerCase().includes(coloredAddressHash),
    );
  };

  private readOutputAddress = (output?: LitecoinOutput): string | undefined =>
    output?.addresses?.[0];

  private readColoredAddressHash = (address: string): string | null => {
    try {
      const payload = decodeBase58Check(address);
      if (payload.length !== 21 || payload[0] !== 0x13) {
        return null;
      }

      return payload.subarray(1).toString("hex");
    } catch (_error) {
      return null;
    }
  };
}
