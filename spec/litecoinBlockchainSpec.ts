import { expect } from "chai";
import Litecoin from "../src/services/blockchain/litecoin";
import { Blockchain } from "../src/services/blockchain";

describe("Litecoin blockchain support", () => {
  it("initializes Litecoin from Blockchain.init", () => {
    const instance = Blockchain.init("LTC");
    expect(instance).to.be.instanceOf(Litecoin);
  });

  it("returns null when the first holder address is missing", async () => {
    const litecoin = new Litecoin();
    const track = await litecoin.getBlockchainTrack(
      "La5iUbVivZk1KKwz52dnJicWVzMooRpX255Lq3",
    );
    expect(track).to.equal(null);
  });

  it("builds a transfer track from issuance through colored transfers", async () => {
    const litecoin = new Litecoin();
    const assetId = "La5iUbVivZk1KKwz52dnJicWVzMooRpX255Lq3";
    const firstHolder = "2N5Zo736NRuTybxdfevXDEedvnCKH5jX3AU";
    const secondHolder = "8pAa7iDLdba1Bm8dxgypJoRS1smJqqW2UV";
    const issuanceTxid =
      "5d2fd172e985e3532987f543940af9dd73f35eac3840d36709a5ed022c38cae2";
    const transferTxid =
      "e56168bbacfb0278760997a37fba1d95ef5cb17fd6ae966ea2ab3e7de773b086";

    type SpecOutput = {
      value: number;
      addresses: string[];
      scriptType: string;
      scriptHex: string;
      spentByTransactionId?: string;
      dataHex?: string;
    };

    const issuanceOutputs: SpecOutput[] = Array.from({ length: 12 }, () => ({
      value: 600,
      addresses: ["other"],
      scriptType: "pay-to-script-hash",
      scriptHex: "a914000000000000000000000000000000000000000087",
    }));
    issuanceOutputs[8] = {
      value: 600,
      addresses: [firstHolder],
      scriptType: "pay-to-script-hash",
      scriptHex: "a9148724a413695cb414d8cc823005f4000fb7ef229e87",
      spentByTransactionId: transferTxid,
    };
    issuanceOutputs[10] = {
      value: 0,
      addresses: [],
      scriptType: "null-data",
      scriptHex: "6a1a434302050a000101010201030104010501060107010801090110",
      dataHex: "434302050a000101010201030104010501060107010801090110",
    };

    const issuanceTransaction = {
      transactionId: issuanceTxid,
      inputs: [
        {
          previousTransactionId: "aa".repeat(32),
          previousOutputIndex: 0,
          value: 1000,
          addresses: ["issuer"],
        },
      ],
      outputs: issuanceOutputs,
    };

    // Mirrors BlockCypher /addrs/.../full: complete txs, no per-tx refetch needed.
    (litecoin as any).getAddressTransactions = async () => [
      issuanceTransaction,
    ];

    (litecoin as any).getTransaction = async (
      transactionId: string,
      transactionCache: Map<string, any>,
    ) => {
      if (transactionCache.has(transactionId)) {
        return transactionCache.get(transactionId);
      }

      if (transactionId === transferTxid) {
        const transferTransaction = {
          transactionId: transferTxid,
          inputs: [
            {
              previousTransactionId: issuanceTxid,
              previousOutputIndex: 8,
              value: 600,
              addresses: [firstHolder],
            },
          ],
          outputs: [
            {
              value: 600,
              addresses: [secondHolder],
              scriptType: "pay-to-script-hash",
              scriptHex: "a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa87",
            },
            {
              value: 0,
              addresses: [],
              scriptType: "null-data",
              scriptHex: "6a0843430201010000",
              dataHex: "43430201010000",
            },
          ],
        };
        transactionCache.set(transactionId, transferTransaction);
        return transferTransaction;
      }

      return null;
    };

    (litecoin as any).deriveAssetId = () => assetId;
    (litecoin as any).readColoredCoinData = (transaction: {
      transactionId: string;
    }) => {
      if (transaction.transactionId === issuanceTxid) {
        return {
          type: "issuance",
          lockStatus: true,
          aggregationPolicy: "aggregatable",
          divisibility: 0,
          payments: [
            { input: 0, output: 8, amount: 1, range: false, percent: false },
          ],
        };
      }
      return {
        type: "transfer",
        aggregationPolicy: "aggregatable",
        payments: [
          { input: 0, output: 0, amount: 1, range: false, percent: false },
        ],
      };
    };

    const track = await litecoin.getBlockchainTrack(assetId, firstHolder);

    expect(track).to.deep.equal({
      asset: assetId,
      transfers: [
        {
          prevTxid: issuanceTxid,
          txid: transferTxid,
          prevAddress: firstHolder,
          currentAddress: secondHolder,
          network: "LTC",
        },
      ],
    });
  });
});
