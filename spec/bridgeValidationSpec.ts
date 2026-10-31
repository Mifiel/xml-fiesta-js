import { expect } from "chai";
import XML from "../src/patches/xmlPatch";
import {
  BridgeLiquidClient,
  BridgeLitecoinClient,
  BridgeValidationResult,
  validateLitecoinToLiquidBridge,
} from "../src/services/blockchain/litecoin-liquid-bridge";
import { LitecoinTransaction } from "../src/services/blockchain/litecoin";
import {
  LiquidAsset,
  LiquidTransaction,
} from "../src/services/blockchain/liquid";

const fs = require("fs");

type BridgeCase = {
  fixture: string;
  lastLitecoinHolder: string;
  bridgeTransactionId: string;
  assetId: string;
  issuanceTransactionId: string;
  firstLiquidHolder: string;
};

const bridgeCases: BridgeCase[] = [
  {
    fixture: "pagare_2110445.xml",
    lastLitecoinHolder: "MF2sxYhnCemw2L7UcejmkfCPeYeqavmxtZ",
    bridgeTransactionId:
      "9d56eec9ddb9a877ec81ce60da0473de22ce7b5dc38f59a9593b7599efcc2b1a",
    assetId: "46d172032a8de3000d86b1ff70f532564a70c0fc3f04ff2321e43be696319231",
    issuanceTransactionId:
      "9bbcc03d7570b88262c361be46f35297db227b64903167c49ece77e12da42b59",
    firstLiquidHolder: "Gts7fyoH1Bmayp3at8Yx4NRPkJKSZeMBFX",
  },
  {
    fixture: "pagare_2035257.xml",
    lastLitecoinHolder: "MJj7Na5YSTgVcN1KC53yAdZvHDjbXyWBf1",
    bridgeTransactionId:
      "2dfed5e513a62e66a7e3c21830bef6394238276fe3069beef65f1648435f27ae",
    assetId: "66eb7a59d27c3659e18de2fa8e5dddf91e8b4d330ca5cbbe630dadcea3764bc1",
    issuanceTransactionId:
      "d2adc5407a1ac6cd6d9c32c3829be6ea0bad6b631452568db9d7a597b9032a81",
    firstLiquidHolder: "GzL4jqmxo27LrRUjizeyjgJz2rheJmNXXE",
  },
];

type BridgeClients = {
  litecoin: BridgeLitecoinClient & {
    transactions: LitecoinTransaction[];
  };
  liquid: BridgeLiquidClient & {
    asset: LiquidAsset;
    transactions: Record<string, LiquidTransaction>;
  };
};

const createBridgeClients = (bridgeCase: BridgeCase): BridgeClients => {
  const previousTransactionId = `${"0".repeat(63)}1`;
  const litecoinTransactions: LitecoinTransaction[] = [
    {
      transactionId: bridgeCase.bridgeTransactionId,
      inputs: [
        {
          previousTransactionId,
          previousOutputIndex: 0,
          value: 1000,
          addresses: [bridgeCase.lastLitecoinHolder],
        },
      ],
      outputs: [
        {
          value: 600,
          addresses: ["variable-burn-address"],
          scriptType: "pay-to-script-hash",
        },
        {
          value: 0,
          addresses: [],
          scriptType: "null-data",
          dataHex: `6c697175696400${bridgeCase.assetId}`,
        },
      ],
    },
  ];

  const liquidTransactions: Record<string, LiquidTransaction> = {
    [bridgeCase.issuanceTransactionId]: {
      transactionId: bridgeCase.issuanceTransactionId,
      outputs: [
        {
          address: bridgeCase.firstLiquidHolder,
          assetId: bridgeCase.assetId,
          value: 1,
        },
      ],
    },
  };

  const clients: BridgeClients = {
    litecoin: {
      transactions: litecoinTransactions,
      getAddressTransactions: async () => clients.litecoin.transactions,
    },
    liquid: {
      asset: {
        issuanceTransactionId: bridgeCase.issuanceTransactionId,
        issuedAmount: 1,
      },
      transactions: liquidTransactions,
      getAsset: async () => clients.liquid.asset,
      getTransaction: async (transactionId: string) =>
        clients.liquid.transactions[transactionId] || null,
    },
  };

  return clients;
};

describe("Litecoin to Liquid bridge validation", () => {
  for (const bridgeCase of bridgeCases) {
    it(`validates the real bridge fixture ${bridgeCase.fixture}`, async () => {
      const clients = createBridgeClients(bridgeCase);
      const result = await validateFixture(bridgeCase.fixture, clients);

      expect(result.status).to.equal("valid");
      expect(result.assetId).to.equal(bridgeCase.assetId);
      expect(result.litecoinTransactionId).to.equal(
        bridgeCase.bridgeTransactionId,
      );
      expect(result.liquidIssuanceTransactionId).to.equal(
        bridgeCase.issuanceTransactionId,
      );
    });
  }

  it("rejects an incorrect OP_RETURN", async () => {
    const bridgeCase = bridgeCases[0];
    const clients = createBridgeClients(bridgeCase);
    clients.litecoin.transactions[0].outputs[1].dataHex = `6c697175696401${bridgeCase.assetId}`;

    const result = await validateFixture(bridgeCase.fixture, clients);

    expect(result.status).to.equal("invalid");
    expect(result.reason).to.equal("litecoin_bridge_not_unique");
  });

  it("rejects a Liquid asset issued with a quantity other than one", async () => {
    const bridgeCase = bridgeCases[0];
    const clients = createBridgeClients(bridgeCase);
    clients.liquid.asset.issuedAmount = 2;

    const result = await validateFixture(bridgeCase.fixture, clients);

    expect(result.status).to.equal("invalid");
    expect(result.reason).to.equal("liquid_asset_quantity_is_not_one");
  });

  it("rejects a Liquid issuance to a different holder", async () => {
    const bridgeCase = bridgeCases[0];
    const clients = createBridgeClients(bridgeCase);
    clients.liquid.transactions[
      bridgeCase.issuanceTransactionId
    ].outputs[0].address = "different-holder";

    const result = await validateFixture(bridgeCase.fixture, clients);

    expect(result.status).to.equal("invalid");
    expect(result.reason).to.equal("liquid_issuance_recipient_mismatch");
  });

  it("rejects two spends of the Litecoin bridge input", async () => {
    const bridgeCase = bridgeCases[0];
    const clients = createBridgeClients(bridgeCase);
    clients.litecoin.transactions.push({
      transactionId: `${"f".repeat(63)}1`,
      inputs: [
        {
          ...clients.litecoin.transactions[0].inputs[0],
        },
      ],
      outputs: [],
    });

    const result = await validateFixture(bridgeCase.fixture, clients);

    expect(result.status).to.equal("invalid");
    expect(result.reason).to.equal(
      "litecoin_bridge_input_spent_more_than_once",
    );
  });

  it("returns unverifiable when litecoin lookup fails", async () => {
    const bridgeCase = bridgeCases[0];
    const clients = createBridgeClients(bridgeCase);
    clients.litecoin.getAddressTransactions = async () => {
      throw new Error("Network unavailable");
    };

    const result = await validateFixture(bridgeCase.fixture, clients);

    expect(result.status).to.equal("unverifiable");
    expect(result.reason).to.equal("blockchain_provider_failure");
  });

  for (const fixture of ["pagare_lbtc_only.xml", "pagare_no_endosable.xml"]) {
    it(`keeps ${fixture} valid without blockchain requests`, async () => {
      const fail = async () => {
        throw new Error("Blockchain clients should not be called");
      };
      const result = await validateFixture(fixture, {
        litecoin: { getAddressTransactions: fail },
        liquid: { getAsset: fail, getTransaction: fail },
      });

      expect(result).to.deep.equal({ status: "valid" });
    });
  }
});

const validateFixture = async (
  fixture: string,
  clients: {
    litecoin: BridgeLitecoinClient;
    liquid: BridgeLiquidClient;
  },
): Promise<BridgeValidationResult> => {
  const xmlString = fs.readFileSync(
    `${__dirname}/../handoff/${fixture}`,
    "utf8",
  );
  const xml = await XML.parse(xmlString);
  return validateLitecoinToLiquidBridge(
    xml.eDocument,
    clients.litecoin,
    clients.liquid,
  );
};
