import Litecoin, {
  LitecoinInput,
  LitecoinTransaction,
} from "./litecoin";
import Liquid, { LiquidAsset, LiquidTransaction } from "./liquid";

export type BridgeValidationStatus = "valid" | "invalid" | "unverifiable";

export type BridgeValidationResult = {
  status: BridgeValidationStatus;
  assetId?: string;
  litecoinTransactionId?: string;
  liquidIssuanceTransactionId?: string;
  reason?: string;
};

export type BlockchainLayer = {
  network: string;
  holderAddress: string;
};

type LitecoinBridgeCandidate = {
  transaction: LitecoinTransaction;
  input: LitecoinInput;
  assetId: string;
};

export type BridgeLitecoinClient = Pick<Litecoin, "getAddressTransactions">;
export type BridgeLiquidClient = Pick<Liquid, "getAsset" | "getTransaction">;

const LIQUID_ASSET_PREFIX_HEX = "6c697175696400";
const LIQUID_ASSET_PAYLOAD_LENGTH = LIQUID_ASSET_PREFIX_HEX.length + 64;

/**
 * Validates only the LTC→LBTC junction when present in the endorsement chain.
 * Liquid endorsements after the bridge are validated via the Liquid track segment.
 */
export const validateLitecoinToLiquidBridge = async (
  electronicDocument,
  litecoin: BridgeLitecoinClient,
  liquid: BridgeLiquidClient,
): Promise<BridgeValidationResult> => {
  const layers = extractBlockchainLayers(electronicDocument);
  const transitionIndexes = layers.reduce((indexes, layer, index) => {
    if (
      index > 0 &&
      layers[index - 1].network === "LTC" &&
      layer.network === "LBTC"
    ) {
      indexes.push(index);
    }
    return indexes;
  }, [] as number[]);

  if (transitionIndexes.length === 0) {
    return { status: "valid" };
  }

  if (transitionIndexes.length > 1) {
    return invalidResult("multiple_litecoin_to_liquid_transitions");
  }

  const transitionIndex = transitionIndexes[0];
  const networksBeforeTransitionAreLitecoin = layers
    .slice(0, transitionIndex)
    .every(({ network }) => network === "LTC");
  const networksAfterTransitionAreLiquid = layers
    .slice(transitionIndex)
    .every(({ network }) => network === "LBTC");

  if (
    !networksBeforeTransitionAreLitecoin ||
    !networksAfterTransitionAreLiquid
  ) {
    return invalidResult("invalid_blockchain_layer_sequence");
  }

  const lastLitecoinHolder = layers[transitionIndex - 1].holderAddress;
  const firstLiquidHolder = layers[transitionIndex].holderAddress;

  if (!lastLitecoinHolder || !firstLiquidHolder) {
    return invalidResult("missing_holder_address");
  }

  return resolveLitecoinToLiquidBridge(
    lastLitecoinHolder,
    firstLiquidHolder,
    litecoin,
    liquid,
  );
};

/**
 * Discovers and checks the on-chain LTC burn → Liquid issuance link only.
 */
export const resolveLitecoinToLiquidBridge = async (
  lastLitecoinHolder: string,
  firstLiquidHolder: string,
  litecoin: BridgeLitecoinClient,
  liquid: BridgeLiquidClient,
): Promise<BridgeValidationResult> => {
  try {
    const litecoinTransactions =
      await litecoin.getAddressTransactions(lastLitecoinHolder);
    const bridgeCandidate = findUniqueBridgeCandidate(
      litecoinTransactions,
      lastLitecoinHolder,
    );

    if (!bridgeCandidate) {
      return invalidResult("litecoin_bridge_not_unique");
    }

    const spendsOfBridgeInput = litecoinTransactions.filter((transaction) =>
      transaction.inputs.some(
        (input) =>
          input.previousTransactionId ===
            bridgeCandidate.input.previousTransactionId &&
          input.previousOutputIndex ===
            bridgeCandidate.input.previousOutputIndex,
      ),
    );

    if (spendsOfBridgeInput.length !== 1) {
      return invalidResult("litecoin_bridge_input_spent_more_than_once");
    }

    const liquidAsset: LiquidAsset | null = await liquid.getAsset(
      bridgeCandidate.assetId,
    );
    if (!liquidAsset) {
      return invalidResult("liquid_asset_not_found");
    }
    if (liquidAsset.issuedAmount !== 1) {
      return invalidResult("liquid_asset_quantity_is_not_one");
    }

    const issuanceTransaction = await liquid.getTransaction(
      liquidAsset.issuanceTransactionId,
    );
    if (!issuanceTransaction) {
      return invalidResult("liquid_issuance_transaction_not_found");
    }

    const issuanceOutputIndex = findUniqueAssetOutputIndex(
      issuanceTransaction,
      bridgeCandidate.assetId,
      firstLiquidHolder,
    );

    if (issuanceOutputIndex === -1) {
      return invalidResult("liquid_issuance_recipient_mismatch");
    }

    return {
      status: "valid",
      assetId: bridgeCandidate.assetId,
      litecoinTransactionId: bridgeCandidate.transaction.transactionId,
      liquidIssuanceTransactionId: issuanceTransaction.transactionId,
    };
  } catch (_error) {
    return {
      status: "unverifiable",
      reason: "blockchain_provider_failure",
    };
  }
};

export const extractBlockchainLayers = (
  electronicDocument,
): BlockchainLayer[] => {
  const documents = [
    electronicDocument,
    ...(electronicDocument?.transfers?.[0]?.electronicDocument || []),
  ];

  return documents
    .map((document) => {
      const blockchain = document?.blockchain?.[0];
      const plaintext =
        blockchain?.holder?.[0]?.binding?.[0]?.signature?.[0]?.$?.plaintext;

      if (!blockchain) {
        return null;
      }

      return {
        network: blockchain.$?.name,
        holderAddress: plaintext?.split("|")[0],
      };
    })
    .filter(Boolean);
};

const findUniqueBridgeCandidate = (
  transactions: LitecoinTransaction[],
  holderAddress: string,
): LitecoinBridgeCandidate | null => {
  const candidates: LitecoinBridgeCandidate[] = [];

  for (const transaction of transactions) {
    const bridgeInputs = transaction.inputs.filter(
      (input) =>
        input.value === 1000 && input.addresses.includes(holderAddress),
    );
    const hasBurnOutput = transaction.outputs.some(
      (output) =>
        output.value === 600 && output.scriptType === "pay-to-script-hash",
    );
    const assetIds = transaction.outputs
      .map(readLiquidAssetId)
      .filter(Boolean);

    if (hasBurnOutput && assetIds.length === 1) {
      for (const input of bridgeInputs) {
        candidates.push({
          transaction,
          input,
          assetId: assetIds[0],
        });
      }
    }
  }

  return candidates.length === 1 ? candidates[0] : null;
};

const readLiquidAssetId = (output): string | null => {
  const dataHex = output.dataHex?.toLowerCase();
  const scriptHex = output.scriptHex?.toLowerCase();
  const payload =
    dataHex ||
    (scriptHex?.startsWith("6a27") && scriptHex.length === 82
      ? scriptHex.slice(4)
      : null);

  if (
    !payload ||
    payload.length !== LIQUID_ASSET_PAYLOAD_LENGTH ||
    !payload.startsWith(LIQUID_ASSET_PREFIX_HEX)
  ) {
    return null;
  }

  const assetId = payload.slice(LIQUID_ASSET_PREFIX_HEX.length);
  return /^[0-9a-f]{64}$/.test(assetId) ? assetId : null;
};

const findUniqueAssetOutputIndex = (
  transaction: LiquidTransaction,
  assetId: string,
  holderAddress: string,
): number => {
  const matchingOutputIndexes = transaction.outputs.reduce(
    (indexes, output, index) => {
      if (
        output.assetId === assetId &&
        output.value === 1 &&
        output.address === holderAddress
      ) {
        indexes.push(index);
      }
      return indexes;
    },
    [] as number[],
  );

  return matchingOutputIndexes.length === 1 ? matchingOutputIndexes[0] : -1;
};

const invalidResult = (reason: string): BridgeValidationResult => ({
  status: "invalid",
  reason,
});
