import { Blockchain, Network } from "./index";
import Litecoin from "./litecoin";
import Liquid from "./liquid";
import {
  GetBlockchainTrackResult,
  GetTransfersByTxIdResult,
} from "./liquid";
import {
  BridgeValidationResult,
  extractBlockchainLayers,
  resolveLitecoinToLiquidBridge,
} from "./litecoin-liquid-bridge";

export type BuildBlockchainTrackOptions = {
  electronicDocument: any;
  assetId: string;
  firstHolderAddress: string;
  network: Network;
  useTestnet?: boolean;
};

export type BuildBlockchainTrackResult = {
  track: GetBlockchainTrackResult | null;
  litecoinLiquidBridge?: BridgeValidationResult;
};

export const buildBlockchainTrack = async ({
  electronicDocument,
  assetId,
  firstHolderAddress,
  network,
  useTestnet = false,
}: BuildBlockchainTrackOptions): Promise<BuildBlockchainTrackResult> => {
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
    return {
      track: await getSingleNetworkTrack({
        network,
        assetId,
        firstHolderAddress,
        useTestnet,
      }),
    };
  }

  if (transitionIndexes.length > 1) {
    return {
      track: null,
      litecoinLiquidBridge: {
        status: "invalid",
        reason: "multiple_litecoin_to_liquid_transitions",
      },
    };
  }

  const transitionIndex = transitionIndexes[0];
  const litecoinLayersAreContiguous = layers
    .slice(0, transitionIndex)
    .every(({ network: layerNetwork }) => layerNetwork === "LTC");
  const liquidLayersAreContiguous = layers
    .slice(transitionIndex)
    .every(({ network: layerNetwork }) => layerNetwork === "LBTC");

  if (!litecoinLayersAreContiguous || !liquidLayersAreContiguous) {
    return {
      track: null,
      litecoinLiquidBridge: {
        status: "invalid",
        reason: "invalid_blockchain_layer_sequence",
      },
    };
  }

  const lastLitecoinHolder = layers[transitionIndex - 1]?.holderAddress;
  const firstLiquidHolder = layers[transitionIndex]?.holderAddress;
  if (!lastLitecoinHolder || !firstLiquidHolder) {
    return {
      track: null,
      litecoinLiquidBridge: {
        status: "invalid",
        reason: "missing_holder_address",
      },
    };
  }

  const litecoin = Blockchain.init("LTC") as Litecoin;
  const liquid = Blockchain.init("LBTC") as Liquid;
  if (useTestnet) {
    litecoin.useTestnet();
    liquid.useTestnet();
  }

  const litecoinLiquidBridge = await resolveLitecoinToLiquidBridge(
    lastLitecoinHolder,
    firstLiquidHolder,
    litecoin,
    liquid,
  );

  if (litecoinLiquidBridge.status !== "valid" || !litecoinLiquidBridge.assetId) {
    return {
      track: null,
      litecoinLiquidBridge,
    };
  }

  const litecoinTrack = await litecoin.getBlockchainTrack(
    assetId,
    firstHolderAddress,
  );
  if (!litecoinTrack) {
    return {
      track: null,
      litecoinLiquidBridge,
    };
  }

  const litecoinTransfers = takeTransfersUntilHolder(
    litecoinTrack.transfers,
    lastLitecoinHolder,
  );

  const liquidTrack = await liquid.getBlockchainTrack(
    litecoinLiquidBridge.assetId,
  );
  if (!liquidTrack) {
    return {
      track: null,
      litecoinLiquidBridge,
    };
  }

  const previousLitecoinTransfer =
    litecoinTransfers[litecoinTransfers.length - 1];
  const bridgeTransfer: GetTransfersByTxIdResult = {
    prevAddress: lastLitecoinHolder,
    currentAddress: firstLiquidHolder,
    txid: litecoinLiquidBridge.litecoinTransactionId,
    prevTxid: previousLitecoinTransfer?.txid,
    network: "LTC",
  };

  return {
    litecoinLiquidBridge,
    track: {
      asset: assetId,
      transfers: [
        ...litecoinTransfers.map((transfer) => ({
          ...transfer,
          network: "LTC" as const,
        })),
        bridgeTransfer,
        ...liquidTrack.transfers.map((transfer) => ({
          ...transfer,
          network: "LBTC" as const,
        })),
      ],
    },
  };
};

const getSingleNetworkTrack = async ({
  network,
  assetId,
  firstHolderAddress,
  useTestnet,
}: {
  network: Network;
  assetId: string;
  firstHolderAddress: string;
  useTestnet: boolean;
}): Promise<GetBlockchainTrackResult | null> => {
  const blockchainInstance = Blockchain.init(network);
  if (useTestnet) blockchainInstance.useTestnet();
  return blockchainInstance.getBlockchainTrack(assetId, firstHolderAddress);
};

const takeTransfersUntilHolder = (
  transfers: GetTransfersByTxIdResult[],
  holderAddress: string,
): GetTransfersByTxIdResult[] => {
  const selectedTransfers: GetTransfersByTxIdResult[] = [];

  for (const transfer of transfers) {
    selectedTransfers.push(transfer);
    if (transfer.currentAddress === holderAddress) {
      break;
    }
  }

  return selectedTransfers;
};
