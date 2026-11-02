import { Blockchain, Network } from "./index";
import Litecoin from "./litecoin";
import Liquid from "./liquid";
import {
  GetBlockchainTrackResult,
  GetTransfersByTxIdResult,
} from "./liquid";
import {
  BridgeValidationResult,
  deriveLitecoinAssetOutpoint,
  findLitecoinToLiquidTransition,
  resolveLitecoinToLiquidBridge,
  takeTransfersUntilHolder,
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
  const transition = findLitecoinToLiquidTransition(electronicDocument);

  if (transition.kind === "none") {
    return {
      track: await getSingleNetworkTrack({
        network,
        assetId,
        firstHolderAddress,
        useTestnet,
      }),
    };
  }

  if (transition.kind === "invalid") {
    return {
      track: null,
      litecoinLiquidBridge: {
        status: "invalid",
        reason: transition.reason,
      },
    };
  }

  const { lastLitecoinHolder, firstLiquidHolder } = transition;

  const litecoin = Blockchain.init("LTC") as Litecoin;
  const liquid = Blockchain.init("LBTC") as Liquid;
  if (useTestnet) {
    litecoin.useTestnet();
    liquid.useTestnet();
  }

  let litecoinTrack: GetBlockchainTrackResult | null;
  try {
    litecoinTrack = await litecoin.getBlockchainTrack(
      assetId,
      firstHolderAddress,
    );
  } catch (_error) {
    return unverifiableBridgeResult();
  }
  if (!litecoinTrack) {
    return {
      track: null,
      litecoinLiquidBridge: {
        status: "invalid",
        reason: "litecoin_track_not_found",
      },
    };
  }

  const litecoinTransfers = takeTransfersUntilHolder(
    litecoinTrack.transfers,
    lastLitecoinHolder,
    firstHolderAddress,
  );
  if (!litecoinTransfers) {
    return {
      track: null,
      litecoinLiquidBridge: {
        status: "invalid",
        reason: "litecoin_holder_not_found_in_track",
      },
    };
  }

  const litecoinAssetOutpoint = deriveLitecoinAssetOutpoint(
    litecoinTrack.issuance,
    litecoinTransfers,
  );
  if (!litecoinAssetOutpoint) {
    return {
      track: null,
      litecoinLiquidBridge: {
        status: "invalid",
        reason: "litecoin_asset_outpoint_not_found",
      },
    };
  }

  const litecoinLiquidBridge = await resolveLitecoinToLiquidBridge(
    lastLitecoinHolder,
    firstLiquidHolder,
    litecoinAssetOutpoint,
    litecoin,
    liquid,
  );

  if (litecoinLiquidBridge.status !== "valid" || !litecoinLiquidBridge.assetId) {
    return {
      track: null,
      litecoinLiquidBridge,
    };
  }

  let liquidTrack: GetBlockchainTrackResult | null;
  try {
    liquidTrack = await liquid.getBlockchainTrack(
      litecoinLiquidBridge.assetId,
    );
  } catch (_error) {
    return unverifiableBridgeResult();
  }
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
      issuance: litecoinTrack.issuance,
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

const unverifiableBridgeResult = (): BuildBlockchainTrackResult => ({
  track: null,
  litecoinLiquidBridge: {
    status: "unverifiable",
    reason: "blockchain_provider_failure",
  },
});
