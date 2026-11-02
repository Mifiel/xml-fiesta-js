import { Blockchain, Network } from "./index";
import Litecoin from "./litecoin";
import Liquid from "./liquid";
import {
  GetBlockchainTrackResult,
  GetTransfersByTxIdResult,
} from "./liquid";
import {
  BridgeValidationResult,
  findLitecoinToLiquidTransition,
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
    firstHolderAddress,
  );
  if (!litecoinTransfers) {
    return {
      track: null,
      litecoinLiquidBridge,
    };
  }

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
  firstHolderAddress: string,
): GetTransfersByTxIdResult[] | null => {
  let holderIndex = -1;
  for (let index = transfers.length - 1; index >= 0; index -= 1) {
    if (transfers[index].currentAddress === holderAddress) {
      holderIndex = index;
      break;
    }
  }

  if (holderIndex === -1) {
    return holderAddress === firstHolderAddress ? [] : null;
  }

  return transfers.slice(0, holderIndex + 1);
};
