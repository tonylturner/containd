import { getJSONWithStatus } from "./api-request";

export type IEC104Point = {
  ioa: number;
  typeId: number;
  firstSeen: string;
  lastSeen: string;
};
export type IEC104CA = {
  ca: number;
  firstSeen: string;
  lastSeen: string;
  attemptedCommands: number;
  acceptedCommands: number;
  points: IEC104Point[];
};
export type IEC104Inventory = {
  pairs: {
    controlling: string;
    controlled: string;
    firstSeen: string;
    lastSeen: string;
    attemptedCommands: number;
    acceptedCommands: number;
    cas: IEC104CA[];
  }[];
  limits: {
    pairs: number;
    casPerPair: number;
    pointsPerCA: number;
    assets: number;
    peersPerAsset: number;
    stationAddressesPerAsset: number;
    maxIdleSeconds: number;
  };
  overflow: {
    observations: number;
    pairs: number;
    cas: number;
    points: number;
    assets: number;
    peers: number;
    stationAddresses: number;
    outcomes: number;
  };
};

export const inventoryAPI = {
  getIEC104Inventory: () =>
    getJSONWithStatus<IEC104Inventory>("/api/v1/inventory/iec104"),
};
