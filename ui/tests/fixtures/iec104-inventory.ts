export const at = "2026-10-26T12:00:00Z";
export const snapshot = {
  pairs: [{
    controlling: "192.0.2.10:50000", controlled: "192.0.2.20:2404",
    firstSeen: at, lastSeen: at, attemptedCommands: 3, acceptedCommands: 1,
    cas: [{ ca: 7, firstSeen: at, lastSeen: at, attemptedCommands: 3, acceptedCommands: 1,
      points: [
        { ioa: 100, typeId: 45, firstSeen: at, lastSeen: at },
        { ioa: 100, typeId: 1, firstSeen: at, lastSeen: at },
      ],
    }],
  }],
  limits: { pairs: 128, casPerPair: 32, pointsPerCA: 256, assets: 1024, peersPerAsset: 128, stationAddressesPerAsset: 256, maxIdleSeconds: 86400 },
  overflow: { observations: 9, pairs: 2, cas: 3, points: 4, assets: 5, peers: 6, stationAddresses: 7, outcomes: 8 },
};
