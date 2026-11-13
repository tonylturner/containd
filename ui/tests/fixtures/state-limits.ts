export const stateLimits = {
  tables: [
    { table: "flows", limit: 16384, entries: 2048, chargedBytes: 0, highWater: 4096, pressure: true, hits: [{ reason: "refused", mode: "enforce", total: 17 }] },
    { table: "inspection_bytes", limit: 67108864, entries: 0, chargedBytes: 1048576, highWater: 2097152, pressure: false, hits: [] },
    ...[["top_talkers", 8192], ["rate_trackers", 8192], ["iec_sessions", 4096], ["iec_reconnect_history", 4096], ["inventory_points", 65536], ["signature_windows", 4096], ["conformance_connections", 65536], ["verdict_cache", 65536], ["pickup_reset", 4096], ["http_correlation", 0]].map(([table, limit]) => ({ table, limit, entries: 12, chargedBytes: 0, highWater: 18, pressure: false, hits: [] })),
  ],
  budget: { limit: 67108864, inUse: 1048576, highWater: 2097152, byCategory: { stream: 524288, decoder: 524288, held: 0, pairing: 0 } },
};
