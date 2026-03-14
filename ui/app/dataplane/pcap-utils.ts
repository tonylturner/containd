import type { PcapConfig } from "../../lib/api";

export function normalizeConfig(cfg: PcapConfig): PcapConfig {
  return {
    enabled: cfg.enabled ?? false,
    interfaces: cfg.interfaces ?? [],
    snaplen: cfg.snaplen ?? 262144,
    maxSizeMB: cfg.maxSizeMB ?? 64,
    maxFiles: cfg.maxFiles ?? 8,
    mode: cfg.mode ?? "rolling",
    promisc: cfg.promisc ?? true,
    bufferMB: cfg.bufferMB ?? 4,
    rotateSeconds: cfg.rotateSeconds ?? 300,
    filePrefix: cfg.filePrefix ?? "capture",
    filter: {
      src: cfg.filter?.src ?? "",
      dst: cfg.filter?.dst ?? "",
      proto: cfg.filter?.proto ?? "any",
    },
    forwardTargets: cfg.forwardTargets ?? [],
  };
}
