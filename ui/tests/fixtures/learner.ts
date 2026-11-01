import type { Page } from "@playwright/test";
import type {
  LearnDataset,
  LearnSuggestion,
  LearnWatch,
} from "../../lib/api-learn";

const createdAt = new Date().toISOString();
const expiresAt = new Date(Date.now() + 7 * 86400000).toISOString();
export const dataset: LearnDataset = {
  schemaVersion: "1",
  id: "capture-1",
  source: "pcap",
  state: "sealed",
  createdAt,
  expiresAt,
  sealedAt: createdAt,
  captureSha256: "capture-sha",
  decoderVersion: "decoder-1",
  profileFingerprint: "profile-1",
  snapshotFingerprint: "snapshot-1",
  evidenceDigest: "evidence-sha",
  records: 24,
  bytes: 8192,
  gaps: [],
};
const versions = {
  schema: "1",
  observation: "1",
  generator: "g1",
  evaluator: "e1",
  decoder: "d1",
  profile: "p1",
  snapshot: "s1",
};
export function suggestion(id = "modbus-1", iec = false): LearnSuggestion {
  return {
    id,
    revision: 2,
    datasetId: dataset.id,
    status: "certified",
    createdAt,
    expiresAt,
    content: {
      versions,
      evidenceDigest: "evidence-sha",
      limits: ["Supported selector relations only; not transaction equality."],
      withheld: [],
      requiresCoordinateReview: false,
      rules: [
        {
          id: `rule-${id}`,
          description: iec ? "PLC command" : "Historian reads",
          action: "ALLOW",
          sources: ["192.0.2.10"],
          destinations: ["192.0.2.20"],
          protocols: [{ name: "tcp", port: iec ? "2404" : "502" }],
          ics: iec
            ? {
                protocol: "iec104",
                mode: "monitor",
                typeIds: [45],
                ca: [1],
                ioa: [{ start: 10, end: 10 }],
                cot: [6],
                originators: [0],
                negative: false,
                test: false,
                selectExecute: "execute",
                commandStates: [1],
                commandQualifiers: [0],
                direction: "request",
              }
            : {
                protocol: "modbus",
                mode: "monitor",
                functionCode: [3],
                unitId: 0,
                addresses: ["10-11"],
                direction: "request",
              },
        },
      ],
    },
    proof: {
      contentId: `content-${id}`,
      evidenceDigest: "evidence-sha",
      versions,
      certifiedAt: createdAt,
      parentRefs: [{ datasetId: dataset.id, observationId: "parent-1" }],
      positive: { total: 24, passed: 24, failed: 0 },
      negative: { total: 16, passed: 16, failed: 0 },
      counterexamples: [],
    },
    legacyOverlaps: [{ ruleId: "learned-old", reason: "same protocol scope" }],
  };
}

export async function mockLearner(page: Page, role = "admin") {
  const state = {
    dirty: false,
    imported: false,
    conflict: false,
    uncertain: false,
    suggestions: [suggestion(), suggestion("iec-1", true)],
    datasets: [structuredClone(dataset)],
    watches: [] as LearnWatch[],
    suggestionReads: 0,
    writes: [] as { path: string; body: any }[],
  };
  await page.addInitScript(
    (r) => localStorage.setItem("containd.auth.role", r),
    role,
  );
  await page.route("**/api/v1/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace("/api/v1", "");
    if (req.method() === "POST") {
      const body =
        path === "/pcap/analyze"
          ? (req.postDataBuffer(), "multipart")
          : req.postDataJSON();
      state.writes.push({ path, body });
      if (path.startsWith("/pcap/analyze")) {
        state.imported = true;
        return route.fulfill({ json: {
            dataset,
            stats: {
              packetCount: 24,
              byteCount: 8192,
              duration: 1e9,
              flows: [],
              protocols: { modbus: 24 },
            },
          }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      }
      if (path === "/learn/generate")
        return route.fulfill({ json: {
            suggestions: state.suggestions.map(({ id, revision }) => ({
              id,
              revision,
            })),
            withheld: { iec104_value: 3 },
          }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      if (path.endsWith("/review")) {
        const s = state.suggestions.find(
          (s) => path === `/learn/suggestions/${s.id}/review`,
        )!;
        if (body.selection.revision !== s.revision)
          return route.fulfill({ status: 409, json: { error: "stale revision" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
        s.review = {
          actor: "admin",
          at: createdAt,
          revision: s.revision,
          coordinateApproved: body.coordinateApproved,
        };
        s.revision++;
        s.status = body.approve ? "reviewed" : "rejected";
        return route.fulfill({ json: s, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      }
      if (path === "/learn/apply") {
        if (state.conflict) {
          state.suggestions[0].revision++;
          return route.fulfill({ status: 409, json: {
              error: "candidate rule conflict: no selected rules staged",
            }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
        }
        state.dirty = true;
        if (state.uncertain)
          return route.fulfill({ status: 503, json: { error: "completion unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
        for (const selection of body.selections) {
          const s = state.suggestions.find((s) => s.id === selection.id)!;
          s.revision++;
          s.status = "staged";
        }
        return route.fulfill({ json: { ...body, staged: true }, headers: { "X-Containd-Revision": "0123456789abcdef.1", "X-Containd-Config": "staged" } });
      }
      if (path === "/learn/watches") {
        const watch = {
          id: "watch-1",
          datasetId: "live-1",
          startedAt: createdAt,
          deadline: new Date(
            Date.now() + body.durationSeconds * 1000,
          ).toISOString(),
        };
        state.watches.push(watch);
        state.datasets.push({
          ...dataset,
          id: "live-1",
          source: "live",
          state: "collecting",
        });
        return route.fulfill({ json: watch, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      }
      if (path === "/learn/watches/watch-1/stop") {
        state.watches[0].stoppedAt = new Date().toISOString();
        state.watches[0].stopReason = "operator";
        state.datasets[1].state = "sealed";
        return route.fulfill({ json: state.watches[0], headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      }
      if (path === "/firewall/rules/preview")
        return route.fulfill({ json: {
            match_count: 1,
            total_events: 2,
            sample_matches: [],
            warnings: [],
          }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      return route.fulfill({ json: {}, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    }
    const data: Record<string, unknown> = {
      "/auth/me": { id: "admin-1", username: "containd", role },
      "/auth/session": { id: "admin-1", username: "containd", role },
      "/config/diff": {
        changed: state.dirty,
        changedSections: state.dirty ? ["firewall"] : [],
        running: {},
        candidate: state.dirty ? { firewall: {} } : {},
      },
      "/pcap/list": [
        { name: "example.pcap", interface: "eth0", sizeBytes: 8192, createdAt },
      ],
      "/learn/datasets": { items: state.datasets },
      "/learn/watches": { items: state.watches },
      "/learn/counters": {
        records: 24,
        bytes: 8192,
        evictedRecords: 0,
        evictedBytes: 0,
        expiredRecords: 0,
        lostBatches: 0,
        rejectedParents: 0,
        withheld: {},
      },
    };
    if (path === "/learn/suggestions") {
      state.suggestionReads++;
      return route.fulfill({ json: { items: state.suggestions }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    }
    if (path.endsWith("/observations"))
      return route.fulfill({ json: {
          items: [
            {
              id: "parent-1",
              capturedAt: createdAt,
              service: {
                clientIp: "192.0.2.10",
                serverIp: "192.0.2.20",
                serverPort: 502,
                transport: "tcp",
                protocol: "modbus",
                direction: "request",
                coordinates: "logical",
              },
              authority: {
                correlation: "verified",
                roleCertain: true,
                roleEvidence: "SYN",
                standardPort: true,
              },
              quality: {
                complete: true,
                decoded: true,
                conformance: [],
                undecoded: [],
                loss: [],
              },
            },
          ],
        }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    return route.fulfill({ json: data[path] ?? {}, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  return state;
}

export async function openDataset(page: Page) {
  const loaded = page.waitForResponse(
    (r) => new URL(r.url()).pathname === "/api/v1/learn/datasets",
  );
  await page.goto("/pcap/");
  await loaded;
  await page
    .getByRole("button", { name: "Open capture-1", exact: true })
    .click();
  await page
    .getByRole("article", { name: "Suggestion modbus-1", exact: true })
    .waitFor();
}
