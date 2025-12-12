export type HealthResponse = {
  status: string;
  component: string;
  build?: string;
  time?: string;
};

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "";

export async function fetchHealth(): Promise<HealthResponse | null> {
  try {
    const res = await fetch(`${API_BASE}/api/v1/health`, {
      cache: "no-store",
    });
    if (!res.ok) return null;
    return (await res.json()) as HealthResponse;
  } catch {
    return null;
  }
}
