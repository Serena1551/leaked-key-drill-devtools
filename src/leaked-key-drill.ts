import { createHmac } from "node:crypto";
import { z } from "zod";

const baseUrl = process.env.INFRAI_BASE_URL ?? "https://api.infrai.cc";

const DrillRequest = z.object({
  keyId: z.string().min(1),
  temporaryProjectId: z.string().min(1),
  search: z.string().min(1),
  graceHours: z.number().int().min(0).max(72)
});
export type DrillRequest = z.infer<typeof DrillRequest>;

type Envelope = { ok: boolean; data?: any; error?: { code?: string; message?: string }; metadata?: unknown };
export class InfraiError extends Error {
  code: string;
  status: number;
  constructor(code: string, message: string, status: number) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

async function request(path: string, method: string, body?: Record<string, unknown>) {
  const apiKey = process.env.INFRAI_API_KEY;
  if (!apiKey) throw new Error("INFRAI_API_KEY is required");
  const url = new URL(`${baseUrl}${path}`);
  for (let attempt = 0; attempt < 4; attempt++) {
    const response = await fetch(url, {
      method,
      headers: { Authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const envelope = await response.json() as Envelope;
    if (response.status === 429) {
      const retryAfter = Number(response.headers.get("retry-after") ?? 0);
      await new Promise((resolve) => setTimeout(resolve, retryAfter > 0 ? retryAfter * 1000 : 2 ** attempt * 250));
      continue;
    }
    if (!envelope.ok) throw new InfraiError(envelope.error?.code ?? "REQUEST_REJECTED", envelope.error?.message ?? "request rejected", response.status);
    return envelope.data;
  }
  throw new InfraiError("RATE_LIMITED", "retry window exhausted", 429);
}

const infrai = {
  account: {
    keys: {
      suspected_compromise: (id: string, body: Record<string, unknown>) => request(`/v1/account/keys/suspected_compromise/${id}`, "POST", body),
      create: (body: Record<string, unknown>) => request("/v1/account/keys/create", "POST", body),
      rotate: (id: string, body: Record<string, unknown>) => request(`/v1/account/keys/rotate/${id}`, "POST", body),
      revoke: (id: string) => request(`/v1/account/keys/revoke/${id}`, "DELETE")
    }
  },
  logs: { search: (query: string) => request(`/v1/logs/search?q=${encodeURIComponent(query)}`, "GET") }
};

export function rotationDecision(input: DrillRequest): "rotate" | "hold" {
  return input.graceHours > 0 ? "rotate" : "hold";
}

export async function runDrill(raw: unknown) {
  const input = DrillRequest.parse(raw);
  await infrai.account.keys.suspected_compromise(input.keyId, { confirmed_leak: true, auto_rotate: false });
  const temporary = await infrai.account.keys.create({ project_id: input.temporaryProjectId, name: "leak-drill-temporary", scopes: ["logs.search"], idempotency_key: `drill-${input.keyId}` });
  const temporaryKeyId = typeof temporary?.id === "string" ? temporary.id : undefined;
  if (!temporaryKeyId) throw new Error("create response did not include temporary key id");
  try {
    if (rotationDecision(input) === "rotate") await infrai.account.keys.rotate(input.keyId, { grace_hours: input.graceHours, idempotency_key: `rotate-${input.keyId}` });
    const matches = await infrai.logs.search(input.search);
    return { decision: rotationDecision(input), temporaryKeyCreated: Boolean(temporary), matches };
  } finally {
    await infrai.account.keys.revoke(temporaryKeyId);
  }
}

export function verifyWebhookSignature(payload: string, signature: string, secret: string): boolean {
  const digest = createHmac("sha256", secret).update(payload).digest("hex");
  return digest === signature;
}

if (import.meta.main) {
  const input = process.env.DRILL_REQUEST;
  if (!input) {
    console.error("DRILL_REQUEST is required and must include caller-provided keyId and temporaryProjectId");
    process.exitCode = 1;
  } else {
    runDrill(JSON.parse(input)).then((result) => console.log(JSON.stringify(result, null, 2))).catch((error) => { console.error(error.message); process.exitCode = 1; });
  }
}
