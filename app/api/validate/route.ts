/**
 * POST /api/validate  { provider, secret }  → { liveness, detail }
 *
 * Re-check a single credential after rotating it, without rescanning the repo.
 *
 * The scan cache deliberately holds masked values only, so this endpoint cannot
 * look a secret up — the caller must supply it. The value is used for one
 * read-only probe and then dropped: it is not stored, not cached, and not logged.
 */
import { isValidatable, validateSecret } from "@/lib/validate";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  let body: { provider?: string; secret?: string; secondary?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return Response.json({ error: "Expected a JSON body." }, { status: 400 });
  }

  const { provider, secret, secondary } = body;
  if (!provider || !secret) {
    return Response.json({ error: "Both `provider` and `secret` are required." }, { status: 400 });
  }
  if (!isValidatable(provider)) {
    return Response.json(
      { liveness: "unknown", detail: { note: `No read-only probe exists for "${provider}".` } },
      { status: 200 },
    );
  }

  const result = await validateSecret(provider, secret, secondary);
  return Response.json(result);
}
