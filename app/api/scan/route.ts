/**
 * GET /api/scan?url=<github url>   → Server-Sent Events stream of the scan.
 * GET /api/scan?id=<scan id>       → the cached result, for reload without rescan.
 *
 * SSE rather than a single JSON response because the progress counter is the
 * product's only animation, and because validation results arrive after the
 * findings they belong to — the render must never wait on a provider.
 */
import { runScan, type ScanEvent } from "@/lib/scan";
import { getScan } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 300;

export async function GET(request: Request): Promise<Response> {
  const params = new URL(request.url).searchParams;

  const cachedId = params.get("id");
  if (cachedId) {
    const result = getScan(cachedId);
    return result
      ? Response.json(result)
      : Response.json({ error: "Scan expired. Results are held for one hour." }, { status: 404 });
  }

  const url = params.get("url");
  if (!url) return Response.json({ error: "Missing ?url" }, { status: 400 });

  const encoder = new TextEncoder();
  let closed = false;

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (event: ScanEvent) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
        } catch {
          closed = true;
        }
      };

      // If the client navigates away, stop doing work for it.
      request.signal.addEventListener("abort", () => {
        closed = true;
      });

      try {
        await runScan(url, send);
      } catch (e) {
        send({
          type: "error",
          message: e instanceof Error ? e.message : "Scan failed.",
        });
      } finally {
        if (!closed) {
          try {
            controller.close();
          } catch {
            /* already closed by the client */
          }
        }
        closed = true;
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      // Nginx and friends buffer streamed responses by default, which would
      // collapse the whole scan into one burst at the end.
      "X-Accel-Buffering": "no",
    },
  });
}
