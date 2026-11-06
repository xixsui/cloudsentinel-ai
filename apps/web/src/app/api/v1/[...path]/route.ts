import { NextRequest, NextResponse } from "next/server";
import { isValidLocalWriteOrigin } from "@/lib/localOrigin";

/** Local-only, same-origin BFF. Never relay AWS or AI API credentials to JS. */
async function proxy(req: NextRequest, segments: string[], method: "GET" | "PATCH" | "POST" | "PUT") {
  if (segments.some((segment) => !/^[a-zA-Z0-9_-]+$/.test(segment))) {
    return NextResponse.json({ detail: "Invalid path" }, { status: 400 });
  }
  const endpoint = segments.join("/");
  const allowedGet = /^(workspace\/status|scans\/jobs|settings\/(ai|aws|scanner)|aws\/inventory|scans|scans\/compare|health|posture\/summary|findings|findings\/[\w-]+|remediations|remediations\/[\w-]+\/activity|ai\/status|findings\/[\w-]+\/ai\/(history|preview))$/;
  const allowedPatch = /^remediations\/[\w-]+$/;
  const allowedPost = /^(settings\/scanner\/install|findings\/[\w-]+\/recheck|scans\/start|scans\/jobs\/[a-f0-9]+\/cancel|settings\/aws\/(connect|disconnect|connect-saved|remove-saved)|settings\/data\/(delete|backup|preview|restore)|aws\/inventory\/refresh|scans\/import|findings\/[\w-]+\/ai\/analyze)$/;
  const allowedPut = /^(settings\/ai\/(default|credential)|findings\/[\w-]+\/ai\/runs\/[0-9]+\/feedback)$/;
  const allowed = method === "GET" ? allowedGet : method === "PATCH" ? allowedPatch : method === "PUT" ? allowedPut : allowedPost;
  if (!allowed.test(endpoint)) return NextResponse.json({ detail: "Not found" }, { status: 404 });

  // Browsers must originate requests from this local application. This is a
  // local-dev precaution, not a substitute for identity and RBAC.
  if (method !== "GET") {
    if (!isValidLocalWriteOrigin(req.headers)) {
      return NextResponse.json({ detail: "Cross-origin writes are not permitted" }, { status: 403 });
    }
    if (!req.headers.get("content-type")?.startsWith("application/json")) {
      return NextResponse.json({ detail: "JSON request required" }, { status: 415 });
    }
    if (!process.env.CLOUDSENTINEL_WRITE_TOKEN) {
      return NextResponse.json({ detail: "Local write token is not configured" }, { status: 403 });
    }
  }
  const upstreamBase = process.env.UPSTREAM_API_URL || "http://127.0.0.1:8000";
  const url = new URL(`${upstreamBase}/api/v1/${endpoint}`);
  if (method === "GET") url.search = req.nextUrl.search;
  const headers: Record<string, string> = {};
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-Local-Token"] = process.env.CLOUDSENTINEL_WRITE_TOKEN!;
  }
  try {
    let body: string | undefined;
    if (method !== "GET") {
      if (endpoint.startsWith("settings/data/")) {
        const reader=req.body?.getReader(); const chunks: Uint8Array[]=[]; let size=0;
        if(reader) { while(true) { const {done,value}=await reader.read(); if(done) break; size+=value.byteLength;
          if(size>20*1024*1024+4096) { await reader.cancel(); return NextResponse.json({detail:"Archive exceeds 20 MB."},{status:413}); } chunks.push(value); } }
        body=Buffer.concat(chunks).toString("utf8");
      } else body=await req.text();
    }
    const response = await fetch(url, {
      method, headers,
      body,
      cache: "no-store",
      signal: AbortSignal.timeout(method === "POST" ? 110000 : 15000),
    });
    const data = await response.text();
    return new NextResponse(data, {
      status: response.status,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
  } catch (error) {
    const timeout=error instanceof Error && (error.name==="TimeoutError" || error.name==="AbortError");
    return NextResponse.json({ detail: timeout
      ? "The local API took too long to respond. Check server logs and refresh status before retrying a write."
      : "Cannot reach the local API. Start CloudSentinel with Start CloudSentinel.cmd (Windows) or bash scripts/start-linux.sh (Linux), then retry.",
      code: timeout?"API_TIMEOUT":"API_UNREACHABLE" }, { status: timeout?504:502 });
  }
}

type Params = { params: Promise<{ path: string[] }> };
export async function GET(req: NextRequest, context: Params) {
  return proxy(req, (await context.params).path, "GET");
}
export async function PATCH(req: NextRequest, context: Params) {
  return proxy(req, (await context.params).path, "PATCH");
}
export async function POST(req: NextRequest, context: Params) {
  return proxy(req, (await context.params).path, "POST");
}

export async function PUT(req: NextRequest, context: Params) {
  return proxy(req, (await context.params).path, "PUT");
}
