export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try { response = await fetch(`/api/v1/${path}`, { ...init, cache: "no-store" }); }
  catch(e) { throw new Error(e instanceof Error && (e.name==="TimeoutError"||e.name==="AbortError")
    ? "Connection check timed out. Check service logs and retry."
    : "Cannot reach the local web server. Start CloudSentinel and reload this page."); }
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try { const body = await response.json(); message = body.detail || message; } catch { /* empty */ }
    throw new Error(typeof message === "string" ? message : JSON.stringify(message));
  }
  return response.json() as Promise<T>;
}
export function formatDate(value?: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
