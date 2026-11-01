export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/v1/${path}`, { ...init, cache: "no-store" });
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
