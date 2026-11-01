/**
 * Strict local-dev write origin validation.
 *
 * Next.js may normalize request.nextUrl.origin to the server bind address
 * (127.0.0.1) while a user's browser correctly sends localhost in Origin.
 * Compare against the incoming HTTP Host instead, and reject non-loopback
 * hosts to avoid DNS rebinding bypasses of the local-only development proxy.
 *
 * This is not authentication or sufficient for public deployments.
 */
export function isValidLocalWriteOrigin(headers: { get(name: string): string | null }): boolean {
  const incomingHost = headers.get("host");
  const origin = headers.get("origin");
  const fetchSite = headers.get("sec-fetch-site");
  if (!incomingHost || !origin || fetchSite === "cross-site") return false;

  try {
    const hostUrl = new URL(`http://${incomingHost}`);
    const originUrl = new URL(origin);
    const isLoopbackHost = ["localhost", "127.0.0.1", "[::1]"].includes(hostUrl.hostname);
    // Only a Host header with an optional port is acceptable.
    const isBareHost =
      !hostUrl.username && !hostUrl.password &&
      hostUrl.pathname === "/" && !hostUrl.search && !hostUrl.hash;
    return isLoopbackHost && isBareHost && origin === originUrl.origin &&
      originUrl.origin === `http://${hostUrl.host}`;
  } catch {
    return false;
  }
}
