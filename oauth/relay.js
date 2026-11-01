// The sign-in relay (docs/SPEC.md §6). Platforms send people back here after they log in, because they only
// accept fixed HTTPS addresses; this page forwards the answer (?code=…&state=… or ?error=…) to the BeduSocial
// computer that started the sign-in. It never sees a secret: the code is useless without the app secret, which
// stays on that computer, and BeduSocial checks the state's signature, nonce and expiry itself.
//
// state = "<payload>.<signature>", payload = base64url(JSON) with "h": the BeduSocial host (and port) to return to.
// Only these hosts are allowed: localhost and 127.0.0.1 (this PC), *.ts.net (Tailscale), *.trycloudflare.com
// (the short-lived tunnels used for "share a link to connect").

const LOCAL = /^(localhost|127\.0\.0\.1)(:\d{1,5})?$/;
const TAILSCALE = /^[a-z0-9-]+(\.[a-z0-9-]+)*\.ts\.net(:\d{1,5})?$/;
const TUNNEL = /^[a-z0-9-]+\.trycloudflare\.com$/;
const CALLBACK = "/api/oauth/callback";

function decodePayload(state) {
  const payload = state.split(".")[0];
  if (!payload || !/^[A-Za-z0-9_-]+$/.test(payload)) return null;
  const base64 = payload.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(payload.length / 4) * 4, "=");
  try {
    const value = JSON.parse(atob(base64));
    return value && typeof value === "object" ? value : null;
  } catch {
    return null;
  }
}

/** Where to send the browser for this query string, or null when the state doesn't name an allowed host. */
export function target(search) {
  const params = new URLSearchParams(search);
  const state = params.get("state");
  if (!state) return null;
  const host = decodePayload(state)?.h;
  if (typeof host !== "string") return null;
  const name = host.toLowerCase();
  let scheme;
  if (LOCAL.test(name)) scheme = "http";
  else if (TAILSCALE.test(name) || TUNNEL.test(name)) scheme = "https";
  else return null;
  return `${scheme}://${name}${CALLBACK}?${params.toString()}`;
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  const next = target(window.location.search);
  if (next) {
    window.location.replace(next);
  } else {
    document.querySelector("h1").textContent = "Sign-in stopped";
    document.getElementById("status").textContent =
      "This sign-in link doesn't belong to a BeduSocial computer, so it was stopped here. Start the sign-in again from BeduSocial.";
    document.getElementById("status").classList.add("error");
  }
}
