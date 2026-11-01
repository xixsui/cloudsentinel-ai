import assert from "node:assert/strict";
import test from "node:test";
import { isValidLocalWriteOrigin } from "../src/lib/localOrigin.ts";

const headers = (host, origin, fetchSite = "same-origin") =>
  new Headers({ ...(host ? { host } : {}), ...(origin ? { origin } : {}),
    ...(fetchSite ? { "sec-fetch-site": fetchSite } : {}) });

test("localhost same-origin writes pass", () => {
  assert.equal(isValidLocalWriteOrigin(headers("localhost:3000", "http://localhost:3000")), true);
});
test("127.0.0.1 same-origin writes pass", () => {
  assert.equal(isValidLocalWriteOrigin(headers("127.0.0.1:3000", "http://127.0.0.1:3000")), true);
});
test("IPv6 loopback same-origin writes pass", () => {
  assert.equal(isValidLocalWriteOrigin(headers("[::1]:3000", "http://[::1]:3000")), true);
});
test("localhost vs 127.0.0.1 mismatch is rejected", () => {
  assert.equal(isValidLocalWriteOrigin(headers("localhost:3000", "http://127.0.0.1:3000")), false);
});
test("different ports are rejected", () => {
  assert.equal(isValidLocalWriteOrigin(headers("localhost:3000", "http://localhost:4000")), false);
});
test("cross-site fetch is rejected", () => {
  assert.equal(isValidLocalWriteOrigin(headers("localhost:3000", "http://localhost:3000", "cross-site")), false);
});
test("missing Origin is rejected", () => {
  assert.equal(isValidLocalWriteOrigin(headers("localhost:3000", null)), false);
});
test("external Host and matching external Origin are both rejected", () => {
  assert.equal(isValidLocalWriteOrigin(headers("evil.example:3000", "http://evil.example:3000")), false);
});
test("invalid Host is rejected", () => {
  assert.equal(isValidLocalWriteOrigin(headers("localhost:3000/evil", "http://localhost:3000")), false);
});
test("https Origin is rejected by the local HTTP dev proxy", () => {
  assert.equal(isValidLocalWriteOrigin(headers("localhost:3000", "https://localhost:3000")), false);
});
