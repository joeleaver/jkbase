// Cross-validates the JS SigV4 implementation against the Rust server's vectors
// (jkbase-objectstore::sigv4 cross_vector tests). Equal signatures for the same
// inputs is exactly what makes a JS-signed request verify on the Rust server.
//
// Run: node --test sdk/js/

import { test } from "node:test";
import assert from "node:assert/strict";
import { signHeader, presign } from "./objectstore.mjs";

const NOW = 1_700_000_000;

test("header signature matches the Rust vector", async () => {
  const { authorization, amzDate } = await signHeader(
    "GET", "s3.test", "/b/k", [], "UNSIGNED-PAYLOAD", "AKID", "SECRET", "us-east-1", NOW,
  );
  assert.equal(amzDate, "20231114T221320Z");
  assert.ok(
    authorization.endsWith(
      "Signature=0f0c7b988b19fb25857e216bac0116a054f0cb91696c0ae00e81bb06520cf115",
    ),
    authorization,
  );
});

test("presign signature matches the Rust vector", async () => {
  const url = await presign("GET", "s3.test", "/b/k", "AKID", "SECRET", "us-east-1", 900, NOW);
  assert.ok(
    url.endsWith(
      "X-Amz-Signature=67dfd03db2009a8216e3779a68cb239b0ba9579b44c4b3fe168cd0b0bab28614",
    ),
    url,
  );
});
