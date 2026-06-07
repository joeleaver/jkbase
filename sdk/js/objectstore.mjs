// jkbase object store — JavaScript SDK (the JS half of the SDK card).
//
// A SigV4-signing S3 client built on Web Crypto + fetch (works in Node 18+,
// Deno, and browsers — no dependencies, no AWS SDK). Its canonicalisation is
// pinned to the Rust server's verification by the shared vectors in
// objectstore.test.mjs, so a JS-signed request validates server-side.

const ENC = new TextEncoder();

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(str) {
  const d = await crypto.subtle.digest("SHA-256", ENC.encode(str));
  return hex(new Uint8Array(d));
}

async function hmac(keyBytes, msg) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const data = typeof msg === "string" ? ENC.encode(msg) : msg;
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}

async function signingKey(secret, date, region) {
  let k = await hmac(ENC.encode("AWS4" + secret), date);
  k = await hmac(k, region);
  k = await hmac(k, "s3");
  k = await hmac(k, "aws4_request");
  return k;
}

// RFC 3986 percent-encoding (leaves `/` intact in paths when encodeSlash=false).
function uriEncode(s, encodeSlash) {
  let out = "";
  for (const b of ENC.encode(s)) {
    const c = String.fromCharCode(b);
    if (/[A-Za-z0-9\-._~]/.test(c)) out += c;
    else if (c === "/" && !encodeSlash) out += "/";
    else out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

function canonicalQuery(pairs, exclude) {
  return pairs
    .filter(([k]) => k !== exclude)
    .map(([k, v]) => [uriEncode(k, true), uriEncode(v, true)])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
}

function amzDate(nowUnix) {
  return new Date(nowUnix * 1000).toISOString().replace(/[:-]/g, "").replace(/\.\d{3}Z$/, "Z");
}
function dateStamp(nowUnix) {
  return amzDate(nowUnix).slice(0, 8);
}

/** Sign with an Authorization header (host;x-amz-content-sha256;x-amz-date). */
export async function signHeader(method, host, path, query, payloadHash, accessKey, secret, region, nowUnix) {
  const amzd = amzDate(nowUnix);
  const scope = `${dateStamp(nowUnix)}/${region}/s3/aws4_request`;
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";
  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzd}\n`;
  const creq = `${method}\n${uriEncode(path, false)}\n${canonicalQuery(query, "")}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
  const sts = `AWS4-HMAC-SHA256\n${amzd}\n${scope}\n${await sha256Hex(creq)}`;
  const sig = hex(await hmac(await signingKey(secret, dateStamp(nowUnix), region), sts));
  return {
    authorization: `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${sig}`,
    amzDate: amzd,
  };
}

/** Mint a presigned URL path+query valid for `expires` seconds. */
export async function presign(method, host, path, accessKey, secret, region, expires, nowUnix) {
  const amzd = amzDate(nowUnix);
  const scope = `${dateStamp(nowUnix)}/${region}/s3/aws4_request`;
  const params = [
    ["X-Amz-Algorithm", "AWS4-HMAC-SHA256"],
    ["X-Amz-Credential", `${accessKey}/${scope}`],
    ["X-Amz-Date", amzd],
    ["X-Amz-Expires", String(expires)],
    ["X-Amz-SignedHeaders", "host"],
  ];
  const creq = `${method}\n${uriEncode(path, false)}\n${canonicalQuery(params, "")}\nhost:${host}\n\nhost\nUNSIGNED-PAYLOAD`;
  const sts = `AWS4-HMAC-SHA256\n${amzd}\n${scope}\n${await sha256Hex(creq)}`;
  const sig = hex(await hmac(await signingKey(secret, dateStamp(nowUnix), region), sts));
  params.push(["X-Amz-Signature", sig]);
  const qs = params.map(([k, v]) => `${uriEncode(k, true)}=${uriEncode(v, true)}`).join("&");
  return `${path}?${qs}`;
}

/** A signed object-store client bound to one set of credentials + endpoint. */
export class ObjectClient {
  constructor(baseUrl, accessKey, secret, region = "us-east-1") {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.host = this.baseUrl.replace(/^[a-z]+:\/\//, "").split("/")[0];
    this.accessKey = accessKey;
    this.secret = secret;
    this.region = region;
  }

  async #send(method, path, query, contentType, body) {
    const now = Math.floor(Date.now() / 1000);
    const { authorization, amzDate } = await signHeader(
      method, this.host, path, query, "UNSIGNED-PAYLOAD", this.accessKey, this.secret, this.region, now,
    );
    let url = this.baseUrl + path;
    if (query.length) {
      url += "?" + query.map(([k, v]) => `${uriEncode(k, true)}=${uriEncode(v, true)}`).join("&");
    }
    const headers = {
      authorization: authorization,
      "x-amz-date": amzDate,
      "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
    };
    if (contentType) headers["content-type"] = contentType;
    const resp = await fetch(url, { method, headers, body });
    if (!resp.ok) throw new Error(`object store ${resp.status}: ${await resp.text()}`);
    return resp;
  }

  async createBucket(bucket) {
    await this.#send("PUT", `/${bucket}`, [], null, "");
  }
  async putObject(bucket, key, body, contentType = "application/octet-stream") {
    const r = await this.#send("PUT", `/${bucket}/${key}`, [], contentType, body);
    return r.headers.get("etag");
  }
  async getObject(bucket, key) {
    const r = await this.#send("GET", `/${bucket}/${key}`, [], null, null);
    return new Uint8Array(await r.arrayBuffer());
  }
  async deleteObject(bucket, key) {
    await this.#send("DELETE", `/${bucket}/${key}`, [], null, null);
  }
  async listObjects(bucket, prefix = "") {
    const query = prefix ? [["prefix", prefix]] : [];
    const xml = await (await this.#send("GET", `/${bucket}`, query, null, null)).text();
    return [...xml.matchAll(/<Key>(.*?)<\/Key>/g)].map((m) => m[1]);
  }
  async presignedGet(bucket, key, expires = 900) {
    const p = await presign("GET", this.host, `/${bucket}/${key}`, this.accessKey, this.secret, this.region, expires, Math.floor(Date.now() / 1000));
    return this.baseUrl + p;
  }
}
