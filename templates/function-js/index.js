// A minimal jkbase JS function: a `wasi:http` component.
//
// Write a Service-Worker-style `fetch` handler — the platform builds this to a
// component server-side (esbuild bundle → ComponentizeJS/StarlingMonkey) and runs it in
// the per-project microVM. The same `wasi:http/incoming-handler` ABI as every other
// jkbase function language. TypeScript works too (rename to `index.ts`; esbuild handles it).
//
// Available today: the request, response, compute, your project's **secrets** via
// `process.env`, and host-mediated **outbound HTTP** (`fetch`) — policed per-function by
// `egress` in `jkbase.toml` (default: public allowed + observed; `egress = ["host", ...]`
// to enforce an allowlist; `egress = false` to sandbox). The `egress` line below probes a
// real outbound request and reports whether the host allowed it.

addEventListener('fetch', (event) => {
  event.respondWith(handle(event.request));
});

async function handle(request) {
  const url = new URL(request.url);
  const egress = await probeEgress();
  // Project secrets are injected as env vars (empty until you set one).
  const demo = process.env.DEMO_SECRET || '<unset>';
  const body =
    'hello from a JS wasi:http component\n' +
    `method=${request.method}\n` +
    `path=${url.pathname}\n` +
    `egress=${egress}\n` +
    `DEMO_SECRET=${demo}\n`;
  return new Response(body, { headers: { 'content-type': 'text/plain' } });
}

// Probe outbound HTTP. `fetch` succeeds when the host allows the destination (default
// policy, or on your `egress` allowlist) and rejects otherwise (sandbox, off-allowlist, or
// a platform/internal address). So we AWAIT it: ALLOWED only when a response arrives.
async function probeEgress() {
  try {
    await fetch('https://example.com/');
    return 'ALLOWED';
  } catch {
    return 'DENIED';
  }
}
