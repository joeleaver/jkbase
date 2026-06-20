// A minimal jkbase JS function: a `wasi:http` component.
//
// Write a Service-Worker-style `fetch` handler — the platform builds this to a
// component server-side (esbuild bundle → ComponentizeJS/StarlingMonkey) and runs it in
// the per-project microVM. The same `wasi:http/incoming-handler` ABI as every other
// jkbase function language. TypeScript works too (rename to `index.ts`; esbuild handles it).
//
// Available today: the request, response, and compute. NOT available yet: outbound
// network (`fetch`) and object-store access — those arrive together in the host-mediated
// outbound-I/O work; until then an outbound request is denied by the platform (shown by
// the `egress` line below).

addEventListener('fetch', (event) => {
  event.respondWith(handle(event.request));
});

async function handle(request) {
  const url = new URL(request.url);
  const egress = await probeEgress();
  const body =
    'hello from a JS wasi:http component\n' +
    `method=${request.method}\n` +
    `path=${url.pathname}\n` +
    `egress=${egress}\n`;
  return new Response(body, { headers: { 'content-type': 'text/plain' } });
}

// The platform denies all egress today, so this reports DENIED (the host rejects the
// outbound request before any socket opens).
async function probeEgress() {
  try {
    await fetch('https://example.com/');
    return 'ALLOWED';
  } catch {
    return 'DENIED';
  }
}
