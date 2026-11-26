// Capture passkey assertions from Chrome's virtual authenticator.
//
// Usage: node tools/webauthn-vectors/capture.mjs [chrome] > vectors.json
//
// Chrome runs headless with a CTAP2 internal authenticator that verifies the
// user. One ES256 credential is registered on http://localhost, and assertions
// are requested for fixed digests until both client data forms Chrome emits
// have been seen: with and without `other_keys_can_be_added_here`.

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const chrome = process.argv[2]
  ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const sha256 = (text) => createHash('sha256').update(text).digest();

function base58(bytes) {
  let value = BigInt(`0x${hex(bytes)}`);
  let out = '';
  while (value > 0n) {
    out = BASE58[Number(value % 58n)] + out;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    out = `1${out}`;
  }
  return out;
}

function did(uncompressed) {
  const x = uncompressed.subarray(1, 33);
  const prefix = (uncompressed[64] & 1) === 0 ? 0x02 : 0x03;
  return `did:key:z${base58(Buffer.concat([Buffer.from([0x80, 0x24, prefix]), x]))}`;
}

function rawSignature(der) {
  const integer = (at) => {
    if (der[at] !== 0x02) throw new Error('not a DER integer');
    const length = der[at + 1];
    return [BigInt(`0x${hex(der.subarray(at + 2, at + 2 + length))}`), at + 2 + length];
  };
  if (der[0] !== 0x30) throw new Error('not a DER sequence');
  const [r, next] = integer(2);
  let [s] = integer(next);
  if (s > N / 2n) s = N - s;
  const word = (value) => value.toString(16).padStart(64, '0');
  return word(r) + word(s);
}

async function devtools(directory) {
  const file = join(directory, 'DevToolsActivePort');
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const [port] = readFileSync(file, 'utf8').split('\n');
      const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const page = pages.find((target) => target.type === 'page');
      if (page) return page.webSocketDebuggerUrl;
    } catch {
      // Chrome has not written the port yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('Chrome did not open a debugging port');
}

function session(url) {
  const socket = new WebSocket(url);
  let next = 0;
  const pending = new Map();
  socket.addEventListener('message', (event) => {
    const message = JSON.parse(event.data);
    const waiter = pending.get(message.id);
    if (!waiter) return;
    pending.delete(message.id);
    if (message.error) waiter.reject(new Error(JSON.stringify(message.error)));
    else waiter.resolve(message.result);
  });
  const opened = new Promise((resolve) => socket.addEventListener('open', resolve));
  const send = async (method, params = {}) => {
    await opened;
    next += 1;
    const id = next;
    socket.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
  };
  return { send, close: () => socket.close() };
}

const PAGE = `<!doctype html><meta charset="utf-8"><script>
const b64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));
const bytes = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
window.register = async () => {
  const credential = await navigator.credentials.create({ publicKey: {
    rp: { id: 'localhost', name: 'vectors' },
    user: { id: new Uint8Array(16), name: 'vectors', displayName: 'vectors' },
    challenge: new Uint8Array(32),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { userVerification: 'required', residentKey: 'required' },
  } });
  return { id: b64(credential.rawId), spki: b64(credential.response.getPublicKey()) };
};
window.assert = async (id, digest) => {
  const assertion = await navigator.credentials.get({ publicKey: {
    rpId: 'localhost',
    challenge: bytes(digest),
    allowCredentials: [{ type: 'public-key', id: bytes(id) }],
    userVerification: 'required',
  } });
  return {
    authenticatorData: b64(assertion.response.authenticatorData),
    clientDataJSON: b64(assertion.response.clientDataJSON),
    signature: b64(assertion.response.signature),
  };
};
</script>`;

async function evaluate(page, expression) {
  const result = await page.send('Runtime.evaluate', {
    expression, awaitPromise: true, returnByValue: true,
  });
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  return result.result.value;
}

async function main() {
  const server = createServer((_, response) => {
    response.setHeader('content-type', 'text/html');
    response.end(PAGE);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const directory = mkdtempSync(join(tmpdir(), 'webauthn-vectors-'));
  const browser = spawn(chrome, [
    '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${directory}`,
    '--no-first-run', '--no-default-browser-check', 'about:blank',
  ], { stdio: 'ignore' });
  try {
    const page = session(await devtools(directory));
    const version = await page.send('Runtime.evaluate', {
      expression: 'navigator.userAgent', returnByValue: true,
    });
    await page.send('Page.enable');
    await page.send('Page.navigate', { url: `http://localhost:${server.address().port}/` });
    await new Promise((resolve) => setTimeout(resolve, 1000));
    await page.send('WebAuthn.enable', { enableUI: false });
    await page.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    } });
    const credential = await evaluate(page, 'window.register()');
    const spki = Buffer.from(credential.spki, 'base64');
    const point = spki.subarray(spki.length - 65);
    const actor = did(point);
    const vectors = [];
    const seen = new Set();
    for (let attempt = 0; attempt < 200 && seen.size < 2; attempt += 1) {
      const digest = sha256(`vera passkey vector ${attempt}`);
      const signed = await evaluate(
        page, `window.assert(${JSON.stringify(credential.id)}, ${JSON.stringify(digest.toString('base64'))})`,
      );
      const clientData = Buffer.from(signed.clientDataJSON, 'base64');
      const form = clientData.includes('other_keys_can_be_added_here') ? 'extra' : 'plain';
      if (seen.has(form)) continue;
      seen.add(form);
      const der = Buffer.from(signed.signature, 'base64');
      vectors.push({
        source: version.result.value,
        client_data_form: form,
        did: actor,
        public_key: hex(point),
        digest: hex(digest),
        authenticator_data: hex(Buffer.from(signed.authenticatorData, 'base64')),
        client_data_json: clientData.toString('utf8'),
        der_signature: hex(der),
        signature: rawSignature(der),
      });
    }
    page.close();
    process.stdout.write(`${JSON.stringify(vectors, null, 2)}\n`);
  } finally {
    const exited = new Promise((resolve) => browser.once('exit', resolve));
    browser.kill();
    await exited;
    server.close();
    rmSync(directory, { recursive: true, force: true });
  }
}

await main();
