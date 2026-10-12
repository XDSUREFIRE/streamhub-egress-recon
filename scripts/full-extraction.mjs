// Standalone runner diagnostic. No app, gateway, or persistent credentials.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const entry = 'https://vidsrc.to/embed/movie/550';
const started = Date.now();
const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.7922.34 Safari/537.36';
const clean = (x, base) => new URL(x.replaceAll('&amp;', '&'), base).href;
const masked = x => { const u = new URL(x); for (const k of u.searchParams.keys()) if (!['w','_','v','type','id','tmdb','stream_urls'].includes(k)) u.searchParams.set(k, 'REDACTED'); return u.href; };
const log = x => console.log(JSON.stringify(x));
const config = (html, name) => { const marker = `window.${name} = `; const start = html.indexOf(marker); if (start < 0) throw Error(`Missing ${name}`); return JSON.parse(html.slice(start + marker.length, html.indexOf(';</script>', start))); };
async function get(label, url, referer, extra = {}, binary = false) {
  const headers = { 'User-Agent': ua, Accept: '*/*', 'Accept-Language': 'en-US,en;q=0.9', ...(referer ? { Referer: new URL(referer).origin + '/' } : {}), ...extra };
  let r;
  if (process.env.PROBE_TRANSPORT === 'curl') {
    const dir = mkdtempSync(join(tmpdir(), 'streamhub-probe-'));
    try {
      const args = ['--silent','--show-error','--location','--max-time','25','--dump-header',join(dir,'headers'),'--output',join(dir,'body'),'--write-out','%{http_code}\n%{url_effective}'];
      for (const [k,v] of Object.entries(headers)) args.push('--header',`${k}: ${v}`);
      args.push(clean(url));
      const result = spawnSync('curl',args,{encoding:'utf8'});
      if (result.status !== 0) throw Error(`curl exit ${result.status}`);
      const [status, finalUrl] = result.stdout.trim().split('\n');
      const blocks = readFileSync(join(dir,'headers'),'utf8').trim().split(/\r?\n\r?\n/);
      const responseHeaders = new Headers();
      for (const line of blocks.at(-1).split(/\r?\n/).slice(1)) { const colon = line.indexOf(':'); if (colon > 0) responseHeaders.append(line.slice(0,colon),line.slice(colon+1).trim()); }
      r = new Response(readFileSync(join(dir,'body')), { status: Number(status), headers: responseHeaders });
      Object.defineProperty(r,'url',{value:finalUrl});
    } finally { rmSync(dir,{recursive:true}); }
  } else r = await fetch(clean(url), { headers, signal: AbortSignal.timeout(25000) });
  log({ label, url: masked(url), finalUrl: masked(r.url), status: r.status, headers: Object.fromEntries([...r.headers].map(([k,v]) => [k, k === 'set-cookie' ? 'REDACTED' : v])) });
  if (!r.ok) { const body = await r.text(); log({ label, errorBody: body.slice(0,1500) }); throw Error(`${label}: HTTP ${r.status}`); }
  return { r, body: binary ? null : await r.text(), url: r.url };
}
try {
  log({ startedAt: new Date(started).toISOString(), runtime: process.version, runner: process.env.RUNNER_NAME, runId: process.env.GITHUB_RUN_ID });
  const outer = await get('movie-embed', entry);
  const iframe = outer.body.match(/<iframe\b[^>]*\bsrc=["'](https:\/\/[^"']+)["']/i)?.[1];
  if (!iframe) throw Error('No outer iframe');
  const wrapper = await get('wrapper', clean(iframe, outer.url), outer.url);
  const apiPath = wrapper.body.match(/<iframe\b[^>]*\bdata-api=["']([^"']+)["']/i)?.[1];
  if (!apiPath) throw Error('No data-api');
  const gate = await get('wrapper-token-json', clean(apiPath, wrapper.url), wrapper.url);
  const landing = await get('landing', clean(JSON.parse(gate.body).src, gate.url), wrapper.url);
  const player = await get('player-page', clean(config(landing.body, 'CFG').playerUrl, landing.url), landing.url);
  const cfg = config(player.body, 'CONFIG');
  const scriptPath = [...player.body.matchAll(/<script\b[^>]*src=["']([^"']+)["']/gi)].map(m => m[1]).find(x => /\/player\.js(?:\?|$)/.test(x));
  if (!scriptPath) throw Error('No player script');
  const script = await get('player-script', clean(scriptPath, player.url), player.url);
  const tokenPath = script.body.match(/fetchToken\(origin\s*\+\s*(['"])([^'"]+)\1\)/)?.[2];
  if (!tokenPath) throw Error('No token path in current script');
  const headers = { Origin: new URL(player.url).origin };
  const apiUrl = new URL(clean(cfg.api, player.url)); apiUrl.searchParams.set('api_token', cfg.apiToken);
  const api = await get('stream-api', apiUrl.href, player.url, { ...headers, Accept: 'application/json' });
  const data = JSON.parse(api.body);
  if (typeof data.data?.stream_urls !== 'string' || !data.vs?.wasm_url) throw Error('Expected encrypted sources and dynamically supplied WASM URL');
  const wasm = await get('dynamic-wasm', clean(data.vs.wasm_url, api.url), player.url, headers, true);
  const bytes = await wasm.r.arrayBuffer();
  const module = await WebAssembly.compile(bytes);
  const instance = await WebAssembly.instantiate(module, {});
  const encrypted = Uint8Array.from(atob(data.data.stream_urls), c => c.charCodeAt(0));
  const ptr = instance.exports.alloc(encrypted.length);
  new Uint8Array(instance.exports.memory.buffer, ptr, encrypted.length).set(encrypted);
  const length = instance.exports.decrypt(ptr, encrypted.length);
  const sources = new TextDecoder().decode(new Uint8Array(instance.exports.memory.buffer, ptr + 12, length)).split('\n').filter(Boolean);
  if (!sources.length) throw Error('Empty decoded sources');
  log({ dynamicWasmDecoded: true, wasmBytes: bytes.byteLength, sourceCount: sources.length, sources: sources.map(masked) });
  const raw = clean(sources[0], api.url);
  const issued = await get('fresh-host-token', clean(tokenPath, new URL(raw).origin), player.url, headers);
  let token = issued.body.trim(); try { const j = JSON.parse(token); token = typeof j === 'string' ? j : j.token || j.data || j.string || j.result; } catch {}
  if (!token || token.startsWith('<')) throw Error('Invalid host token');
  let claims; try { claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url')); } catch {}
  log({ freshTokenIssued: true, issuedDuringThisRun: true, iat: claims?.iat, exp: claims?.exp, lifetimeSeconds: claims?.exp - claims?.iat, ipBound: !!claims?.ip_cidr });
  const signed = raw.includes('__TOKEN__') ? raw.replaceAll('__TOKEN__', token) : raw + (raw.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(token);
  const firstUri = text => text.split(/\r?\n/).map(x => x.trim()).find(x => x && !x.startsWith('#'));
  const master = await get('master', signed, player.url, headers);
  if (!master.body.startsWith('#EXTM3U')) throw Error('Master is not HLS');
  const variant = await get('variant', clean(firstUri(master.body), master.url), player.url, headers);
  if (!variant.body.startsWith('#EXTM3U')) throw Error('Variant is not HLS');
  const segment = await get('segment', clean(firstUri(variant.body), variant.url), player.url, { ...headers, Range: 'bytes=0-4095' }, true);
  const reader = segment.r.body.getReader(); const chunks = []; let size = 0;
  while (size < 4096) { const x = await reader.read(); if (x.done) break; chunks.push(x.value); size += x.value.length; } await reader.cancel();
  const sample = Buffer.concat(chunks);
  const ts = sample[0] === 0x47 && sample[188] === 0x47 && sample[376] === 0x47;
  log({ result: ts && [master,variant,segment].every(x => x.r.status === 200) ? 'PASSED' : 'FAILED', master: master.r.status, variant: variant.r.status, segment: segment.r.status, sampleBytes: size, mpegTsSyncOffsets: [0,188,376].map(i => sample[i]), validMpegTs: ts, finishedAt: new Date().toISOString() });
  if (!ts || [master,variant,segment].some(x => x.r.status !== 200)) process.exitCode = 1;
} catch (error) { log({ result: 'BLOCKED', error: error.message, finishedAt: new Date().toISOString() }); process.exitCode = 1; }
