// Different-network proof only. This receives an ephemeral MEDIA capability,
// never a resolver credential. No raw capability/manifest is logged or saved.
import { createServer } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash, createDecipheriv } from 'node:crypto';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

// Gateway rewrites every URI to a signed capability; that expansion makes a
// valid sub-1MiB upstream playlist larger. Keep the rewritten response bounded.
const MAX_MANIFEST = 8 * 1024 * 1024;
const MAX_SEGMENT = 16 * 1024 * 1024;
const SAFE_HEADERS = ['content-type', 'content-length', 'content-range', 'accept-ranges', 'access-control-allow-origin',
  'access-control-allow-methods', 'cache-control', 'server', 'cf-ray'];
const require = createRequire(import.meta.url);
class ProofError extends Error { constructor(code) { super(code); this.code = code; } }
const fail = code => { throw new ProofError(code); };
const safeCode = value => /^[A-Z0-9_:-]{1,120}$/i.test(String(value)) ? String(value) : 'REMOTE_VALIDATION_ERROR';
const headersProof = headers => Object.fromEntries(SAFE_HEADERS.filter(key => headers[key] !== undefined).map(key => [key, String(headers[key])]));

export function normalizeTestOptions({ quality = 'lowest', seconds = 3 } = {}) {
  if (!['lowest', 'highest'].includes(quality)) fail('INVALID_TEST_QUALITY');
  if (!/^(?:[3-9]|[1-5]\d|60)$/.test(String(seconds))) fail('INVALID_TEST_SECONDS');
  return { quality, seconds: Number(seconds) };
}

function dimensions(variant) {
  const pair = /^([1-9]\d{0,4})x([1-9]\d{0,4})$/.exec(variant.resolution || '');
  const width = Number(variant.width || pair?.[1]) || null;
  const height = Number(variant.height || pair?.[2]) || null;
  return { width, height, area: width && height ? width * height : 0 };
}

export function selectVariant(variants, quality = 'lowest') {
  if (!['lowest', 'highest'].includes(quality) || !Array.isArray(variants) || !variants.length) fail('INVALID_VARIANT_SELECTION');
  const bitrate = variant => Number(variant.bandwidth ?? variant.bitrate) > 0 ? Number(variant.bandwidth ?? variant.bitrate) : 0;
  return [...variants].sort((first, second) => quality === 'highest'
    ? dimensions(second).area - dimensions(first).area || bitrate(second) - bitrate(first)
    : (bitrate(first) || Number.MAX_SAFE_INTEGER) - (bitrate(second) || Number.MAX_SAFE_INTEGER))[0];
}

export function evaluateDecodedProof(proof, { quality = 'lowest', seconds = 3, expected = {} } = {}) {
  const required = normalizeTestOptions({ quality, seconds });
  const hasExpected = Number(expected.width) > 0 && Number(expected.height) > 0;
  return Boolean(!proof.fatal && !proof.qualityFallback && !proof.frameResolutionMismatch && !proof.timelineDiscontinuity &&
    proof.frameCallbacks >= 20 && proof.decodedSeconds >= required.seconds && proof.decodedWallSeconds >= required.seconds - 0.25 &&
    proof.width > 0 && proof.height > 0 && proof.manualQualityLocked === true && proof.selectedLevel &&
    (!(expected.bandwidth > 0) || proof.selectedLevel.bandwidth === expected.bandwidth) &&
    (!hasExpected || (proof.selectedLevel.width === expected.width && proof.selectedLevel.height === expected.height)) &&
    (!hasExpected || (proof.width === expected.width && proof.height === expected.height && proof.frameDimensionsMatch === true)) &&
    (quality !== 'highest' || hasExpected));
}

function httpsUrl(value, base) {
  let url;
  try { url = new URL(value, base); } catch { fail('INVALID_HTTPS_URL'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.href.length > 32_768) fail('INVALID_HTTPS_URL');
  return url;
}

function mediaUrl(value, base, origin) {
  const url = httpsUrl(value, base);
  if (url.origin !== origin || !/^\/media\/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/.test(url.pathname) || url.search) {
    fail('MANIFEST_CONTAINS_NON_GATEWAY_MEDIA');
  }
  return url.href;
}

async function fetchBytes(target, { limit = MAX_MANIFEST, timeout = 45_000, headers = {} } = {}) {
  const url = httpsUrl(target);
  return new Promise((accept, reject) => {
    const request = httpsRequest(url, { family: 4, headers: { Accept: '*/*', 'Accept-Encoding': 'identity', ...headers },
      signal: AbortSignal.timeout(timeout) }, response => {
      const chunks = [];
      let bytes = 0;
      if (Number(response.headers['content-length']) > limit) { response.destroy(); reject(new ProofError('BODY_LIMIT_EXCEEDED')); return; }
      response.on('data', part => {
        bytes += part.length;
        if (bytes > limit) { response.destroy(); reject(new ProofError('BODY_LIMIT_EXCEEDED')); }
        else chunks.push(part);
      });
      response.on('end', () => accept({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks), bytes }));
      response.on('error', () => reject(new ProofError('UPSTREAM_BODY_ERROR')));
    });
    request.on('error', () => reject(new ProofError('UPSTREAM_REQUEST_ERROR')));
    request.end();
  });
}

function attributes(line) {
  return Object.fromEntries([...line.matchAll(/([A-Z0-9-]+)=("[^"]*"|[^,]*)/g)].map(match => [match[1], match[2].replace(/^"|"$/g, '')]));
}

export function parseMaster(text, base, origin) {
  if (!text.replace(/^\uFEFF/, '').trimStart().startsWith('#EXTM3U')) fail('INVALID_MASTER_MANIFEST');
  const lines = text.split(/\r?\n/).map(line => line.trim());
  const choices = [];
  for (let index = 0; index < lines.length; index++) {
    // Validate alternate audio, subtitle, key and iframe URI attributes too.
    for (const match of lines[index].matchAll(/\bURI="([^"\r\n]+)"/g)) mediaUrl(match[1], base, origin);
    if (lines[index].startsWith('#EXT-X-STREAM-INF:')) {
      const attrs = attributes(lines[index]);
      const next = lines.slice(index + 1).find(line => line && !line.startsWith('#'));
      if (!next) fail('MISSING_VARIANT_URI');
      const resolution = /^\d+x\d+$/.test(attrs.RESOLUTION || '') ? attrs.RESOLUTION : null;
      choices.push({ url: mediaUrl(next, base, origin), bandwidth: Number(attrs.BANDWIDTH) || Number(attrs['AVERAGE-BANDWIDTH']) || 0,
        resolution, ...dimensions({ resolution }) });
    }
  }
  if (!choices.length) fail('MASTER_HAS_NO_VARIANTS');
  return choices.sort((a, b) => (a.bandwidth || Number.MAX_SAFE_INTEGER) - (b.bandwidth || Number.MAX_SAFE_INTEGER));
}

export function parseVariant(text, base, origin) {
  if (!text.replace(/^\uFEFF/, '').trimStart().startsWith('#EXTM3U') || text.includes('#EXT-X-STREAM-INF:')) fail('INVALID_VARIANT_MANIFEST');
  const segments = [];
  let sequence = 0, key = null, map = null, byteRange = null, gap = false;
  for (const line of text.split(/\r?\n/).map(value => value.trim()).filter(Boolean)) {
    for (const match of line.matchAll(/\bURI="([^"\r\n]+)"/g)) mediaUrl(match[1], base, origin);
    if (line.startsWith('#EXT-X-MEDIA-SEQUENCE:')) sequence = Number(line.split(':')[1]);
    else if (line.startsWith('#EXT-X-KEY:')) {
      const attrs = attributes(line);
      key = attrs.METHOD === 'NONE' ? null : { method: attrs.METHOD, format: attrs.KEYFORMAT || 'identity',
        url: attrs.URI ? mediaUrl(attrs.URI, base, origin) : null, iv: attrs.IV };
    } else if (line.startsWith('#EXT-X-MAP:')) {
      const attrs = attributes(line);
      map = { url: mediaUrl(attrs.URI, base, origin), byteRange: attrs.BYTERANGE || null };
    } else if (line.startsWith('#EXT-X-BYTERANGE:')) byteRange = line.slice(17);
    else if (line === '#EXT-X-GAP') gap = true;
    else if (!line.startsWith('#')) {
      if (!gap) segments.push({ url: mediaUrl(line, base, origin), sequence, key, map, byteRange });
      sequence++; byteRange = null; gap = false;
    }
  }
  return segments;
}

export function inspectMedia(bytes) {
  for (let offset = 0; offset < Math.min(188, bytes.length - 376); offset++) {
    const count = Math.min(5, Math.floor((bytes.length - offset) / 188));
    const offsets = Array.from({ length: count }, (_, index) => offset + index * 188);
    if (count >= 3 && offsets.every(index => bytes[index] === 0x47 && ((bytes[index + 3] >> 4) & 3) !== 0)) {
      return { format: 'MPEG-TS', syncOffsets: offsets };
    }
  }
  let position = 0;
  const boxes = [];
  while (position + 8 <= bytes.length && boxes.length < 1000) {
    let size = bytes.readUInt32BE(position);
    const type = bytes.subarray(position + 4, position + 8).toString('ascii');
    if (size === 1) {
      if (position + 16 > bytes.length) break;
      const long = bytes.readBigUInt64BE(position + 8);
      if (long > BigInt(Number.MAX_SAFE_INTEGER)) break;
      size = Number(long);
    } else if (size === 0) size = bytes.length - position;
    if (size < 8 || position + size > bytes.length || !/^[A-Za-z0-9 ]{4}$/.test(type)) break;
    boxes.push(type); position += size;
  }
  if (boxes.includes('moof') && boxes.includes('mdat')) return { format: 'fMP4', boxes };
  if (boxes.includes('ftyp') && boxes.includes('moov')) return { format: 'fMP4-init', boxes };
  return { format: null, boxes };
}

async function recordFetch(label, url, proof, options) {
  const fetched = await fetchBytes(url, options);
  proof.http.push({ label, status: fetched.status, headers: headersProof(fetched.headers), bytes: fetched.bytes,
    sha256: createHash('sha256').update(fetched.body).digest('hex') });
  return fetched;
}

async function egressProof() {
  const response = await fetchBytes('https://ifconfig.me/ip', { limit: 1024, timeout: 20_000 });
  const ip = response.body.toString('utf8').trim();
  if (response.status !== 200 || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) fail('EGRESS_IP_UNAVAILABLE');
  const lookup = await fetchBytes(`https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`, { timeout: 20_000 });
  let data;
  try { data = JSON.parse(lookup.body.toString('utf8')).data; } catch { fail('ASN_LOOKUP_UNREADABLE'); }
  if (lookup.status !== 200 || !Array.isArray(data?.asns) || !data.asns.length) fail('ASN_LOOKUP_UNAVAILABLE');
  return { ip, asns: data.asns.map(Number), prefix: data.prefix, ipStatus: response.status, asnStatus: lookup.status, forcedIpv4: true };
}

async function transportProof(source, origin, quality) {
  const proof = { passed: false, http: [], availableVariants: [], selectedVariant: null, segments: [], encryption: [], initialization: [] };
  try {
  const master = await recordFetch('master', source, proof);
  if (master.status !== 200) fail('MASTER_NOT_200');
  const variants = parseMaster(master.body.toString('utf8'), source, origin);
  const selection = selectVariant(variants, quality);
  proof.availableVariants = variants.map(({ bandwidth, resolution, width, height }) => ({ bandwidth, resolution, width, height }));
  proof.selectedVariant = { bandwidth: selection.bandwidth, resolution: selection.resolution, width: selection.width, height: selection.height,
    choice: quality === 'highest' ? 'highest-pixel-area-then-bandwidth' : 'lowest-bandwidth', count: variants.length };
  const variant = await recordFetch('variant', selection.url, proof);
  if (variant.status !== 200) fail('VARIANT_NOT_200');
  const entries = parseVariant(variant.body.toString('utf8'), selection.url, origin);
  const selected = entries.filter((entry, index, all) => all.findIndex(other => other.url === entry.url) === index).slice(0, 3);
  if (selected.length !== 3) fail('THREE_DISTINCT_SEGMENTS_REQUIRED');
  const keys = new Map(), maps = new Set(), segmentHashes = new Set();
  for (const [index, entry] of selected.entries()) {
    if (entry.byteRange) fail('BYTE_RANGE_CANNOT_MEET_THREE_HTTP_200_RULE');
    if (entry.map && !maps.has(entry.map.url)) {
      if (entry.map.byteRange) fail('BYTE_RANGE_INIT_UNSUPPORTED');
      const init = await recordFetch(`init-${maps.size + 1}`, entry.map.url, proof, { limit: MAX_SEGMENT });
      const detected = inspectMedia(init.body);
      proof.initialization.push({ status: init.status, bytes: init.bytes, ...detected });
      if (init.status !== 200 || detected.format !== 'fMP4-init') fail('INVALID_FMP4_INITIALIZATION');
      maps.add(entry.map.url);
    }
    const fetched = await recordFetch(`segment-${index + 1}`, entry.url, proof, { limit: MAX_SEGMENT });
    if (fetched.status !== 200) fail(`SEGMENT_${index + 1}_NOT_200`);
    let bytes = fetched.body;
    if (entry.key) {
      if (entry.key.method !== 'AES-128' || entry.key.format !== 'identity' || !entry.key.url) fail('UNSUPPORTED_SEGMENT_ENCRYPTION');
      if (!keys.has(entry.key.url)) {
        const issued = await recordFetch(`key-${keys.size + 1}`, entry.key.url, proof, { limit: 1024 });
        if (issued.status !== 200 || issued.bytes !== 16) fail('INVALID_AES_KEY');
        keys.set(entry.key.url, issued.body);
        proof.encryption.push({ method: 'AES-128', status: issued.status, keyBytes: issued.bytes });
      }
      const iv = Buffer.alloc(16);
      if (entry.key.iv) {
        const value = entry.key.iv.replace(/^0x/i, '');
        if (!/^[0-9a-f]{1,32}$/i.test(value)) fail('INVALID_AES_IV');
        Buffer.from(value.padStart(32, '0'), 'hex').copy(iv);
      } else {
        if (!Number.isSafeInteger(entry.sequence) || entry.sequence < 0) fail('INVALID_MEDIA_SEQUENCE');
        iv.writeBigUInt64BE(BigInt(entry.sequence), 8);
      }
      try {
        const cipher = createDecipheriv('aes-128-cbc', keys.get(entry.key.url), iv);
        bytes = Buffer.concat([cipher.update(bytes), cipher.final()]);
      } catch { fail('AES_SEGMENT_DECODE_FAILED'); }
    }
    const detected = inspectMedia(bytes);
    const decodedSha256 = createHash('sha256').update(bytes).digest('hex');
    const valid = detected.format === 'MPEG-TS' || (detected.format === 'fMP4' && entry.map && maps.has(entry.map.url));
    proof.segments.push({ number: index + 1, status: fetched.status, wireBytes: fetched.bytes, decodedBytes: bytes.length,
      decodedSha256, encrypted: Boolean(entry.key), prefixHex: bytes.subarray(0, 16).toString('hex'), ...detected, passed: Boolean(valid) });
    if (!valid) fail(`SEGMENT_${index + 1}_INVALID_MEDIA_BYTES`);
    segmentHashes.add(decodedSha256);
  }
  if (segmentHashes.size !== 3) fail('THREE_DISTINCT_SEGMENT_BYTES_REQUIRED');
  proof.passed = true;
  } catch (error) { proof.reason = error instanceof ProofError ? error.code : 'TRANSPORT_VALIDATION_FAILED'; }
  return proof;
}

async function exposureProof(origin) {
  const proof = { passed: false, routes: [], invalidCapability: null };
  try {
  for (const pathname of ['/resolve', '/api/me', '/__dev', '/__prototype/resolve', '/']) {
    const response = await fetchBytes(new URL(pathname, origin).href, { limit: 64 * 1024, timeout: 20_000 });
    proof.routes.push({ path: pathname, status: response.status, headers: headersProof(response.headers) });
  }
  const invalid = await fetchBytes(`${origin}/media/invalid.invalid/master.m3u8`, { limit: 64 * 1024, timeout: 20_000 });
  proof.invalidCapability = { status: invalid.status, headers: headersProof(invalid.headers) };
  proof.passed = proof.routes.every(route => route.status === 404) && invalid.status === 403;
  if (!proof.passed) proof.reason = proof.routes.some(route => route.status !== 404) ? 'PUBLIC_CONTROL_ROUTE_EXPOSED' : 'INVALID_CAPABILITY_NOT_REJECTED';
  } catch (error) { proof.reason = error instanceof ProofError ? error.code : 'EXPOSURE_VALIDATION_FAILED'; }
  return proof;
}

const PLAYER_HTML = `<!doctype html><meta charset="utf-8"><title>StreamHub remote playback proof</title>
<style>body{margin:0;background:#101018;color:#f5f5fa;font:16px system-ui;padding:24px}video{display:block;width:min(960px,100%);background:#000}h1{font-size:22px}#status{margin-top:16px}</style>
<h1>StreamHub — different-network playback proof</h1><video id="video" muted playsinline controls></video><p id="status">Waiting for a protected media source.</p><script src="/hls.min.js"></script><script>
window.proof={frameCallbacks:0,firstMediaTime:null,lastMediaTime:null,decodedSeconds:0,decodedWallSeconds:0,width:0,height:0,videoWidth:0,videoHeight:0,fatal:null,passed:false,selectedLevel:null,manualQualityLocked:false,frameResolutionMismatch:false,frameDimensionsMatch:false,qualityFallback:false,timelineDiscontinuity:false,maxMediaTimeGap:0,waitingEvents:0,waitingSeconds:0,droppedFrames:0,totalVideoFrames:0};
window.startValidation=async function(input){
 const {source,quality,seconds,expected}=input;
 const video=document.querySelector('video'),status=document.querySelector('#status');
 if(!Hls.isSupported()||!video.requestVideoFrameCallback)throw new Error('BROWSER_DECODE_API_UNAVAILABLE');
 const hls=new Hls({autoStartLoad:false,startLevel:0,minAutoBitrate:0,maxBufferLength:8,maxMaxBufferLength:12,maxBufferSize:16777216,backBufferLength:0,enableWorker:true});
 window.hls=hls;window.proof.quality=quality;window.proof.requiredSeconds=seconds;window.proof.expectedDimensions={width:expected.width,height:expected.height};
 let lockedLevel=null,firstFrameWall=null,waitingAt=null;
 const startedWall=performance.now();
 function fatal(details){window.proof.fatal={type:'quality-proof',details};status.textContent='Playback proof failed: '+details;video.pause();hls.stopLoad();}
 function finishWaiting(){if(waitingAt!==null){window.proof.waitingSeconds+=(performance.now()-waitingAt)/1000;waitingAt=null;}}
 video.addEventListener('waiting',()=>{window.proof.waitingEvents++;if(waitingAt===null)waitingAt=performance.now();});
 video.addEventListener('playing',finishWaiting);
 window.snapshotProof=function(){finishWaiting();const stats=video.getVideoPlaybackQuality();window.proof.droppedFrames=stats.droppedVideoFrames;window.proof.totalVideoFrames=stats.totalVideoFrames;window.proof.wallSeconds=(performance.now()-startedWall)/1000;return {...window.proof};};
 function frame(now,metadata){
  const proof=window.proof;if(proof.fatal)return;proof.frameCallbacks++;
  const hasExpected=Number(expected.width)>0&&Number(expected.height)>0;
  proof.width=metadata.width;proof.height=metadata.height;proof.videoWidth=video.videoWidth;proof.videoHeight=video.videoHeight;
  proof.frameDimensionsMatch=hasExpected&&metadata.width===expected.width&&metadata.height===expected.height;
  if(hasExpected&&(!proof.frameDimensionsMatch||video.videoWidth!==expected.width||video.videoHeight!==expected.height)){proof.frameResolutionMismatch=true;fatal('DECODED_RESOLUTION_MISMATCH');return;}
  if(lockedLevel===null||hls.currentLevel!==lockedLevel||hls.autoLevelEnabled){proof.qualityFallback=true;fatal('QUALITY_FALLBACK_DETECTED');return;}
  if(proof.firstMediaTime===null){proof.firstMediaTime=metadata.mediaTime;firstFrameWall=now;}
  else{const gap=metadata.mediaTime-proof.lastMediaTime;proof.maxMediaTimeGap=Math.max(proof.maxMediaTimeGap,gap);if(gap<0||gap>0.5){proof.timelineDiscontinuity=true;fatal('DECODED_TIMELINE_DISCONTINUITY');return;}}
  proof.lastMediaTime=metadata.mediaTime;proof.decodedSeconds=proof.lastMediaTime-proof.firstMediaTime;
  proof.decodedWallSeconds=(now-firstFrameWall)/1000;proof.manualQualityLocked=!hls.autoLevelEnabled;
  proof.passed=proof.frameCallbacks>=20&&proof.decodedSeconds>=seconds&&proof.decodedWallSeconds>=seconds-0.25&&proof.width>0&&proof.height>0&&proof.manualQualityLocked&&!proof.fatal;
  status.textContent='Decoded '+proof.decodedSeconds.toFixed(3)+' seconds; '+proof.frameCallbacks+' displayed frames; '+proof.width+' × '+proof.height+'.';
  if(proof.passed){video.pause();hls.stopLoad();}else video.requestVideoFrameCallback(frame);
 }
 video.requestVideoFrameCallback(frame);
 hls.on(Hls.Events.ERROR,(_,data)=>{if(data.fatal){window.proof.fatal={type:String(data.type).replace(/[^a-zA-Z0-9_-]/g,'').slice(0,100),details:String(data.details).replace(/[^a-zA-Z0-9_-]/g,'').slice(0,100),status:Number(data.response?.code)||null};status.textContent='Playback failed.';}});
 hls.on(Hls.Events.LEVEL_SWITCHING,(_,data)=>{if(lockedLevel!==null&&data.level!==lockedLevel){window.proof.qualityFallback=true;fatal('QUALITY_FALLBACK_DETECTED');}});
 hls.on(Hls.Events.MANIFEST_PARSED,()=>{
  if(quality==='highest'&&!(expected.width>0&&expected.height>0)){fatal('EXPECTED_RESOLUTION_UNAVAILABLE');return;}
  const matches=hls.levels.map((level,index)=>({level,index})).filter(({level})=>(!(expected.width>0&&expected.height>0)||(level.width===expected.width&&level.height===expected.height))&&(!(expected.bandwidth>0)||level.bitrate===expected.bandwidth));
  if(matches.length!==1){fatal(matches.length?'AMBIGUOUS_SELECTED_VARIANT':'SELECTED_VARIANT_NOT_AVAILABLE_IN_BROWSER');return;}
  const {level,index}=matches[0];lockedLevel=index;window.proof.selectedLevel={index,width:level.width||null,height:level.height||null,bandwidth:level.bitrate||null};
  hls.startLevel=index;hls.loadLevel=index;hls.nextLoadLevel=index;hls.currentLevel=index;hls.nextLevel=index;hls.autoLevelCapping=index;
  window.proof.manualQualityLocked=!hls.autoLevelEnabled;
  if(!window.proof.manualQualityLocked){fatal('MANUAL_QUALITY_LOCK_FAILED');return;}
  hls.startLoad(0);video.play().catch(()=>{window.proof.fatal={type:'play',details:'AUTOPLAY_REJECTED'};});
 });
 hls.loadSource(source);hls.attachMedia(video);
};</script>`;

async function browserProof(source, origin, out, options, expected) {
  const proof = { passed: false, method: 'Playwright Chromium + hls.js 1.7.3 + requestVideoFrameCallback', mediaResponses: [], failedRequests: [] };
  let browser, server;
  try {
    const { chromium } = await import('playwright');
    const hlsRuntime = await readFile(require.resolve('hls.js/dist/hls.min.js'));
    server = createServer((req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      if (req.url === '/hls.min.js') { res.setHeader('Content-Type', 'application/javascript'); res.end(hlsRuntime); }
      else if (req.url === '/') { res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end(PLAYER_HTML); }
      else { res.writeHead(404); res.end(); }
    });
    await new Promise((accept, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', accept); });
    browser = await chromium.launch({ headless: true, args: ['--autoplay-policy=no-user-gesture-required', '--disable-dev-shm-usage'] });
    const page = await browser.newPage({ viewport: { width: 1100, height: 780 } });
    page.on('response', response => {
      let url;
      try { url = new URL(response.url()); } catch { return; }
      if (url.origin === origin && url.pathname.startsWith('/media/') && proof.mediaResponses.length < 100) {
        proof.mediaResponses.push({ status: response.status(), headers: headersProof(response.headers()) });
      }
    });
    page.on('requestfailed', request => {
      let url;
      try { url = new URL(request.url()); } catch { return; }
      if (url.origin === origin && proof.failedRequests.length < 20) proof.failedRequests.push({ code: safeCode(request.failure()?.errorText || 'NETWORK_FAILURE') });
    });
    await page.goto(`http://127.0.0.1:${server.address().port}/`, { waitUntil: 'load' });
    await page.evaluate(value => window.startValidation(value), { source, ...options, expected });
    try { await page.waitForFunction(() => window.proof.passed || window.proof.fatal, undefined, { timeout: 90_000 + options.seconds * 1000 }); }
    catch { proof.reason = 'BROWSER_DECODE_TIMEOUT'; }
    Object.assign(proof, await page.evaluate(() => window.snapshotProof()));
    proof.passed = evaluateDecodedProof(proof, { ...options, expected });
    if (!proof.passed && proof.fatal && !proof.reason) proof.reason = safeCode(proof.fatal.details);
    if (proof.passed) delete proof.reason;
    await page.screenshot({ path: resolve(out, 'remote-player.png'), fullPage: true });
    proof.screenshot = 'remote-player.png';
    await page.evaluate(() => { document.querySelector('video').pause(); window.hls?.destroy(); });
  } catch (error) { proof.passed = false; proof.reason = error instanceof ProofError ? error.code : 'BROWSER_VALIDATION_FAILED'; }
  finally {
    await browser?.close().catch(() => {});
    if (server) await new Promise(accept => { server.closeAllConnections(); server.close(accept); });
  }
  return proof;
}

export async function runRemoteValidation({ source = process.env.STREAMHUB_TEST_MEDIA_URL, out = process.env.OUT || 'verification/remote-playback',
  quality = process.env.STREAMHUB_TEST_QUALITY || 'lowest', seconds = process.env.STREAMHUB_TEST_SECONDS || 3 } = {}) {
  const directory = resolve(out);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const result = { status: 'FAIL', startedAt: new Date().toISOString(), runtime: process.version,
    runner: process.env.RUNNER_NAME || 'unspecified', publicOrigin: null, egress: null, transport: null, exposure: null, browser: null,
    quality: null, requiredSeconds: null };
  try {
    const options = normalizeTestOptions({ quality, seconds });
    result.quality = options.quality; result.requiredSeconds = options.seconds;
    const parsed = httpsUrl(source);
    const origin = parsed.origin;
    const checked = mediaUrl(parsed.href, origin, origin);
    result.publicOrigin = origin;
    result.egress = await egressProof();
    try { result.transport = await transportProof(checked, origin, options.quality); }
    catch (error) { result.transport = { passed: false, reason: error instanceof ProofError ? error.code : 'TRANSPORT_VALIDATION_FAILED' }; }
    try { result.exposure = await exposureProof(origin); }
    catch (error) { result.exposure = { passed: false, reason: error instanceof ProofError ? error.code : 'EXPOSURE_VALIDATION_FAILED' }; }
    result.browser = result.transport.selectedVariant
      ? await browserProof(checked, origin, directory, options, result.transport.selectedVariant)
      : { passed: false, reason: 'NO_VALIDATED_VARIANT_AVAILABLE' };
    if (result.transport.passed && result.exposure.passed && result.browser.passed) result.status = 'PASS';
  } catch (error) { result.reason = error instanceof ProofError ? error.code : 'REMOTE_VALIDATION_FAILED'; }
  result.finishedAt = new Date().toISOString();
  await writeFile(resolve(directory, 'result.json'), JSON.stringify(result, null, 2), { mode: 0o600 });
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const result = await runRemoteValidation();
    console.log(JSON.stringify({ status: result.status, ip: result.egress?.ip, asns: result.egress?.asns,
      quality: result.quality, requiredSeconds: result.requiredSeconds, selectedVariant: result.transport?.selectedVariant || null,
      transport: result.transport?.passed || false, exposure: result.exposure?.passed || false,
      browser: result.browser?.passed || false, decodedSeconds: result.browser?.decodedSeconds || 0,
      frames: result.browser?.frameCallbacks || 0, width: result.browser?.width || 0, height: result.browser?.height || 0,
      reason: result.reason || result.transport?.reason || result.exposure?.reason || result.browser?.reason || null }));
    process.exitCode = result.status === 'PASS' ? 0 : 1;
  } catch { console.log(JSON.stringify({ status: 'FAIL', reason: 'EVIDENCE_WRITE_FAILED' })); process.exitCode = 1; }
}
