(() => {
'use strict';

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const fmt = n => Math.round(n).toLocaleString('ko-KR');
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const CAT = ['l1', 'l2', 'l3', 'ksic', 'sido', 'sgg', 'dong', 'bdong', 'floor', 'roadNm', 'zip'];
const CODE_FIELDS = ['l1', 'l2', 'l3', 'ksic', 'sido', 'sgg', 'dong', 'bdong'];
const nk = s => String(s || '').replace(/[\s·.\/ㆍ]/g, '');

function ymSubMonths(ym, months) {
  let y = Math.floor(ym / 100), m = ym % 100;
  m -= months;
  while (m <= 0) { m += 12; y--; }
  return y * 100 + m;
}
function fmtYM(ym) {
  if (!ym || ym < 200000) return '';
  return `${String(ym).slice(2, 4)}.${String(ym).slice(4, 6)}`;
}
function parseRegYM(id) {
  if (!id || id.length < 12) return 0;
  const sub = id.slice(6, 12);
  if (/^20\d{4}$/.test(sub)) {
    const m = +sub.slice(4, 6);
    if (m >= 1 && m <= 12) return +sub;
  }
  return 0;
}
function shortRoadName(rawRoadNm, sidoName, sggName) {
  let r = String(rawRoadNm || '').trim();
  if (!r) return '(미상)';
  if (sidoName && r.startsWith(sidoName)) r = r.slice(sidoName.length).trim();
  if (sggName && r.startsWith(sggName)) r = r.slice(sggName.length).trim();
  const toks = r.split(/\s+/).filter(Boolean);
  return toks.length ? toks[toks.length - 1] : '(미상)';
}

/* ==================== Storage & IndexedDB ==================== */
const store = {
  get(k, d) {
    try { const v = localStorage.getItem('sbizmap:' + k); return v !== null ? JSON.parse(v) : d; }
    catch { return d; }
  },
  set(k, v) { try { localStorage.setItem('sbizmap:' + k, JSON.stringify(v)); } catch {} },
  del(k) { try { localStorage.removeItem('sbizmap:' + k); } catch {} },
};

const idb = (() => {
  let dbp = null;
  const open = () => dbp || (dbp = new Promise((res, rej) => {
    try {
      const r = indexedDB.open('sbizmap_db', 2);
      r.onupgradeneeded = () => {
        const db = r.result;
        if (!db.objectStoreNames.contains('kv')) db.createObjectStore('kv');
        if (!db.objectStoreNames.contains('vault')) db.createObjectStore('vault');
      };
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    } catch (e) { rej(e); }
  }));
  const tx = (st, m, f) => open().then(db => new Promise((res, rej) => {
    const t = db.transaction(st, m), q = f(t.objectStore(st));
    t.oncomplete = () => res(q && q.result);
    t.onerror = () => rej(t.error);
  }));
  return {
    get: k => tx('kv', 'readonly', s => s.get(k)).catch(() => undefined),
    set: (k, v) => tx('kv', 'readwrite', s => s.put(v, k)).then(() => true).catch(() => false),
    del: k => tx('kv', 'readwrite', s => s.delete(k)).catch(() => {}),
    getKey: () => tx('vault', 'readonly', s => s.get('key')).catch(() => undefined),
    setKey: v => tx('vault', 'readwrite', s => s.put(v, 'key')).then(() => true).catch(() => false),
    delKey: () => tx('vault', 'readwrite', s => s.delete('key')).catch(() => {}),
  };
})();

function toast(t) {
  const e = $('#toast');
  if (!e) return;
  e.textContent = t;
  e.classList.add('on');
  clearTimeout(toast.t);
  toast.t = setTimeout(() => e.classList.remove('on'), 2300);
}
async function copyText(t, msg) {
  try { await navigator.clipboard.writeText(t); toast(msg || '복사했습니다'); }
  catch { toast('복사가 허용되지 않는 환경입니다'); }
}

/* ==================== WebCrypto AES-256-GCM Vault ==================== */
const CANARY = 'SBIZMAP-VAULT-OK-V1';
let VAULT_META = null;
let VAULT_KEY = null;
let VAULT_SUMMARY = null;
let APP_BOOTED = false;
const loadedSidos = new Set();

function b64ToBytes(b64) {
  const bin = atob(b64), u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
async function deriveVaultKey(password, saltB64, iter) {
  const bk = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64ToBytes(saltB64), iterations: iter, hash: 'SHA-256' },
    bk,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}
async function verifyKey(key, vault) {
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBytes(vault.checkIv) },
      key,
      b64ToBytes(vault.checkCt)
    );
    return new TextDecoder().decode(pt) === CANARY;
  } catch { return false; }
}
async function fetchDecJson(name, onProg) {
  const vTag = VAULT_META ? encodeURIComponent(VAULT_META.salt.slice(0, 8)) : '2';
  const res = await fetch(`./data/${name}.enc?v=${vTag}`);
  if (!res.ok) throw new Error(`${name}.enc 로드 실패 (HTTP ${res.status})`);
  let buf;
  const total = Number(res.headers.get('content-length') || 0);
  if (onProg && res.body && total > 0) {
    const rd = res.body.getReader();
    const chunks = [];
    let got = 0;
    for (;;) {
      const { done, value } = await rd.read();
      if (done) break;
      chunks.push(value);
      got += value.length;
      onProg(got / total);
    }
    buf = new Uint8Array(got);
    let off = 0;
    for (const c of chunks) { buf.set(c, off); off += c.length; }
  } else {
    buf = new Uint8Array(await res.arrayBuffer());
  }
  const gz = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.subarray(0, 12) }, VAULT_KEY, buf.subarray(12));
  const ds = new Blob([gz]).stream().pipeThrough(new DecompressionStream('gzip'));
  return JSON.parse(await new Response(ds).text());
}
async function lockAppNow() {
  await idb.delKey();
  VAULT_KEY = null;
  location.reload();
}

/* ==================== API Key Helpers ==================== */
function normalizeDataGoKey(raw) {
  const clean = String(raw || '').replace(/\s+/g, '');
  if (!clean) return '';
  try {
    const dec = clean.includes('%') ? decodeURIComponent(clean) : clean;
    return encodeURIComponent(dec);
  } catch {
    return clean.includes('%') ? clean : encodeURIComponent(clean);
  }
}
function maskKeyPreview(raw) {
  const s = String(raw || '').replace(/\s+/g, '');
  if (!s) return '미입력';
  if (s.length <= 16) return `${s.slice(0, 4)}… (${s.length}자)`;
  return `${s.slice(0, 7)}…${s.slice(-7)} (${s.length}자)`;
}
function getVWorldKey() {
  const local = String(store.get('vworldKey', '') || '').replace(/\s+/g, '');
  if (local) return local;
  return String(VAULT_SUMMARY?.vaultKeys?.vworld || '').replace(/\s+/g, '');
}
function getVWorldDomain() {
  return (location.origin && location.origin !== 'null' && /^https?:/.test(location.origin))
    ? location.origin
    : 'https://heebonpark.github.io';
}
function syncApiKeyUI() {
  const dk = store.get('dataGoKey', '');
  const gk = store.get('geminiKey', '');
  const localVw = String(store.get('vworldKey', '') || '').replace(/\s+/g, '');
  const effVw = getVWorldKey();
  if ($('#apiKeyIn')) $('#apiKeyIn').value = dk;
  if ($('#apiKeyMask')) $('#apiKeyMask').textContent = maskKeyPreview(dk);
  if ($('#setDataGoKey')) $('#setDataGoKey').value = dk;
  if ($('#setDataGoMask')) $('#setDataGoMask').textContent = maskKeyPreview(dk);
  if ($('#setGeminiKey')) $('#setGeminiKey').value = gk;
  if ($('#setGeminiMask')) $('#setGeminiMask').textContent = maskKeyPreview(gk);
  if ($('#vwKeyIn')) $('#vwKeyIn').value = localVw;
  if ($('#setVwKey')) $('#setVwKey').value = localVw;
  const vwTag = localVw ? `${maskKeyPreview(effVw)} (수동 저장)` : effVw ? `${maskKeyPreview(effVw)} (Vault 암호화)` : '미입력';
  if ($('#vwKeyMask')) $('#vwKeyMask').textContent = vwTag;
  if ($('#setVwMask')) $('#setVwMask').textContent = vwTag;
  if ($('#vwSourceBadge')) $('#vwSourceBadge').textContent = localVw ? '(브라우저 수동 저장)' : effVw ? '(Vault 암호화 자동연동)' : '(미입력)';
}

/* ==================== VWorld Digital Twin Land JSONP Client ==================== */
let vwCbSeq = 0;
function vworldJsonp(endpoint, params, timeoutMs = 9000) {
  const key = getVWorldKey();
  if (!key) return Promise.reject(new Error('브이월드 인증키가 없습니다'));
  return new Promise((resolve, reject) => {
    const cb = `__vwcb_${++vwCbSeq}_${Date.now()}`;
    const q = new URLSearchParams({ ...params, key, domain: getVWorldDomain(), format: 'json', callback: cb });
    const script = document.createElement('script');
    let done = false;
    const cleanup = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { delete window[cb]; } catch { window[cb] = undefined; }
      script.remove();
    };
    const timer = setTimeout(() => { cleanup(); reject(new Error('브이월드 응답 시간 초과')); }, timeoutMs);
    window[cb] = data => { cleanup(); resolve(data); };
    script.onerror = () => { cleanup(); reject(new Error('브이월드 네트워크 오류')); };
    script.src = `https://api.vworld.kr/req/${endpoint}?${q.toString()}`;
    document.head.appendChild(script);
  });
}
async function vwReverseAddr(lat, lon) {
  const j = await vworldJsonp('address', {
    service: 'address', request: 'getAddress', version: '2.0',
    crs: 'epsg:4326', point: `${lon},${lat}`, type: 'both', zipcode: 'true', simple: 'false',
  });
  if (j?.response?.status !== 'OK') return null;
  const res = j.response.result || [];
  const road = res.find(x => x.type === 'road') || null;
  const parcel = res.find(x => x.type === 'parcel') || null;
  return {
    road: road?.text || '',
    parcel: parcel?.text || '',
    zip: road?.zipcode || parcel?.zipcode || '',
    bld: road?.structure?.detail || '',
  };
}
async function vwGeocodeAddr(addr) {
  for (const type of ['road', 'parcel']) {
    try {
      const j = await vworldJsonp('address', {
        service: 'address', request: 'getCoord', version: '2.0',
        crs: 'epsg:4326', address: addr, refine: 'true', simple: 'false', type,
      });
      if (j?.response?.status === 'OK' && j.response.result?.point) {
        const pt = j.response.result.point;
        const x = parseFloat(pt.x), y = parseFloat(pt.y);
        if (x > 124 && x < 132 && y > 33 && y < 39.5) {
          return { lat: y, lon: x, type: type === 'road' ? '브이월드(도로명)' : '브이월드(지번)', refined: j.response.refined?.text || addr };
        }
      }
    } catch {}
  }
  return null;
}
async function vwSearchPlaceAndAddr(query) {
  const [pRes, aRes] = await Promise.allSettled([
    vworldJsonp('search', { service: 'search', request: 'search', version: '2.0', crs: 'EPSG:4326', size: '6', query, type: 'place' }),
    vworldJsonp('search', { service: 'search', request: 'search', version: '2.0', crs: 'EPSG:4326', size: '5', query, type: 'address', category: 'road' }),
  ]);
  const out = [];
  const pushItems = (res, kind) => {
    if (res.status !== 'fulfilled' || res.value?.response?.status !== 'OK') return;
    for (const it of (res.value.response.result?.items || [])) {
      const x = parseFloat(it.point?.x), y = parseFloat(it.point?.y);
      if (!(x > 124 && x < 132 && y > 33 && y < 39.5)) continue;
      out.push({
        kind,
        title: it.title || it.address?.road || it.address?.parcel || query,
        addr: it.address?.road || it.address?.parcel || '',
        cat: it.category || '',
        lat: y, lon: x,
      });
    }
  };
  pushItems(pRes, '장소');
  pushItems(aRes, '도로명주소');
  return out;
}
async function vwLandInfo(lat, lon) {
  const pt = `POINT(${lon} ${lat})`;
  const [pRes, zRes] = await Promise.allSettled([
    vworldJsonp('data', { service: 'data', request: 'GetFeature', data: 'LP_PA_CBND_BUBUN', geomFilter: pt }),
    vworldJsonp('data', { service: 'data', request: 'GetFeature', data: 'LT_C_UQ111', geomFilter: pt }),
  ]);
  const pFeat = pRes.status === 'fulfilled' ? pRes.value?.response?.result?.featureCollection?.features?.[0] : null;
  const zFeats = zRes.status === 'fulfilled' ? (zRes.value?.response?.result?.featureCollection?.features || []) : [];
  const zoning = [...new Set(zFeats.map(f => f?.properties?.uname).filter(Boolean))];
  return { parcel: pFeat || null, zoning };
}
function formatLandCardHtml(addrInfo, land) {
  const parts = [];
  if (addrInfo) {
    if (addrInfo.road) parts.push(`<div class="b"><b>${esc(addrInfo.road)}</b>${addrInfo.zip ? ` <span class="mth">${esc(addrInfo.zip)}</span>` : ''}</div>`);
    if (addrInfo.parcel) parts.push(`<div class="c">지번: ${esc(addrInfo.parcel)}</div>`);
  }
  const p = land?.parcel?.properties;
  if (p) {
    const jiga = Number(p.jiga || 0);
    const pyungMan = jiga > 0 ? Math.round((jiga * 3.305785) / 10000) : 0;
    parts.push(`<div class="c" style="margin-top:3px"><b>📐 필지/공시지가</b> · ${esc(p.addr || p.jibun || '')} (${esc(p.jibun || '')})</div>`);
    if (jiga > 0) {
      parts.push(`<div class="c" style="color:#0f766e;font-weight:700">개별공시지가: ${fmt(jiga)}원/㎡ (평당 약 ${fmt(pyungMan)}만원 · ${esc(p.gosi_year || '')}년)</div>`);
    }
    if (p.pnu) parts.push(`<div class="c">PNU: <code>${esc(p.pnu)}</code></div>`);
  }
  if (land?.zoning?.length) {
    parts.push(`<div class="c" style="margin-top:2px"><b>🏙 용도지역:</b> <span class="mth">${land.zoning.map(esc).join(' · ')}</span></div>`);
  }
  return parts.length ? parts.join('') : '<div class="c">브이월드 필지/용도 정보를 찾지 못했습니다.</div>';
}
function drawParcelHighlight(feature) {
  if (!parcelLayer) return;
  parcelLayer.clearLayers();
  if (!feature || !feature.geometry) return;
  try {
    L.geoJSON(feature, { style: { color: '#d97706', weight: 2.5, fillColor: '#f59e0b', fillOpacity: 0.22 } }).addTo(parcelLayer);
  } catch {}
}

/* ==================== Data Store (v2 Enriched) ==================== */
const L1_COLORS = {
  '음식': '#e8553d', '소매': '#2f6fed', '부동산': '#f2a516', '숙박': '#6d4c41',
  '과학기술': '#00a3a3', '시설관리임대': '#7f8c9a', '교육': '#8e5cd9', '학문교육': '#8e5cd9',
  '보건의료': '#e0457b', '예술스포츠': '#2bb673', '스포츠': '#2bb673',
  '수리개인': '#9bbb1f', '생활서비스': '#9bbb1f', '관광여가오락': '#ff7eb6',
};
const EXTRA = ['#17becf', '#bcbd22', '#ff9896', '#9467bd', '#8c564b', '#7f7f7f'];

const D = {
  N: 0,
  lat: new Float64Array(0), lon: new Float64Array(0),
  mx: new Float64Array(0), my: new Float64Array(0),
  codes: {}, dict: {}, map: {}, cnt: {}, parent: {}, codeMaps: {},
  strs: [], files: new Map(), idSet: new Set(),
  apiMask: new Uint8Array(0), apiCount: 0,
  bldId: new Uint32Array(0), bldCnt: new Uint32Array(1), bldSeq: 0,
  regYM: new Uint32Array(0), maxYM: 202609,
  isFran: new Uint8Array(0),
};
for (const f of CAT) { D.codes[f] = new Uint16Array(0); D.dict[f] = []; D.map[f] = new Map(); D.cnt[f] = []; }
for (const f of CODE_FIELDS) D.codeMaps[f] = [];
D.codes.st = new Uint8Array(0); D.dict.st = ['유지', '신규', '폐업', '비교제외']; D.cnt.st = [0, 0, 0, 0];
const ST_COL = ['#9aa4b4', '#16a34a', '#e11d48', '#cfd4dc'];

const H = str => {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0, ch; i < str.length; i++) {
    ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507); h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507); h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
};
const hasS = (a, v) => { let lo = 0, hi = a.length - 1; while (lo <= hi) { const m = (lo + hi) >> 1, x = a[m]; if (x === v) return true; if (x < v) lo = m + 1; else hi = m - 1; } return false; };
const CMP = { on: false, files: new Map(), newN: 0, closedN: 0, keepN: 0, exN: 0, baseYM: '', curYM: '', baseTotal: 0 };
let colorMode = 'l1';
function ckey() { return colorMode === 'st' && CMP.on ? [D.codes.st, ST_COL, [3, 0, 2, 1]] : [D.codes.l1, colorOf, null]; }
let colorOf = [], colorRGBA = [], filtered = new Uint32Array(0), selMask = new Uint8Array(0), selCount = 0, centroids = null;
const parts = [];

function label(f, c) {
  const k = D.dict[f][c]; if (k == null) return '';
  if (f === 'l2' || f === 'l3' || f === 'roadNm') return k.slice(k.lastIndexOf('>') + 1);
  if (f === 'sgg') return k.slice(k.indexOf(' ') + 1);
  if (f === 'dong' || f === 'bdong') return k.slice(k.lastIndexOf(' ') + 1);
  return k;
}
const sidoShort = t => /^(충청|전라|경상)(북|남)도$/.test(t) ? t[0] + t[2] : t.slice(0, 2);
function sggFull(c) { const k = D.dict.sgg[c] || ''; const p = k.indexOf(' '); return sidoShort(k.slice(0, p)) + ' ' + k.slice(p + 1); }
function S(i) {
  const a = D.strs[i].split('\x1f');
  return {
    id: a[0], name: a[1], branch: a[2], road: a[3], bld: a[4], ho: a[5], jb: a[6] || '',
    addr: a[3] || (a[6] ? D.dict.sgg[D.codes.sgg[i]] + ' ' + a[6] : ''),
  };
}
const hexRGB = h => { const n = parseInt(h.slice(1), 16); return [(n >> 16) & 255, (n >> 8) & 255, n & 255]; };
const brandKey = nm => String(nm || '').replace(/\(주\)|㈜|주식회사|\(유\)|유한회사|\s+/g, '').toLowerCase();

function finalize() {
  let add = 0; for (const p of parts) add += p.n;
  if (!add) return;
  const N0 = D.N, N = N0 + add;
  const grow = (a, T) => { const b = new T(N); b.set(a); return b; };
  D.lat = grow(D.lat, Float64Array); D.lon = grow(D.lon, Float64Array);
  D.mx = grow(D.mx, Float64Array); D.my = grow(D.my, Float64Array);
  for (const f of CAT) D.codes[f] = grow(D.codes[f], Uint16Array);
  D.codes.st = grow(D.codes.st, Uint8Array);
  D.apiMask = grow(D.apiMask, Uint8Array);
  D.bldId = grow(D.bldId, Uint32Array);
  D.regYM = grow(D.regYM, Uint32Array);

  let o = N0;
  for (const p of parts) {
    const rm = {};
    for (const f of CAT) {
      const pDict = p.dicts[f] || ['(미상)'];
      const pCdMap = p.codeMaps && p.codeMaps[f];
      rm[f] = pDict.map((k, idx) => {
        let c = D.map[f].get(k);
        if (c === undefined) {
          c = D.dict[f].length;
          D.dict[f].push(k);
          D.map[f].set(k, c);
          D.cnt[f].push(0);
          if (D.codeMaps[f]) D.codeMaps[f].push(pCdMap ? (pCdMap[idx] || '') : '');
        } else if (D.codeMaps[f] && pCdMap && pCdMap[idx] && !D.codeMaps[f][c]) {
          D.codeMaps[f][c] = pCdMap[idx];
        }
        return c;
      });
    }
    D.lat.set(p.lat, o); D.lon.set(p.lon, o);
    const isApi = !!p.isApi;
    const bldOff = D.bldSeq;
    let maxChunkBld = 0;
    const hasBld = p.bldId && p.bldId.length === p.n;
    for (let j = 0; j < p.n; j++) {
      const i = o + j, y = p.lat[j];
      D.mx[i] = (p.lon[j] + 180) / 360;
      const s = Math.sin(y * Math.PI / 180);
      D.my[i] = 0.5 - Math.log((1 + s) / (1 - s)) / (4 * Math.PI);
      for (const f of CAT) {
        const srcArr = p.codes[f];
        const c = rm[f][srcArr ? srcArr[j] : 0];
        D.codes[f][i] = c;
        D.cnt[f][c]++;
      }
      if (isApi) { D.apiMask[i] = 1; D.apiCount++; }
      if (hasBld) {
        const bid = p.bldId[j];
        if (bid > 0) {
          D.bldId[i] = bldOff + bid;
          if (bid > maxChunkBld) maxChunkBld = bid;
        }
      }
    }
    D.bldSeq += maxChunkBld;
    for (let j = 0; j < p.n; j++) {
      const str = p.strs[j];
      D.strs.push(str);
      const id = str.slice(0, str.indexOf('\x1f'));
      if (id) {
        D.idSet.add(id);
        const ym = parseRegYM(id);
        D.regYM[o + j] = ym;
        if (ym > D.maxYM) D.maxYM = ym;
      }
    }
    o += p.n;
  }
  parts.length = 0;
  D.N = N; centroids = null;

  // Parent hierarchy
  const P = D.parent, C = D.codes;
  P.sgg = []; P.dong = []; P.bdong = []; P.l2 = []; P.l3 = []; P.roadNm = []; P.zip = [];
  for (let i = 0; i < N; i++) {
    P.sgg[C.sgg[i]] = C.sido[i];
    P.dong[C.dong[i]] = C.sgg[i];
    P.bdong[C.bdong[i]] = C.sgg[i];
    P.l2[C.l2[i]] = C.l1[i];
    P.l3[C.l3[i]] = C.l2[i];
    P.roadNm[C.roadNm[i]] = C.sgg[i];
    P.zip[C.zip[i]] = C.sgg[i];
  }

  // Building store counts (exact 건물관리번호 density)
  const bc = new Uint32Array(D.bldSeq + 1);
  for (let i = 0; i < N; i++) { const b = D.bldId[i]; if (b) bc[b]++; }
  D.bldCnt = bc;

  // Franchise vs Independent detection (지점명 존재 OR 동일 브랜드 5개 이상)
  const bCounts = new Map();
  const bKeys = new Array(N);
  const hasBr = new Uint8Array(N);
  for (let i = 0; i < N; i++) {
    const s = D.strs[i];
    const p1 = s.indexOf('\x1f');
    const p2 = s.indexOf('\x1f', p1 + 1);
    const p3 = s.indexOf('\x1f', p2 + 1);
    const nm = s.slice(p1 + 1, p2);
    const br = s.slice(p2 + 1, p3);
    if (br) hasBr[i] = 1;
    const bk = brandKey(nm);
    bKeys[i] = bk;
    if (bk.length >= 2) bCounts.set(bk, (bCounts.get(bk) || 0) + 1);
  }
  const fr = new Uint8Array(N);
  for (let i = 0; i < N; i++) {
    if (hasBr[i] || (bKeys[i].length >= 2 && (bCounts.get(bKeys[i]) || 0) >= 5)) fr[i] = 1;
  }
  D.isFran = fr;

  if (VAULT_SUMMARY && VAULT_SUMMARY.dataYM) {
    const vym = +VAULT_SUMMARY.dataYM.replace('.', '');
    if (vym > D.maxYM) D.maxYM = vym;
  }

  const ns = new Uint8Array(N); ns.set(selMask); selMask = ns;
  let e = 0;
  colorOf = D.dict.l1.map(k => L1_COLORS[nk(k)] || EXTRA[(e++) % EXTRA.length]);
  colorRGBA = colorOf.map(h => { const [r, g, b] = hexRGB(h); return (255 << 24) | (b << 16) | (g << 8) | r; });
}

function getCentroids() {
  if (centroids) return centroids;
  const out = {};
  for (const f of ['sido', 'sgg', 'dong', 'bdong']) {
    const n = D.dict[f].length;
    out[f] = { y: new Float64Array(n), x: new Float64Array(n), c: new Uint32Array(n) };
  }
  const C = D.codes;
  for (let i = 0; i < D.N; i++) {
    for (const f of ['sido', 'sgg', 'dong', 'bdong']) {
      const k = C[f][i], o = out[f];
      o.y[k] += D.lat[i]; o.x[k] += D.lon[i]; o.c[k]++;
    }
  }
  for (const f in out) {
    const o = out[f];
    for (let k = 0; k < o.c.length; k++) if (o.c[k]) { o.y[k] /= o.c[k]; o.x[k] /= o.c[k]; }
  }
  return centroids = out;
}

/* ==================== CSV Web Worker (v2 Enriched) ==================== */
const WORKER_SRC = `
const COLS={id:'상가업소번호',name:'상호명',branch:'지점명',
  l1Cd:'상권업종대분류코드',l1:'상권업종대분류명',l2Cd:'상권업종중분류코드',l2:'상권업종중분류명',
  l3Cd:'상권업종소분류코드',l3:'상권업종소분류명',ksicCd:'표준산업분류코드',ksic:'표준산업분류명',
  sidoCd:'시도코드',sido:'시도명',sggCd:'시군구코드',sgg:'시군구명',dongCd:'행정동코드',dong:'행정동명',
  bdongCd:'법정동코드',bdong:'법정동명',roadNm:'도로명',road:'도로명주소',jibun:'지번주소',
  bldMgt:'건물관리번호',bld:'건물명',zip:'신우편번호',floor:'층정보',ho:'호정보',lon:'경도',lat:'위도'};
const CAT=['l1','l2','l3','ksic','sido','sgg','dong','bdong','floor','roadNm','zip'];
const CODE_FIELDS=['l1','l2','l3','ksic','sido','sgg','dong','bdong'];
const H=(str)=>{let h1=0xdeadbeef,h2=0x41c6ce57;for(let i=0,ch;i<str.length;i++){ch=str.charCodeAt(i);h1=Math.imul(h1^ch,2654435761);h2=Math.imul(h2^ch,1597334677);}
  h1=Math.imul(h1^(h1>>>16),2246822507);h1^=Math.imul(h2^(h2>>>13),3266489909);h2=Math.imul(h2^(h2>>>16),2246822507);h2^=Math.imul(h1^(h1>>>13),3266489909);return 4294967296*(2097151&h2)+(h1>>>0);};
const hasS=(a,v)=>{let lo=0,hi=a.length-1;while(lo<=hi){const m=(lo+hi)>>1,x=a[m];if(x===v)return true;if(x<v)lo=m+1;else hi=m-1;}return false;};
function shortRoad(r,sd,sg){if(!r)return '(미상)';if(sd&&r.startsWith(sd))r=r.slice(sd.length).trim();if(sg&&r.startsWith(sg))r=r.slice(sg.length).trim();const t=r.split(/\\s+/).filter(Boolean);return t.length?t[t.length-1]:'(미상)';}
self.onmessage=async e=>{const {file,fid,method,usize,cmp}=e.data;try{await run(file,fid,method,usize,cmp);}catch(err){postMessage({type:'error',fid,msg:String(err&&err.message||err)});}};
function parseQuoted(line){const out=[];let cur='',q=false;for(let i=0;i<line.length;i++){const c=line[i];
  if(q){if(c==='"'){if(line[i+1]==='"'){cur+='"';i++;}else q=false;}else cur+=c;}
  else{if(c==='"')q=true;else if(c===','){out.push(cur);cur='';}else cur+=c;}}out.push(cur);return out;}
function cntQ(s){let n=0,p=-1;while((p=s.indexOf('"',p+1))!==-1)n++;return n;}
async function run(file,fid,method,usize,cmp){
  let bId=new Float64Array(1<<16),bKey=new Float64Array(1<<16),bn=0;const bs=new Set(),cs=cmp?new Set(cmp.sidos):null;
  const total=usize||file.size;
  const rd=(method===8?file.stream().pipeThrough(new DecompressionStream('deflate-raw')):file.stream()).getReader();
  const pre=[];let preLen=0,eof=false;
  while(preLen<65536){const {done,value}=await rd.read();if(done){eof=true;break;}pre.push(value);preLen+=value.length;}
  const head=new Uint8Array(preLen);{let o=0;for(const c of pre){head.set(c,o);o+=c.length;}}
  let enc='utf-8';
  try{new TextDecoder('utf-8',{fatal:true}).decode(head.subarray(0,65536),{stream:true});}catch(_){enc='euc-kr';}
  const dec=new TextDecoder(enc);
  const dicts={},maps={},codes={},codeMaps={};
  for(const f of CAT){dicts[f]=[];maps[f]=new Map();codes[f]=[];}
  for(const f of CODE_FIELDS)codeMaps[f]=[];
  const bldMap=new Map();const bldId=[];
  let lat=new Float64Array(1<<16),lon=new Float64Array(1<<16);
  const strs=[];let n=0,bad=0,ix=null,pend=null;
  const code=(f,k,cd)=>{let m=maps[f],c=m.get(k);if(c===undefined){c=dicts[f].length;dicts[f].push(k);m.set(k,c);if(codeMaps[f])codeMaps[f].push(cd||'');}else if(cd&&codeMaps[f]&&!codeMaps[f][c]){codeMaps[f][c]=cd;}codes[f].push(c);};
  const JB=/(\\S+)\\s+(산\\s*\\d+(?:-\\d+)?|\\d+(?:-\\d+)?)\\s*$/;
  function row(r){
    if(!ix){r[0]=r[0].replace(/^\\uFEFF/,'');ix={};
      for(const k in COLS){ix[k]=r.findIndex(h=>h.trim()===COLS[k]);}
      if(ix.name<0||ix.lon<0||ix.lat<0)throw new Error('상가(상권)정보 CSV 형식이 아닙니다 (상호명/경도/위도 열 없음)');
      return;}
    const g=k=>{const i=ix[k];return i>=0&&r[i]!==undefined?r[i].trim():'';};
    const x=parseFloat(g('lon')),y=parseFloat(g('lat'));
    if(!(x>124&&x<132&&y>33&&y<39.5)){bad++;return;}
    const jm=g('jibun').match(JB),jb=jm?jm[1]+' '+jm[2].replace(/\\s+/g,''):'',id=g('id'),nm=g('name'),road=g('road');
    if(cmp){const hi=id?H(id):-2,hk=H(nm+'|'+(road||jb));
      if(bn>=bId.length){const a=new Float64Array(bId.length*2);a.set(bId);bId=a;const b=new Float64Array(bKey.length*2);b.set(bKey);bKey=b;}
      bId[bn]=hi;bKey[bn]=hk;bn++;const sd=g('sido')||'(미상)';bs.add(sd);
      if(!cs.has(sd))return;if((id&&hasS(cmp.idH,hi))||hasS(cmp.keyH,hk))return;}
    if(n>=lat.length){const a=new Float64Array(lat.length*2);a.set(lat);lat=a;const b=new Float64Array(lon.length*2);b.set(lon);lon=b;}
    lat[n]=y;lon[n]=x;
    const sido=g('sido')||'(미상)',sggRaw=g('sgg')||'(미상)',sgg=sido+' '+sggRaw,l1=g('l1')||'(미상)',l2=l1+'>'+(g('l2')||'(미상)');
    code('l1',l1,g('l1Cd'));code('l2',l2,g('l2Cd'));code('l3',l2+'>'+(g('l3')||'(미상)'),g('l3Cd'));code('ksic',g('ksic'),g('ksicCd'));
    code('sido',sido,g('sidoCd'));code('sgg',sgg,g('sggCd'));code('dong',sgg+' '+(g('dong')||'(미상)'),g('dongCd'));code('bdong',sgg+' '+(g('bdong')||'(미상)'),g('bdongCd'));
    code('floor',g('floor')||'(미상)');
    code('roadNm',sgg+'>'+shortRoad(g('roadNm'),sido,sggRaw));
    code('zip',g('zip')||'(미상)');
    const bm=g('bldMgt');
    if(bm){let bid=bldMap.get(bm);if(bid===undefined){bid=bldMap.size+1;bldMap.set(bm,bid);}bldId.push(bid);}else bldId.push(0);
    strs.push([id,nm,g('branch'),road,g('bld'),g('ho'),jb].join('\\x1f'));
    n++;
  }
  function lines(block){
    for(let L of block.split('\\n')){
      if(L.endsWith('\\r'))L=L.slice(0,-1);
      if(pend!==null){L=pend+'\\n'+L;if(cntQ(L)%2){pend=L;continue;}pend=null;}
      else if(L.indexOf('"')>=0&&cntQ(L)%2){pend=L;continue;}
      if(!L)continue;
      row(L.indexOf('"')<0?L.split(','):parseQuoted(L));
    }
  }
  let carry='',loaded=0,last=0,first=true;
  for(;;){let done,value;
    if(first){first=false;value=head;done=preLen===0;}else if(eof){done=true;}else({done,value}=await rd.read());
    if(done)break;loaded+=value.length;
    const t=carry+dec.decode(value,{stream:true});const p=t.lastIndexOf('\\n');
    if(p<0){carry=t;continue;}carry=t.slice(p+1);lines(t.slice(0,p));
    if(loaded-last>3e6){last=loaded;postMessage({type:'progress',fid,loaded,total,n:cmp?bn:n});}}
  carry+=dec.decode();if(carry)lines(carry);if(pend)lines('');
  const out={type:'done',fid,n,bad,enc,dicts,codeMaps,codes:{},bldId:Uint32Array.from(bldId),strs,lat:lat.slice(0,n),lon:lon.slice(0,n)};
  const tr=[out.lat.buffer,out.lon.buffer,out.bldId.buffer];
  for(const f of CAT){out.codes[f]=Uint32Array.from(codes[f]);tr.push(out.codes[f].buffer);}
  if(cmp){out.bId=bId.slice(0,bn);out.bKey=bKey.slice(0,bn);out.bSidos=[...bs];out.bTotal=bn;tr.push(out.bId.buffer,out.bKey.buffer);}
  postMessage(out,tr);
}
`;
const workerURL = URL.createObjectURL(new Blob([WORKER_SRC], { type: 'text/javascript' }));
let fidSeq = 0;

function decodeName(b) { try { return new TextDecoder('utf-8', { fatal: true }).decode(b); } catch { return new TextDecoder('euc-kr').decode(b); } }
async function listZip(f) {
  const tl = Math.min(f.size, 65557), tail = new DataView(await f.slice(f.size - tl).arrayBuffer());
  let e = -1; for (let i = tl - 22; i >= 0; i--) if (tail.getUint32(i, true) === 0x06054b50) { e = i; break; }
  if (e < 0) throw new Error('ZIP 파일 구조를 읽을 수 없습니다');
  let cnt = tail.getUint16(e + 10, true), cdSize = tail.getUint32(e + 12, true), cdOff = tail.getUint32(e + 16, true);
  if (cnt === 0xFFFF || cdOff === 0xFFFFFFFF || cdSize === 0xFFFFFFFF) {
    const l = e - 20;
    if (l >= 0 && tail.getUint32(l, true) === 0x07064b50) {
      const zo = Number(tail.getBigUint64(l + 8, true));
      const z = new DataView(await f.slice(zo, zo + 56).arrayBuffer());
      cnt = Number(z.getBigUint64(32, true)); cdSize = Number(z.getBigUint64(40, true)); cdOff = Number(z.getBigUint64(48, true));
    }
  }
  const cd = new DataView(await f.slice(cdOff, cdOff + cdSize).arrayBuffer()), u8 = new Uint8Array(cd.buffer), out = []; let p = 0;
  for (let k = 0; k < cnt && p + 46 <= u8.length; k++) {
    if (cd.getUint32(p, true) !== 0x02014b50) break;
    const flag = cd.getUint16(p + 8, true), method = cd.getUint16(p + 10, true);
    let cSize = cd.getUint32(p + 20, true), uSize = cd.getUint32(p + 24, true), lho = cd.getUint32(p + 42, true);
    const nL = cd.getUint16(p + 28, true), xL = cd.getUint16(p + 30, true), cL = cd.getUint16(p + 32, true);
    const name = decodeName(u8.subarray(p + 46, p + 46 + nL)); let x = p + 46 + nL; const xe = x + xL;
    while (x + 4 <= xe) {
      const id = cd.getUint16(x, true), sz = cd.getUint16(x + 2, true);
      if (id === 1) {
        let q = x + 4;
        if (uSize === 0xFFFFFFFF) { uSize = Number(cd.getBigUint64(q, true)); q += 8; }
        if (cSize === 0xFFFFFFFF) { cSize = Number(cd.getBigUint64(q, true)); q += 8; }
        if (lho === 0xFFFFFFFF) { lho = Number(cd.getBigUint64(q, true)); }
      }
      x += 4 + sz;
    }
    p = xe + cL;
    if (/\/$/.test(name) || !/\.csv$/i.test(name)) continue;
    if (flag & 1) throw new Error('암호가 걸린 ZIP은 지원하지 않습니다');
    if (method !== 0 && method !== 8) throw new Error('지원하지 않는 압축 방식(' + method + ')');
    out.push({ name: name.split('/').pop(), method, cSize, uSize, lho });
  }
  for (const o of out) {
    const h = new DataView(await f.slice(o.lho, o.lho + 30).arrayBuffer());
    const ds = o.lho + 30 + h.getUint16(26, true) + h.getUint16(28, true);
    o.blob = f.slice(ds, ds + o.cSize);
  }
  return out;
}
async function gatherFiles(input) {
  input = [...input]; const files = [];
  for (const f of input) {
    if (/\.zip$/i.test(f.name)) {
      if (typeof DecompressionStream === 'undefined') { alert('ZIP을 바로 읽으려면 최신 Chrome/Edge가 필요합니다.'); continue; }
      try {
        showBusy(`ZIP 목록 읽는 중… ${f.name}`, 0);
        const ents = await listZip(f);
        if (!ents.length) alert(`${f.name} 안에 CSV 파일이 없습니다.`);
        for (const z of ents) files.push({ name: z.name, size: z.uSize, blob: z.blob, method: z.method, from: f.name });
      } catch (err) { alert(`${f.name}: ${err.message || err}`); }
      finally { hideBusy(); }
    } else if (/\.csv$/i.test(f.name)) files.push({ name: f.name, size: f.size, blob: f });
  }
  return files;
}
function register(reg, files) {
  const todo = files.filter(f => ![...reg.values()].some(x => x.name === f.name && x.size === f.size && x.status !== 'error'));
  todo.sort((a, b) => b.size - a.size);
  for (const f of todo) {
    const fid = ++fidSeq;
    reg.set(fid, { fid, name: f.name, size: f.size, file: f.blob, method: f.method, from: f.from, status: 'wait', loaded: 0, n: 0 });
  }
  return [...reg.values()].filter(x => x.status === 'wait');
}
function runPool(queue, extra, lbl, render, onAll) {
  const par = Math.max(1, Math.min(4, (navigator.hardwareConcurrency || 4) - 1));
  let running = 0; const res = [];
  const totalBytes = queue.reduce((a, b) => a + b.size, 0) || 1;
  const tick = () => {
    const l = queue.reduce((a, b) => a + (b.status === 'done' ? b.size : b.loaded), 0);
    showBusy(`${lbl}… ${queue.filter(q => q.status === 'done').length}/${queue.length} 파일`, l / totalBytes);
  };
  tick();
  const next = () => {
    if (!queue.some(q => q.status === 'wait' || q.status === 'run')) {
      showBusy('병합·인덱싱 중…', 1);
      setTimeout(() => { try { onAll(res); } finally { hideBusy(); } }, 30);
      return;
    }
    while (running < par) {
      const q = queue.find(q => q.status === 'wait'); if (!q) break;
      running++; q.status = 'run';
      const w = new Worker(workerURL);
      w.onmessage = e => {
        const m = e.data;
        if (m.type === 'progress') { q.loaded = m.loaded; q.n = m.n; render(); tick(); }
        else if (m.type === 'done') { q.status = 'done'; q.n = m.bTotal != null ? m.bTotal : m.n; q.bad = m.bad; q.enc = m.enc; q.file = null; res.push(m); w.terminate(); running--; render(); tick(); next(); }
        else if (m.type === 'error') { q.status = 'error'; q.err = m.msg; q.file = null; w.terminate(); running--; render(); next(); }
      };
      w.onerror = ev => { q.status = 'error'; q.err = ev.message || '오류'; w.terminate(); running--; render(); next(); };
      w.postMessage({ file: q.file, fid: q.fid, method: q.method, usize: q.method !== undefined ? q.size : 0, ...extra });
    }
  };
  next();
}
async function loadFiles(input) {
  if (CMP.on) { alert('개폐업 비교 후에는 현재 데이터를 추가할 수 없습니다. [데이터 비우기] 후 다시 불러오세요.'); return; }
  const files = await gatherFiles(input); if (!files.length) return;
  const queue = register(D.files, files); if (!queue.length) { alert('이미 불러온 파일입니다.'); return; }
  renderFiles();
  runPool(queue, {}, '데이터 읽는 중', renderFiles, res => { parts.push(...res); finalize(); afterLoad(true); });
}
function renderFiles() { renderFileList(D.files, $('#flist')); }
function renderFileList(reg, el) {
  el.innerHTML = [...reg.values()].map(x => {
    const pct = x.status === 'done' ? 100 : Math.round((x.loaded / (x.size || 1)) * 100);
    const st = x.status === 'done'
      ? `${fmt(x.n)}건 · ${x.enc === 'vault' ? 'AES-256 Vault v2' : x.enc === 'api' ? 'OpenAPI 실시간' : (x.enc === 'euc-kr' ? 'EUC-KR' : 'UTF-8')}${x.bad ? ` · 좌표없음 ${fmt(x.bad)}` : ''}`
      : x.status === 'error' ? `<span style="color:var(--accent)">오류: ${esc(x.err)}</span>`
      : x.status === 'run' ? `${pct}% · ${fmt(x.n)}건` : '대기';
    const short = x.name.replace(/^소상공인시장진흥공단_상가\(상권\)정보_/, '');
    const ico = x.enc === 'vault' ? '🔐 ' : x.enc === 'api' ? '🔌 ' : (x.from ? '🗜 ' : '');
    const mb = x.size ? `${(x.size / 1048576).toFixed(1)}MB` : '';
    return `<div class="fitem"><div class="nm"><span title="${esc(x.name)}">${ico}${esc(short)}</span><span class="note">${mb}</span></div>
      <div class="note">${st}</div>${x.status === 'run' ? `<div class="bar"><i style="width:${pct}%"></i></div>` : ''}</div>`;
  }).join('');
}
function showBusy(msg, p) { $('#busy').style.display = 'flex'; $('#busyMsg').textContent = msg; $('#busyBar').style.width = Math.round((p || 0) * 100) + '%'; }
function hideBusy() { $('#busy').style.display = 'none'; }

/* ==================== Vault On-Demand Sido Loader ==================== */
function renderVaultSidoGrids() {
  if (!VAULT_SUMMARY || !Array.isArray(VAULT_SUMMARY.sidos)) {
    $('#vaultBadge').textContent = '로컬 모드';
    $('#sidoGrid').innerHTML = '<div class="note" style="grid-column:1/4">암호화 시도 데이터가 없습니다. 아래 ZIP 업로드 또는 API 탭을 이용하세요.</div>';
    return;
  }
  const sidos = VAULT_SUMMARY.sidos;
  $('#vaultBadge').textContent = `${VAULT_SUMMARY.dataYM} · 총 ${fmt(VAULT_SUMMARY.totalStores)}건`;
  $('#emptyMeta').innerHTML = `기준 <b>${esc(VAULT_SUMMARY.dataYM)}</b> · 전국 <b>${fmt(VAULT_SUMMARY.totalStores)}건</b> (${sidos.length}개 시도 AES-256-GCM 분할 암호화 v2)<br>건물관리번호·신규등재·프랜차이즈·도로명·우편번호·KSIC 코드 통합 탑재`;

  const html = sidos.map(s => {
    const ld = loadedSidos.has(s.slug);
    return `<button type="button" class="sido-btn${ld ? ' loaded' : ''}" data-sido-slug="${esc(s.slug)}">
      <b>${esc(s.short)}</b>
      <span>${fmt(s.count)}건 · ${(s.bytes / 1048576).toFixed(1)}MB</span>
    </button>`;
  }).join('');
  $('#sidoGrid').innerHTML = html;
  $('#emptySidoGrid').innerHTML = html;
}

async function loadVaultSido(slug, fitAfter = true) {
  if (!VAULT_KEY || !VAULT_SUMMARY) { toast('Vault 잠금 해제 상태에서만 사용할 수 있습니다'); return; }
  if (CMP.on) { alert('개폐업 비교 후에는 시도를 추가할 수 없습니다. [데이터 비우기] 후 다시 진행하세요.'); return; }
  if (loadedSidos.has(slug)) {
    const s = VAULT_SUMMARY.sidos.find(x => x.slug === slug);
    if (s) map.setView([s.lat, s.lon], 11);
    toast(`${s ? s.name : slug}는 이미 로드되어 있습니다`);
    return;
  }
  const meta = VAULT_SUMMARY.sidos.find(x => x.slug === slug);
  if (!meta) return;

  $$(`[data-sido-slug="${CSS.escape(slug)}"]`).forEach(b => b.classList.add('loading'));
  showBusy(`🔐 ${meta.name} (${(meta.bytes / 1048576).toFixed(1)}MB) 복호화 중…`, 0.08);
  try {
    const data = await fetchDecJson(`sido_${slug}`, p => showBusy(`🔐 ${meta.name} 다운로드·복호화 중…`, 0.1 + p * 0.65));
    showBusy(`⚡ ${meta.name} ${fmt(data.n)}건 인덱싱 중…`, 0.85);
    await new Promise(r => setTimeout(r, 15));

    const n = data.n;
    const lat = new Float64Array(n), lon = new Float64Array(n);
    for (let i = 0; i < n; i++) { lat[i] = data.lat[i] / 1e6; lon[i] = data.lon[i] / 1e6; }
    const codes = {};
    for (const f of CAT) codes[f] = data.cols[f] ? Uint32Array.from(data.cols[f]) : new Uint32Array(n);

    parts.push({
      n,
      dicts: data.dicts,
      codeMaps: data.codeMaps || null,
      codes,
      bldId: data.bldId ? Uint32Array.from(data.bldId) : null,
      strs: data.strs,
      lat, lon,
      isApi: false,
    });
    finalize();
    loadedSidos.add(slug);

    const fid = ++fidSeq;
    D.files.set(fid, { fid, name: `${meta.name} (${VAULT_SUMMARY.dataYM})`, size: meta.bytes, status: 'done', loaded: meta.bytes, n, enc: 'vault' });
    renderFiles();
    renderVaultSidoGrids();
    afterLoad(false);
    if (fitAfter) map.setView([meta.lat, meta.lon], slug === 'sejong' || slug === 'seoul' ? 12 : 11);
    toast(`🔐 ${meta.name} ${fmt(n)}건 복호화 완료`);
  } catch (err) {
    console.error(err);
    toast(`복호화 실패: ${err.message}`);
  } finally {
    $$(`[data-sido-slug="${CSS.escape(slug)}"]`).forEach(b => b.classList.remove('loading'));
    hideBusy();
  }
}

/* ==================== Filters (v2: RegYM, Franchise, Building, Road, Zip, KSIC) ==================== */
const sel = { sido: new Set(), sgg: new Set(), dong: new Set(), roadNm: new Set(), zip: new Set(), l1: new Set(), l2: new Set(), l3: new Set(), floor: new Set(), st: new Set() };
let kwTerms = [], onlySel = false, onlyApi = false;
let regYmFilter = 'all', franFilter = 'all', bldFilter = 'all';

function prune() {
  const P = D.parent;
  if (sel.sido.size) for (const c of [...sel.sgg]) if (!sel.sido.has(P.sgg[c])) sel.sgg.delete(c);
  if (sel.sido.size || sel.sgg.size) {
    const okSgg = s => sel.sgg.size ? sel.sgg.has(s) : sel.sido.has(P.sgg[s]);
    for (const c of [...sel.dong]) if (!okSgg(P.dong[c])) sel.dong.delete(c);
    for (const c of [...sel.roadNm]) if (!okSgg(P.roadNm[c])) sel.roadNm.delete(c);
    for (const c of [...sel.zip]) if (!okSgg(P.zip[c])) sel.zip.delete(c);
  }
  if (sel.l1.size) for (const c of [...sel.l2]) if (!sel.l1.has(P.l2[c])) sel.l2.delete(c);
  if (sel.l1.size || sel.l2.size) for (const c of [...sel.l3]) { const s = P.l3[c]; if (!(sel.l2.size ? sel.l2.has(s) : sel.l1.has(P.l2[s]))) sel.l3.delete(c); }
}

function updateApiDongHint() {
  const el = $('#apiDongHint');
  if (!el) return;
  if (sel.dong.size) {
    const first = [...sel.dong][0];
    const cd = D.codeMaps.dong[first] || '';
    el.innerHTML = `선택 행정동: <b>${esc(label('dong', first))}</b>${sel.dong.size > 1 ? ` 외 ${sel.dong.size - 1}개` : ''} ${cd ? `<code>${esc(cd)}</code>` : ''}`;
  } else {
    el.textContent = '행정동 미선택 시 현재 지도 중심의 행정동코드 자동 연동';
  }
}

function computeFilter(skip) {
  const N = D.N, C = D.codes;
  const fl = Object.keys(sel).filter(f => sel[f].size && f !== skip).map(f => {
    const a = new Uint8Array(D.dict[f].length);
    for (const c of sel[f]) a[c] = 1;
    return [C[f], a];
  });
  const out = new Uint32Array(N); let k = 0; const terms = kwTerms;
  const minYM = regYmFilter === '3m' ? ymSubMonths(D.maxYM, 3)
    : regYmFilter === '6m' ? ymSubMonths(D.maxYM, 6)
    : regYmFilter === '1y' ? ymSubMonths(D.maxYM, 12)
    : regYmFilter === '2026' ? 202601 : 0;
  const isOld = regYmFilter === 'old';
  const ksicCodes = D.codeMaps.ksic, ksicDict = D.dict.ksic, zipDict = D.dict.zip;

  outer: for (let i = 0; i < N; i++) {
    if (onlySel && !selMask[i]) continue;
    if (onlyApi && !D.apiMask[i]) continue;
    if (minYM && D.regYM[i] < minYM) continue;
    if (isOld && (D.regYM[i] === 0 || D.regYM[i] > 202208)) continue;
    if (franFilter === 'ind' && D.isFran[i]) continue;
    if (franFilter === 'fran' && !D.isFran[i]) continue;
    if (bldFilter !== 'all') {
      const bc = D.bldId[i] ? D.bldCnt[D.bldId[i]] : 1;
      if (bldFilter === '1-2' && bc > 2) continue;
      if (bldFilter === '3-9' && (bc < 3 || bc > 9)) continue;
      if (bldFilter === '10' && bc < 10) continue;
      if (bldFilter === '30' && bc < 30) continue;
      if (bldFilter === '100' && bc < 100) continue;
    }
    for (let j = 0; j < fl.length; j++) if (!fl[j][1][fl[j][0][i]]) continue outer;
    if (terms.length) {
      const kc = C.ksic[i];
      const s = (D.strs[i] + '\x1f' + (ksicCodes[kc] || '') + '\x1f' + (ksicDict[kc] || '') + '\x1f' + (zipDict[C.zip[i]] || '')).toLowerCase();
      let ok = false;
      for (const grp of terms) {
        let all = true;
        for (const t of grp) if (s.indexOf(t) < 0) { all = false; break; }
        if (all) { ok = true; break; }
      }
      if (!ok) continue;
    }
    out[k++] = i;
  }
  return out.subarray(0, k);
}

function applyFilter() {
  filtered = computeFilter();
  $('#sFilt').textContent = fmt(filtered.length);
  renderLegend();
  layer.redraw();
  updateApiDongHint();
  if (CMP.on && curTab === 'cmp') renderCmp();
}
let fTimer = null;
function refilter() { clearTimeout(fTimer); fTimer = setTimeout(() => { applyFilter(); renderFilterUI(); }, 60); }
function chipGroup(el, f) {
  const items = D.dict[f].map((_, c) => c).sort((a, b) => D.cnt[f][b] - D.cnt[f][a]);
  el.innerHTML = items.map(c => `<span class="chip ${sel[f].has(c) ? 'on' : ''}" data-c="${c}">${f === 'l1' ? `<span class="dot" style="background:${colorOf[c]}"></span>` : ''}${esc(label(f, c))} <span class="n">${fmt(D.cnt[f][c])}</span></span>`).join('');
  el.onclick = e => { const ch = e.target.closest('.chip'); if (!ch) return; const c = +ch.dataset.c; sel[f].has(c) ? sel[f].delete(c) : sel[f].add(c); prune(); refilter(); };
}
const mlSearch = {};
function multiList(el, f, allow) {
  if (!el._init) {
    el.innerHTML = `<input type="search" placeholder="검색"><div class="items"></div>`;
    el._init = 1;
    el.querySelector('input').oninput = e => { mlSearch[f] = e.target.value.trim(); multiList(el, f, el._allow); };
    el.querySelector('.items').onchange = e => { const c = +e.target.dataset.c; e.target.checked ? sel[f].add(c) : sel[f].delete(c); prune(); refilter(); };
  }
  el._allow = allow;
  const q = (mlSearch[f] || '').toLowerCase(); let items = [];
  const byCount = f === 'floor' || f === 'roadNm' || f === 'zip';
  for (let c = 0; c < D.dict[f].length; c++) {
    if (allow && !allow(c)) continue;
    const lb = label(f, c);
    if ((f === 'roadNm' || f === 'zip') && lb === '(미상)') continue;
    const parentSgg = f === 'dong' ? D.parent.dong[c] : f === 'roadNm' ? D.parent.roadNm[c] : f === 'zip' ? D.parent.zip[c] : -1;
    const full = parentSgg >= 0 ? label('sgg', parentSgg) + ' ' + lb : lb;
    if (q && full.toLowerCase().indexOf(q) < 0) continue;
    items.push([c, lb, full]);
  }
  items.sort((a, b) => (sel[f].has(b[0]) - sel[f].has(a[0])) || (byCount ? D.cnt[f][b[0]] - D.cnt[f][a[0]] : a[2].localeCompare(b[2], 'ko')));
  const MAX = 400;
  el.querySelector('.items').innerHTML = items.slice(0, MAX).map(([c, lb, full]) => `<label><input type="checkbox" data-c="${c}" ${sel[f].has(c) ? 'checked' : ''}>${esc((f === 'dong' || f === 'roadNm') && !sel.sgg.size ? full : lb)}<span class="n">${fmt(D.cnt[f][c])}</span></label>`).join('')
    + (items.length > MAX ? `<div class="more">외 ${fmt(items.length - MAX)}개 · 검색어로 좁히세요</div>` : '')
    + (!items.length ? '<div class="more">항목 없음</div>' : '');
}
function renderFilterUI() {
  if (!D.N) return;
  chipGroup($('#f-sido'), 'sido'); chipGroup($('#f-l1'), 'l1');
  const P = D.parent;
  const regionAllow = parentArr => (sel.sgg.size || sel.sido.size)
    ? c => sel.sgg.size ? sel.sgg.has(parentArr[c]) : sel.sido.has(P.sgg[parentArr[c]])
    : null;
  multiList($('#f-sgg'), 'sgg', sel.sido.size ? c => sel.sido.has(P.sgg[c]) : null);
  multiList($('#f-dong'), 'dong', regionAllow(P.dong));
  multiList($('#f-roadNm'), 'roadNm', regionAllow(P.roadNm));
  multiList($('#f-zip'), 'zip', regionAllow(P.zip));
  multiList($('#f-l2'), 'l2', sel.l1.size ? c => sel.l1.has(P.l2[c]) : null);
  multiList($('#f-l3'), 'l3', (sel.l2.size || sel.l1.size) ? c => sel.l2.size ? sel.l2.has(P.l3[c]) : sel.l1.has(P.l2[P.l3[c]]) : null);
  multiList($('#f-floor'), 'floor', null);
  for (const f of Object.keys(sel)) { const e = $('#c-' + f); if (e) e.textContent = sel[f].size ? `${sel[f].size}개 선택` : '전체'; }
  syncQuickChipCounts();
}
function syncQuickChipCounts() {
  $$('#f-regym .chip').forEach(c => c.classList.toggle('on', c.dataset.regym === regYmFilter));
  $$('#f-fran .chip').forEach(c => c.classList.toggle('on', c.dataset.fran === franFilter));
  $$('#f-bld .chip').forEach(c => c.classList.toggle('on', c.dataset.bld === bldFilter));
  const regMap = { all: '전체', '3m': '최근 3개월', '6m': '최근 6개월', '1y': '최근 1년', '2026': '2026년 신규', old: '기존(22.08 이전)' };
  const frMap = { all: '전체', ind: '개인 점포만', fran: '프랜차이즈·지점만' };
  const blMap = { all: '전체', '1-2': '단독·소형(1~2)', '3-9': '중형(3~9)', '10': '대형 상가(10+)', '30': '초대형(30+)', '100': '메가빌딩(100+)' };
  if ($('#c-regym')) $('#c-regym').textContent = regMap[regYmFilter] || '전체';
  if ($('#c-fran')) $('#c-fran').textContent = frMap[franFilter] || '전체';
  if ($('#c-bld')) $('#c-bld').textContent = blMap[bldFilter] || '전체';
}

/* ==================== Legend ==================== */
const hiddenL1 = new Set();
function stToggle(c) {
  const cur = sel.st.size ? new Set(sel.st) : new Set([0, 1, 2, 3]);
  cur.has(c) ? cur.delete(c) : cur.add(c);
  if (!cur.size) return;
  sel.st = cur.size === 4 ? new Set() : cur;
  syncCmpButtons(); refilter();
}
function renderLegend() {
  const el = $('#legend');
  if (!D.N) { el.style.display = 'none'; return; }
  el.style.display = 'block';
  if (CMP.on && colorMode === 'st') {
    const ac = sel.st.size ? sel.st : new Set([0, 1, 2, 3]);
    const base = computeFilter('st'), cnt = [0, 0, 0, 0], ST = D.codes.st;
    for (let k = 0; k < base.length; k++) cnt[ST[base[k]]]++;
    el.innerHTML = `<div class="hd">개폐업 ${esc(CMP.baseYM)} → ${esc(CMP.curYM)}<span class="lnk" id="lgCat">업종 색상</span></div>` +
      [1, 2, 0, 3].filter(c => cnt[c] || c < 3).map(c => `<div class="row ${ac.has(c) ? '' : 'off'}" data-st="${c}"><span class="dot" style="background:${ST_COL[c]}"></span>${['유지(계속 영업)', '신규 개업', '폐업(사라짐)', '비교 제외 지역'][c]}<span class="n">${fmt(cnt[c])}</span></div>`).join('') +
      (cust.list.length ? `<div class="row cust" data-cust="1" style="${cust.show ? '' : 'opacity:.35'}"><span class="custmk"></span>고객 <span class="n">${fmt(cust.list.filter(c => c.lat).length)}</span></div>` : '');
    return;
  }
  const cnt = new Array(D.dict.l1.length).fill(0), C = D.codes.l1;
  for (let k = 0; k < filtered.length; k++) cnt[C[filtered[k]]]++;
  const order = D.dict.l1.map((_, c) => c).filter(c => cnt[c] || hiddenL1.has(c)).sort((a, b) => cnt[b] - cnt[a]);
  el.innerHTML = `<div class="hd">업종 대분류<span class="lnk" id="lgAll">전체</span><span class="lnk" style="margin-left:8px" id="lgNone">없음</span>${CMP.on ? '<span class="lnk" style="margin-left:8px" id="lgSt">개폐업 색상</span>' : ''}</div>` +
    order.map(c => `<div class="row ${hiddenL1.has(c) ? 'off' : ''}" data-c="${c}"><span class="dot" style="background:${colorOf[c]}"></span>${esc(D.dict.l1[c])}<span class="n">${fmt(cnt[c])}</span></div>`).join('') +
    (cust.list.length ? `<div class="row cust" data-cust="1" style="${cust.show ? '' : 'opacity:.35'}"><span class="custmk"></span>고객 <span class="n">${fmt(cust.list.filter(c => c.lat).length)}</span></div>` : '');
}

/* ==================== Map, VWorld WMTS Basemaps & WMS Overlays ==================== */
let map = null, curBase = null, layer = null, zoneLayer = null, parcelLayer = null;
const wmsOverlays = { cadastral: null, zoning: null, bldg: null };

const G = (lyrs, cls) => L.tileLayer(`https://mt{s}.google.com/vt/lyrs=${lyrs}&hl=ko&gl=KR&x={x}&y={y}&z={z}`, { subdomains: '0123', maxZoom: 20, attribution: '© Google', className: cls || '' });
const VW = (type, ext = 'png', maxNative = 18) => {
  const k = getVWorldKey();
  return L.tileLayer(`https://api.vworld.kr/req/wmts/1.0.0/${encodeURIComponent(k)}/${type}/{z}/{y}/{x}.${ext}`, {
    maxZoom: 20, maxNativeZoom: maxNative, minZoom: 6, attribution: '© VWorld 국토교통부',
  });
};
const BASES = {
  vwhite: () => VW('white', 'png', 18),
  vbase: () => VW('Base', 'png', 19),
  vmidnight: () => VW('midnight', 'png', 18),
  vsat: () => VW('Satellite', 'jpeg', 19),
  vhyb: () => L.layerGroup([VW('Satellite', 'jpeg', 19), VW('Hybrid', 'png', 19)]),
  gsoft: () => G('m', 'tl-soft'),
  gmap: () => G('m'),
  gdark: () => G('m', 'tl-dark'),
  gsat: () => G('y'),
  esri: () => L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}', { maxZoom: 16, maxNativeZoom: 16, attribution: '© Esri' }),
  osm: () => L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 19, attribution: '© OpenStreetMap' }),
};
function setBase(v) {
  if (!map || !BASES[v]) return;
  if (v.startsWith('v') && !getVWorldKey()) {
    toast('브이월드 인증키가 없어 구글 지도로 전환합니다');
    v = 'gsoft';
  }
  if (curBase) map.removeLayer(curBase);
  curBase = BASES[v]().addTo(map);
  if (curBase.bringToBack) curBase.bringToBack();
  else if (curBase.eachLayer) curBase.eachLayer(l => l.bringToBack && l.bringToBack());
  $('#baseSel').value = v;
  store.set('base', v);
}
let showStoreLabels = true, showStoreMarkers = true, measureMode = false, measurePts = [], measureLayer = null;
function toggleWmsOverlay(kind) {
  if (!map) return;
  const key = getVWorldKey();
  if (!key) { toast('브이월드 인증키를 먼저 입력해 주세요'); return; }
  const btnMap = { sido: '#ovSido', sgg: '#ovSgg', emd: '#ovEmd', cadastral: '#ovCadastral', zoning: '#ovZoning', bldg: '#ovBldg' };
  const btnId = btnMap[kind];
  if (wmsOverlays[kind]) {
    map.removeLayer(wmsOverlays[kind]);
    wmsOverlays[kind] = null;
    $(btnId)?.classList.remove('on');
    return;
  }
  const cfg = {
    sido: { layers: 'lt_c_adsido_info', styles: 'lt_c_adsido', opacity: 0.85, minZoom: 6, label: '🗺 행정구역(시·도) 경계 ON' },
    sgg: { layers: 'lt_c_adsigg_info', styles: 'lt_c_adsigg', opacity: 0.88, minZoom: 7, label: '🏛 행정구역(시·군·구) 경계·명칭 ON' },
    emd: { layers: 'lt_c_ademd_info', styles: 'lt_c_ademd', opacity: 0.86, minZoom: 11, label: '🏘 행정구역(읍·면·동) 경계·명칭 ON (줌 11+)' },
    cadastral: { layers: 'lp_pa_cbnd_bonbun,lp_pa_cbnd_bubun', styles: '', opacity: 0.85, minZoom: 14, label: '📐 연속지적도 ON (줌 14 이상 확대 시 필지 경계 표시)' },
    zoning: { layers: 'lt_c_uq111', styles: 'lt_c_uq111', opacity: 0.45, minZoom: 11, label: '🏙 도시 용도지역 ON (상업·주거·공업·녹지)' },
    bldg: { layers: 'lt_c_bldginfo', styles: '', opacity: 0.72, minZoom: 15, label: '🏢 건물 통합 레이어 ON (줌 15 이상 확대 시 표시)' },
  }[kind];
  if (!cfg) return;
  const wms = L.tileLayer.wms('https://api.vworld.kr/req/wms', {
    layers: cfg.layers,
    styles: cfg.styles,
    format: 'image/png',
    transparent: true,
    version: '1.3.0',
    key,
    domain: getVWorldDomain(),
    opacity: cfg.opacity,
    maxZoom: 20,
    minZoom: cfg.minZoom,
    attribution: '© VWorld 공간정보',
  }).addTo(map);
  wmsOverlays[kind] = wms;
  $(btnId)?.classList.add('on');
  toast(cfg.label);
}
function renderMeasureOverlay() {
  if (!measureLayer) return;
  measureLayer.clearLayers();
  if (!measurePts.length) return;
  const distM = (a, b) => map.distance(a, b);
  let total = 0;
  measurePts.forEach((pt, i) => {
    L.circleMarker(pt, { radius: 5, color: '#fff', weight: 2, fillColor: '#ea580c', fillOpacity: 1 }).addTo(measureLayer);
    if (i > 0) total += distM(measurePts[i - 1], pt);
  });
  if (measurePts.length >= 2) L.polyline(measurePts, { color: '#ea580c', weight: 3, dashArray: '6 4' }).addTo(measureLayer);
  let area = 0;
  if (measurePts.length >= 3) {
    L.polygon(measurePts, { color: '#ea580c', weight: 1.5, fillColor: '#fb923c', fillOpacity: 0.16, interactive: false }).addTo(measureLayer);
    const lat0 = measurePts.reduce((s, p) => s + p[0], 0) / measurePts.length;
    const mLat = 111132.92 - 559.82 * Math.cos(2 * lat0 * Math.PI / 180);
    const mLon = 111412.84 * Math.cos(lat0 * Math.PI / 180);
    let s = 0;
    for (let i = 0; i < measurePts.length; i++) {
      const [y1, x1] = measurePts[i], [y2, x2] = measurePts[(i + 1) % measurePts.length];
      s += (x1 * mLon) * (y2 * mLat) - (x2 * mLon) * (y1 * mLat);
    }
    area = Math.abs(s) / 2;
  }
  const dStr = total >= 1000 ? `${(total / 1000).toFixed(2)}km` : `${Math.round(total).toLocaleString('ko-KR')}m`;
  const aStr = area > 0 ? ` · 면적 ${fmt(Math.round(area))}㎡ (${fmt(Math.round(area / 3.305785))}평)` : '';
  flash(`📏 측정(${measurePts.length}점): 총 거리 ${dStr}${aStr} · 다시 [📏 측정] 클릭 시 종료`);
}
function setTheme(t) {
  document.documentElement.dataset.theme = t;
  if ($('#themeSel')) $('#themeSel').value = t;
  $$('#setThemeChips .chip').forEach(c => c.classList.toggle('on', c.dataset.th === t));
  store.set('theme', t);
  if (map) {
    const dark = t !== 'clean', b = $('#baseSel').value;
    if (dark && (b === 'gsoft' || b === 'vwhite')) setBase(getVWorldKey() ? 'vmidnight' : 'gdark');
    else if (!dark && (b === 'gdark' || b === 'vmidnight')) setBase(getVWorldKey() ? 'vwhite' : 'gsoft');
  }
}
setTheme(store.get('theme', 'clean'));

/* ==================== Point Layer ==================== */
let dispMode = 'auto', curTab = 'data';
const PAD = 0.25;
const vis = { n: 0, idx: new Uint32Array(0), x: new Float32Array(0), y: new Float32Array(0), r: 4, mode: 'point', clusters: [] };
const kfmt = n => n >= 100000 ? Math.round(n / 10000) + '만' : n >= 10000 ? (n / 10000).toFixed(1) + '만' : n >= 1000 ? (n / 1000).toFixed(1) + '천' : String(n);
const HEAT = (() => {
  const c = document.createElement('canvas'); c.width = 256; c.height = 1;
  const g = c.getContext('2d'), gr = g.createLinearGradient(0, 0, 256, 0);
  [[0, 'rgba(0,0,255,0)'], [.15, '#2b6cff'], [.35, '#00c2ff'], [.55, '#3ddc84'], [.75, '#ffd400'], [1, '#ff2d2d']].forEach(([o, col]) => gr.addColorStop(o, col));
  g.fillStyle = gr; g.fillRect(0, 0, 256, 1);
  return g.getImageData(0, 0, 256, 1).data;
})();

const PointLayer = L.Layer.extend({
  onAdd(m) {
    this._c = L.DomUtil.create('canvas', 'pt-canvas');
    m.getPanes().overlayPane.appendChild(this._c);
    m.on('moveend resize', this.redraw, this);
    m.on('zoomstart', () => { this._c.style.visibility = 'hidden'; });
    this.redraw();
  },
  redraw() {
    const m = this._map; if (!m) return;
    const c = this._c, sz = m.getSize(), dpr = window.devicePixelRatio || 1;
    if (!sz.x || !sz.y) return;
    const px = Math.round(sz.x * PAD), py = Math.round(sz.y * PAD), W = sz.x + 2 * px, H = sz.y + 2 * py;
    c.width = Math.round(W * dpr); c.height = Math.round(H * dpr);
    c.style.width = W + 'px'; c.style.height = H + 'px';
    L.DomUtil.setPosition(c, m.containerPointToLayerPoint([-px, -py]));
    c.style.visibility = 'visible';
    const ctx = c.getContext('2d'); ctx.clearRect(0, 0, c.width, c.height);
    const z = m.getZoom(), sc = 256 * Math.pow(2, z), o = m.getPixelBounds().min, F = filtered, MX = D.mx, MY = D.my, L1 = D.codes.l1;
    if (vis.idx.length < F.length) { vis.idx = new Uint32Array(F.length); vis.x = new Float32Array(F.length); vis.y = new Float32Array(F.length); }
    const hid = new Uint8Array(D.dict.l1.length); for (const h of hiddenL1) hid[h] = 1;
    let n = 0; const ox = o.x, oy = o.y;
    for (let k = 0; k < F.length; k++) {
      const i = F[k]; if (hid[L1[i]]) continue;
      const x = MX[i] * sc - ox; if (x < -px || x > sz.x + px) continue;
      const y = MY[i] * sc - oy; if (y < -py || y > sz.y + py) continue;
      vis.idx[n] = i; vis.x[n] = x; vis.y[n] = y; n++;
    }
    vis.n = n; let inView = 0;
    for (let k = 0; k < n; k++) { const x = vis.x[k], y = vis.y[k]; if (x >= 0 && y >= 0 && x <= sz.x && y <= sz.y) inView++; }
    $('#sView').textContent = fmt(inView);
    const r = z >= 18 ? 7 : z >= 17 ? 6 : z >= 16 ? 5 : z >= 14 ? 4 : 3; vis.r = r;
    let mode = dispMode === 'auto' ? ((z <= 14 && n > 1500) || (z === 15 && n > 8000) ? 'cluster' : 'point') : dispMode;
    vis.mode = mode; vis.clusters = [];
    ctx.setTransform(dpr, 0, 0, dpr, px * dpr, py * dpr);
    if (!showStoreMarkers) { ctx.setTransform(1, 0, 0, 1, 0, 0); if (curTab === 'list') renderViewList(); return; }
    if (mode === 'cluster') this.drawClusters(ctx, n, px, py, W, H, z);
    else if (mode === 'heat') { ctx.setTransform(1, 0, 0, 1, 0, 0); this.drawHeat(ctx, n, px, py, W, H, z); ctx.setTransform(dpr, 0, 0, dpr, px * dpr, py * dpr); }
    else {
      this.drawPoints(ctx, n, r, z);
      if (showStoreLabels && z >= 17 && n <= 260) {
        ctx.font = '700 11px Pretendard, "Malgun Gothic", sans-serif';
        ctx.textAlign = 'center'; ctx.textBaseline = 'bottom';
        const used = [];
        const dark = getComputedStyle(document.documentElement).getPropertyValue('--dark').trim() === '1';
        for (let k = 0; k < n; k++) {
          const x = vis.x[k], y = vis.y[k] - r - 3;
          if (used.some(u => Math.abs(u[0] - x) < 76 && Math.abs(u[1] - y) < 16)) continue;
          const nm = S(vis.idx[k]).name;
          if (!nm) continue;
          const lbl = nm.length > 10 ? nm.slice(0, 9) + '…' : nm;
          used.push([x, y]);
          ctx.lineWidth = 3; ctx.strokeStyle = dark ? 'rgba(15,23,42,.92)' : 'rgba(255,255,255,.95)';
          ctx.strokeText(lbl, x, y);
          ctx.fillStyle = dark ? '#f8fafc' : '#0f172a';
          ctx.fillText(lbl, x, y);
        }
      }
    }
    if (selCount && mode !== 'cluster') {
      const sp = new Path2D(), rr = Math.max(r + 3, 5); let any = 0;
      for (let k = 0; k < n; k++) if (selMask[vis.idx[k]]) { sp.moveTo(vis.x[k] + rr, vis.y[k]); sp.arc(vis.x[k], vis.y[k], rr, 0, 6.2832); any = 1; }
      if (any) { ctx.lineWidth = 4; ctx.strokeStyle = '#fff'; ctx.stroke(sp); ctx.lineWidth = 2.2; ctx.strokeStyle = '#e60012'; ctx.stroke(sp); }
    }
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    if (curTab === 'list') renderViewList();
  },
  drawPoints(ctx, n, r, z) {
    const [CK, COL, ORD] = ckey(), order = ORD || COL.map((_, i) => i), stm = !!ORD, fade = c => stm && (c === 0 || c === 3);
    if (n > 40000) {
      const s = z >= 13 ? 3 : z >= 11 ? 2.2 : z >= 9 ? 1.6 : 1.2;
      const groups = COL.map(() => []);
      for (let k = 0; k < n; k++) groups[CK[vis.idx[k]]].push(k);
      for (const c of order) {
        const g = groups[c]; if (!g || !g.length) continue;
        ctx.globalAlpha = fade(c) ? .3 : (z >= 12 ? .75 : .6);
        const ss = stm && !fade(c) ? s * 1.6 : s, hh = ss / 2;
        ctx.fillStyle = COL[c]; ctx.beginPath();
        for (const k of g) ctx.rect(vis.x[k] - hh, vis.y[k] - hh, ss, ss);
        ctx.fill();
      }
      ctx.globalAlpha = 1;
    } else {
      const paths = COL.map(() => new Path2D());
      for (let k = 0; k < n; k++) {
        const c = CK[vis.idx[k]], rr = fade(c) ? r * .7 : r, p = paths[c];
        p.moveTo(vis.x[k] + rr, vis.y[k]); p.arc(vis.x[k], vis.y[k], rr, 0, 6.2832);
      }
      ctx.lineWidth = z >= 15 ? 1.2 : .8; ctx.strokeStyle = 'rgba(255,255,255,.95)';
      for (const c of order) {
        const p = paths[c]; if (!p) continue;
        ctx.fillStyle = COL[c]; ctx.globalAlpha = fade(c) ? .45 : .92; ctx.fill(p);
        ctx.globalAlpha = 1; if (z >= 13 && !fade(c)) ctx.stroke(p);
      }
    }
  },
  drawClusters(ctx, n, px, py, W, H, z) {
    const cs = z >= 14 ? 56 : 66, cols = Math.ceil(W / cs), rows = Math.ceil(H / cs), NC = cols * rows, K = Math.max(1, ckey()[1].length), [CK, COL] = ckey();
    const cnt = new Uint32Array(NC), sx = new Float64Array(NC), sy = new Float64Array(NC), cat = new Uint32Array(NC * K), sl = new Uint32Array(NC);
    for (let k = 0; k < n; k++) {
      const x = vis.x[k] + px, y = vis.y[k] + py;
      const cx = Math.min(cols - 1, Math.max(0, x / cs | 0)), cy = Math.min(rows - 1, Math.max(0, y / cs | 0)), ci = cy * cols + cx;
      cnt[ci]++; sx[ci] += vis.x[k]; sy[ci] += vis.y[k]; cat[ci * K + CK[vis.idx[k]]]++;
      if (selMask[vis.idx[k]]) sl[ci]++;
    }
    let max = 1; for (let i = 0; i < NC; i++) if (cnt[i] > max) max = cnt[i];
    const dark = getComputedStyle(document.documentElement).getPropertyValue('--dark').trim() === '1';
    ctx.font = '700 11px Pretendard, "Malgun Gothic", sans-serif'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    for (let i = 0; i < NC; i++) {
      const c = cnt[i]; if (!c) continue;
      const x = sx[i] / c, y = sy[i] / c;
      if (c <= 3) {
        for (let j = 0; j < K; j++) if (cat[i * K + j]) { ctx.beginPath(); ctx.arc(x, y, 4.5, 0, 6.2832); ctx.fillStyle = COL[j]; ctx.fill(); ctx.lineWidth = 1.2; ctx.strokeStyle = '#fff'; ctx.stroke(); }
        vis.clusters.push({ x, y, r: 7, c }); continue;
      }
      const R = Math.min(cs * .46, 11 + Math.sqrt(c / max) * 20 + Math.log10(c) * 2);
      let a0 = -Math.PI / 2;
      for (let j = 0; j < K; j++) {
        const v = cat[i * K + j]; if (!v) continue;
        const a1 = a0 + v / c * Math.PI * 2;
        ctx.beginPath(); ctx.arc(x, y, R, a0, a1); ctx.arc(x, y, R * .62, a1, a0, true); ctx.closePath();
        ctx.fillStyle = COL[j]; ctx.fill(); a0 = a1;
      }
      ctx.beginPath(); ctx.arc(x, y, R * .62, 0, 6.2832); ctx.fillStyle = dark ? 'rgba(17,22,36,.92)' : 'rgba(255,255,255,.95)'; ctx.fill();
      ctx.beginPath(); ctx.arc(x, y, R, 0, 6.2832); ctx.lineWidth = 1.5; ctx.strokeStyle = dark ? 'rgba(0,0,0,.6)' : 'rgba(255,255,255,.9)'; ctx.stroke();
      if (sl[i]) { ctx.beginPath(); ctx.arc(x, y, R + 3, 0, 6.2832); ctx.lineWidth = 2.5; ctx.strokeStyle = '#e60012'; ctx.stroke(); }
      ctx.font = `700 ${R > 24 ? 12.5 : R > 17 ? 11.5 : 10}px Pretendard, "Malgun Gothic", sans-serif`;
      ctx.fillStyle = dark ? '#fff' : '#1b2230';
      ctx.fillText(kfmt(c), x, y + .5);
      vis.clusters.push({ x, y, r: R, c });
    }
  },
  drawHeat(ctx, n, px, py, W, H, z) {
    const dpr = window.devicePixelRatio || 1, q = 3, gw = Math.ceil(W / q), gh = Math.ceil(H / q), g = new Float32Array(gw * gh);
    for (let k = 0; k < n; k++) { const x = (vis.x[k] + px) / q | 0, y = (vis.y[k] + py) / q | 0; if (x >= 0 && y >= 0 && x < gw && y < gh) g[y * gw + x]++; }
    const rad = z >= 15 ? 4 : z >= 12 ? 5 : 6, tmp = new Float32Array(gw * gh);
    const blur = (src, dst, horiz) => {
      for (let y = 0; y < gh; y++) for (let x = 0; x < gw; x++) {
        let s = 0;
        for (let d = -rad; d <= rad; d++) { const xx = horiz ? x + d : x, yy = horiz ? y : y + d; if (xx >= 0 && yy >= 0 && xx < gw && yy < gh) s += src[yy * gw + xx]; }
        dst[y * gw + x] = s;
      }
    };
    blur(g, tmp, true); blur(tmp, g, false);
    let mx = 0; for (let i = 0; i < g.length; i++) if (g[i] > mx) mx = g[i];
    if (!mx) return;
    const lm = Math.log1p(mx), oc = document.createElement('canvas'); oc.width = gw; oc.height = gh;
    const oc2 = oc.getContext('2d'), img = oc2.createImageData(gw, gh), d = img.data;
    for (let i = 0; i < g.length; i++) {
      if (!g[i]) continue;
      const v = Math.log1p(g[i]) / lm, ci = Math.min(255, v * 255 | 0) * 4;
      d[i * 4] = HEAT[ci]; d[i * 4 + 1] = HEAT[ci + 1]; d[i * 4 + 2] = HEAT[ci + 2]; d[i * 4 + 3] = Math.min(235, 40 + v * 230);
    }
    oc2.putImageData(img, 0, 0); ctx.imageSmoothingEnabled = true; ctx.drawImage(oc, 0, 0, gw * q * dpr, gh * q * dpr);
  },
});

/* ==================== Popups & Selection (v2 Enriched) ==================== */
function hits(cp, extra) {
  const r = vis.r + (extra || 4), r2 = r * r, out = [];
  for (let k = 0; k < vis.n; k++) { const dx = vis.x[k] - cp.x, dy = vis.y[k] - cp.y, d = dx * dx + dy * dy; if (d <= r2) out.push([d, vis.idx[k]]); }
  out.sort((a, b) => a[0] - b[0]); return out.map(a => a[1]);
}
function sameBuildingIds(bldId) {
  const out = [];
  if (!bldId) return out;
  for (let i = 0; i < D.N; i++) if (D.bldId[i] === bldId) out.push(i);
  return out;
}
function links(name, addr, lat, lon) {
  return `<a href="https://map.naver.com/p/search/${encodeURIComponent((name ? name + ' ' : '') + addr)}" target="_blank">네이버</a>
  <a href="https://map.kakao.com/link/map/${encodeURIComponent(name || addr || '위치')},${lat},${lon}" target="_blank">카카오</a>
  <a href="https://map.kakao.com/link/roadview/${lat},${lon}" target="_blank">로드뷰</a>`;
}
const badge = i => {
  let out = '';
  if (D.apiMask[i]) out += '<span class="bdg ba">API</span>';
  if (CMP.on) {
    const t = D.codes.st[i];
    if (t === 1) out += '<span class="bdg bn">신규</span>';
    else if (t === 2) out += '<span class="bdg bc">폐업</span>';
  } else if (D.regYM[i] >= ymSubMonths(D.maxYM, 6)) {
    out += `<span class="bdg bnew">${fmtYM(D.regYM[i])}신규</span>`;
  }
  if (D.isFran[i]) out += '<span class="bdg bf">프랜</span>';
  const bc = D.bldId[i] ? D.bldCnt[D.bldId[i]] : 0;
  if (bc >= 10) out += `<span class="bdg bb">🏢${bc}</span>`;
  return out;
};
function itemHTML(i) {
  const s = S(i), C = D.codes, fl = label('floor', C.floor[i]);
  const zip = label('zip', C.zip[i]);
  const ksicCd = D.codeMaps.ksic[C.ksic[i]] || '';
  const ksicNm = D.dict.ksic[C.ksic[i]] || '';
  const dongCd = D.codeMaps.dong[C.dong[i]] || '';
  const sggCd = D.codeMaps.sgg[C.sgg[i]] || '';
  const ym = D.regYM[i];
  const bid = D.bldId[i], bcnt = bid ? D.bldCnt[bid] : 0;
  return `<div class="pp"><div class="a"><span class="dot" style="background:${colorOf[C.l1[i]]}"></span>${badge(i)}${esc(s.name)}${s.branch ? ` <span style="font-weight:400;color:#777">${esc(s.branch)}</span>` : ''}</div>
   <div class="b">${esc(D.dict.l1[C.l1[i]])} › ${esc(label('l2', C.l2[i]))} › <b>${esc(label('l3', C.l3[i]))}</b></div>
   <div class="c">${zip && zip !== '(미상)' ? `[${esc(zip)}] ` : ''}${esc(s.addr)}${s.bld ? ' (' + esc(s.bld) + ')' : ''}${fl && fl !== '(미상)' ? ' · ' + esc(fl) + '층' : ''}${s.ho ? ' ' + esc(s.ho) + '호' : ''}</div>
   <div class="c">${esc(label('sgg', C.sgg[i]))}${sggCd ? `(${esc(sggCd)})` : ''} ${esc(label('dong', C.dong[i]))}${dongCd ? `(${esc(dongCd)})` : ''}${ksicNm ? ` · ${ksicCd ? esc(ksicCd) + ' ' : ''}${esc(ksicNm)}` : ''}</div>
   <div class="c">${D.isFran[i] ? '프랜차이즈·지점' : '개인 점포'}${ym ? ` · 등재 ${String(ym).slice(0, 4)}.${String(ym).slice(4, 6)}` : ''}${bcnt > 1 ? ` · 같은 건물 ${fmt(bcnt)}개 업소` : ''}</div>
   <div class="pbtn"><button data-tg="${i}" class="${selMask[i] ? 'on' : ''}">${selMask[i] ? '선택됨 ✓' : '+ 선택'}</button>${bcnt > 1 ? `<button data-bld="${bid}">🏢 건물 ${bcnt}개</button><button data-bldsel="${bid}">+ 건물전체</button>` : ''}<button data-vwland="${D.lat[i]},${D.lon[i]},${esc(s.name)}">📐 공시지가·용도</button>${links(s.name, s.addr, D.lat[i], D.lon[i])}</div></div>`;
}
let popIds = [];
function openPopup(ids, ll) {
  if (!ids.length) return;
  const MAX = 60; popIds = ids;
  const h = (ids.length > 1 ? `<div class="pp-h">이 위치/건물 업소 ${fmt(ids.length)}개 <button data-tgall="1" style="font-size:11px">모두 선택</button></div>` : '') +
    `<div class="pp-list">${ids.slice(0, MAX).map(itemHTML).join('')}${ids.length > MAX ? `<div class="c">외 ${ids.length - MAX}개 (전체 선택 또는 확대해 보세요)</div>` : ''}</div>`;
  L.popup({ maxWidth: 365, autoPanPadding: [40, 40] }).setLatLng(ll || [D.lat[ids[0]], D.lon[ids[0]]]).setContent(h).openOn(map);
}

function setSel(ids, on) {
  let ch = 0;
  for (const i of ids) {
    if (on && !selMask[i]) { selMask[i] = 1; selCount++; ch++; }
    else if (!on && selMask[i]) { selMask[i] = 0; selCount--; ch++; }
  }
  if (ch) {
    $('#sSel').textContent = fmt(selCount);
    layer.redraw(); renderSelPanel();
    if (onlySel && !on) applyFilter();
  }
}
function selIndices() { const out = []; for (let i = 0; i < D.N; i++) if (selMask[i]) out.push(i); return out; }
function bars(ids, f, top, colorFn) {
  const m = new Map(), C = D.codes;
  for (const i of ids) { const c = C[f][i]; if (f === 'roadNm' && label(f, c) === '(미상)') continue; m.set(c, (m.get(c) || 0) + 1); }
  const arr = [...m].sort((a, b) => b[1] - a[1]).slice(0, top), mx = arr.length ? arr[0][1] : 1;
  return arr.map(([c, v]) => {
    const lb = f === 'sgg' ? sggFull(c) : label(f, c);
    return `<div class="r"><span class="lb" title="${esc(lb)}">${esc(lb)}</span><span class="bb"><i style="width:${v / mx * 100}%;background:${colorFn(c)}"></i></span><span class="v">${fmt(v)}</span></div>`;
  }).join('');
}
function renderSelPanel() {
  $('#selCnt').textContent = fmt(selCount) + '개';
  if ($('#selpanel').classList.contains('hide')) return;
  const body = $('#selBody');
  if (!selCount) {
    body.innerHTML = '<div class="note" style="padding:10px 0;line-height:1.8">상단 <b>▭ 사각형 · ✎ 올가미 · ◯ 반경</b> 도구로 영역을 드래그하거나<br><b>Ctrl+클릭</b>으로 하나씩 추가/제외하세요.<br>지도 <b>우클릭</b> → 반경 선택 · 팝업 <b>+ 건물전체</b> → 건물 단위 일괄 선택<br>선택 후 <b>✨ AI 분석</b> 버튼으로 상권 전략을 받을 수 있습니다.</div>';
    return;
  }
  const ids = selIndices(), C = D.codes, LIM = 300;
  let franN = 0, new6N = 0, bigBldN = 0;
  const cut6 = ymSubMonths(D.maxYM, 6);
  for (const i of ids) {
    if (D.isFran[i]) franN++;
    if (D.regYM[i] >= cut6) new6N++;
    if (D.bldId[i] && D.bldCnt[D.bldId[i]] >= 10) bigBldN++;
  }
  const sorted = ids.length > 20000 ? ids.slice(0, LIM) : ids.sort((a, b) => C.sgg[a] - C.sgg[b] || S(a).name.localeCompare(S(b).name, 'ko')).slice(0, LIM);
  body.innerHTML = `
    <div class="kpis" style="margin-top:0">
      <div class="kpi"><span>개인 / 프랜차이즈</span><b>${fmt(ids.length - franN)} / ${fmt(franN)}</b></div>
      <div class="kpi"><span>최근 6개월 신규 / 대형상가</span><b>${fmt(new6N)} / ${fmt(bigBldN)}</b></div>
    </div>
    <div class="brk"><h4>대분류</h4>${bars(ids, 'l1', 12, c => colorOf[c])}</div>
    <div class="brk"><h4>중분류 TOP 10</h4>${bars(ids, 'l2', 10, c => colorOf[D.parent.l2[c]])}</div>
    <div class="brk"><h4>🛣 가로 상권 (도로명 TOP 8)</h4>${bars(ids, 'roadNm', 8, () => '#0f766e')}</div>
    <div class="brk"><h4>시군구</h4>${bars(ids, 'sgg', 8, () => 'var(--accent2)')}</div>
    <h4 style="font-size:12px;margin:8px 0 2px">업소 목록 ${ids.length > LIM ? `<span class="note">(앞 ${LIM}개 · 전체는 CSV)</span>` : ''}</h4>` +
    sorted.map(i => { const s = S(i); return `<div class="li" data-go="${i}"><span class="dot" style="background:${colorOf[C.l1[i]]};margin-top:4px"></span><div class="t"><div class="a">${badge(i)}${esc(s.name)}${s.branch ? ' ' + esc(s.branch) : ''}</div><div class="b">${esc(label('l3', C.l3[i]))} · ${esc(s.addr)}</div></div><span class="x" data-rm="${i}" title="선택 제외">✕</span></div>`; }).join('');
}
function goTo(i) { map.setView([D.lat[i], D.lon[i]], Math.max(map.getZoom(), 18)); setTimeout(() => { layer.redraw(); openPopup([i]); }, 350); }
const mPerDegLat = 111320;
function nearIds(lat, lon, m, src) {
  const out = [], F = src || filtered, cl = Math.cos(lat * Math.PI / 180), r2 = m * m;
  for (let k = 0; k < F.length; k++) {
    const i = F[k], dy = (D.lat[i] - lat) * mPerDegLat;
    if (dy > m || dy < -m) continue;
    const dx = (D.lon[i] - lon) * mPerDegLat * cl;
    if (dx * dx + dy * dy <= r2) out.push(i);
  }
  return out;
}
function radiusSelect(lat, lon, m, exSame) {
  let ids = nearIds(lat, lon, m);
  if (exSame) { const ex = new Set(nearIds(lat, lon, 15)); ids = ids.filter(i => !ex.has(i)); }
  const circ = L.circle([lat, lon], { radius: m, color: '#e60012', weight: 2, dashArray: '6 4', fillOpacity: .06, interactive: false }).addTo(map);
  setTimeout(() => map.removeLayer(circ), 2500);
  setSel(ids, true); openSelPanel();
  flash(`반경 ${fmt(m)}m · ${fmt(ids.length)}개 선택 → 현재 선택 ${fmt(selCount)}개`);
}
function openSelPanel() { if ($('#selpanel').classList.contains('hide')) { $('#selpanel').classList.remove('hide'); renderSelPanel(); } }

/* ==================== Drawing Tools ==================== */
let tool = 'pan', drawing = null, flashT = null;
function setTool(t) {
  tool = t;
  ['Pan', 'Rect', 'Lasso', 'Circle'].forEach(n => $('#t' + n).classList.toggle('on', t === n.toLowerCase()));
  map.getContainer().classList.toggle('tool-mode', t !== 'pan');
  const hint = $('#hint');
  if (t === 'pan') { map.dragging.enable(); hint.style.display = 'none'; }
  else {
    map.dragging.disable(); hint.style.display = 'block';
    hint.textContent = { rect: '드래그해서 사각형 영역 선택', lasso: '마우스를 누른 채 둘러서 선택', circle: '중심에서 바깥으로 드래그해 반경 선택' }[t] + ' · Alt+드래그=제외 · Esc=이동모드';
    openSelPanel();
  }
}
function flash(t) {
  const hint = $('#hint');
  hint.style.display = 'block'; hint.textContent = t;
  clearTimeout(flashT);
  flashT = setTimeout(() => { if (tool === 'pan') hint.style.display = 'none'; else setTool(tool); }, 2600);
}
function finishDraw() {
  if (!drawing) return;
  const d = drawing; drawing = null; map.removeLayer(d.shape);
  const end = d.end || d.start, ids = [];
  if (tool === 'rect') {
    const x0 = Math.min(d.start.x, end.x), x1 = Math.max(d.start.x, end.x), y0 = Math.min(d.start.y, end.y), y1 = Math.max(d.start.y, end.y);
    if (x1 - x0 < 3 && y1 - y0 < 3) return;
    for (let k = 0; k < vis.n; k++) { const x = vis.x[k], y = vis.y[k]; if (x >= x0 && x <= x1 && y >= y0 && y <= y1) ids.push(vis.idx[k]); }
  } else if (tool === 'circle') {
    const R = Math.hypot(end.x - d.start.x, end.y - d.start.y); if (R < 3) return;
    const R2 = R * R;
    for (let k = 0; k < vis.n; k++) { const dx = vis.x[k] - d.start.x, dy = vis.y[k] - d.start.y; if (dx * dx + dy * dy <= R2) ids.push(vis.idx[k]); }
  } else {
    const P = d.pts; if (P.length < 3) return;
    let x0 = 1e9, x1 = -1e9, y0 = 1e9, y1 = -1e9;
    for (const p of P) { x0 = Math.min(x0, p.x); x1 = Math.max(x1, p.x); y0 = Math.min(y0, p.y); y1 = Math.max(y1, p.y); }
    const n = P.length;
    for (let k = 0; k < vis.n; k++) {
      const x = vis.x[k], y = vis.y[k]; if (x < x0 || x > x1 || y < y0 || y > y1) continue;
      let ins = false;
      for (let a = 0, b = n - 1; a < n; b = a++) {
        const pa = P[a], pb = P[b];
        if (((pa.y > y) !== (pb.y > y)) && (x < (pb.x - pa.x) * (y - pa.y) / (pb.y - pa.y) + pa.x)) ins = !ins;
      }
      if (ins) ids.push(vis.idx[k]);
    }
  }
  setSel(ids, !d.remove);
  flash(`${d.remove ? '제외' : '선택'} ${fmt(ids.length)}개 → 현재 선택 ${fmt(selCount)}개`);
}

/* ==================== Live OpenAPI Collector & Diagnostics ==================== */
let LAST_API_LOG = '대기 중… 인증키 저장 후 [전체 API 연결 진단] 또는 수집 버튼을 눌러주세요.';
let LAST_API_DIAG = null;
let LAST_NTS_ROWS = [];

function logApi(msg, reset = false) {
  LAST_API_LOG = reset ? msg : (LAST_API_LOG + '\n' + msg);
  const el = $('#apiLog');
  if (el) { el.textContent = LAST_API_LOG; el.scrollTop = el.scrollHeight; }
}
function renderDiagBoard() {
  const board = $('#apiDiagBoard');
  if (!board) return;
  if (!LAST_API_DIAG) { board.innerHTML = ''; return; }
  const { checkedAt, keyMask, items } = LAST_API_DIAG;
  board.innerHTML = `
  <div class="diag-board">
    <div class="row2" style="justify-content:space-between">
      <strong style="font-size:12px">🩺 API 실시간 연결 진단 결과</strong>
      <span class="note">키: <code>${esc(keyMask)}</code> · ${esc(checkedAt)}</span>
    </div>
    <div class="diag-grid">
      ${items.map(it => {
        const cls = it.ok ? 'ok' : (it.status === 403 ? 'warn' : 'err');
        const icon = it.ok ? '🟢' : (it.status === 403 ? '🟡' : '🔴');
        return `<div class="diag-card ${cls}">
          <div class="dh">${icon} ${esc(it.name)}</div>
          <div style="font-weight:600">${esc(it.summary)}</div>
          <div class="note" style="margin-top:2px">${esc(it.hint)}</div>
        </div>`;
      }).join('')}
    </div>
  </div>`;
}
function getEffectiveCoord() {
  const c = map ? map.getCenter() : { lat: 37.4895, lng: 126.7235 };
  if (map && map.getZoom() < 10) return { lat: 37.4895, lon: 126.7235 };
  return { lat: Number(c.lat.toFixed(6)), lon: Number(c.lng.toFixed(6)) };
}
function getApiKeyOrWarn() {
  const raw = ($('#apiKeyIn')?.value || store.get('dataGoKey', '')).replace(/\s+/g, '');
  if (!raw) {
    toast('먼저 공공데이터포털 일반 인증키를 입력하세요');
    $('#apiKeyIn')?.focus();
    return '';
  }
  store.set('dataGoKey', raw);
  syncApiKeyUI();
  return raw;
}

async function runApiHealthCheck() {
  const rawKey = ($('#apiKeyIn')?.value || store.get('dataGoKey', '')).replace(/\s+/g, '');
  const vwKey = getVWorldKey();
  if (!rawKey && !vwKey) { toast('공공데이터포털 또는 브이월드 인증키를 먼저 입력하세요'); return; }
  if (rawKey) store.set('dataGoKey', rawKey);
  syncApiKeyUI();
  const keyEnc = normalizeDataGoKey(rawKey);
  const { lat, lon } = getEffectiveCoord();
  const board = $('#apiDiagBoard');
  if (board) board.innerHTML = '<div class="note" style="padding:8px 0">🩺 6개 공공·국토 API 연결 상태를 동시에 점검 중입니다…</div>';

  const dataGoTargets = [
    {
      name: '상가정보 반경조회',
      run: () => fetch(`https://apis.data.go.kr/B553077/api/open/sdsc2/storeListInRadius?serviceKey=${keyEnc}&pageNo=1&numOfRows=1&radius=500&cx=${lon}&cy=${lat}&type=json`),
      parse: j => ({ code: j?.header?.resultCode, msg: j?.header?.resultMsg, cnt: j?.body?.totalCount ?? (j?.body?.items?.length || 0) }),
    },
    {
      name: '상가정보 행정동조회',
      run: () => fetch(`https://apis.data.go.kr/B553077/api/open/sdsc2/storeListInDong?serviceKey=${keyEnc}&pageNo=1&numOfRows=1&divId=adongCd&key=28237510&type=json`),
      parse: j => ({ code: j?.header?.resultCode, msg: j?.header?.resultMsg, cnt: j?.body?.totalCount ?? (j?.body?.items?.length || 0) }),
    },
    {
      name: '주요 상권 영역',
      run: () => fetch(`https://apis.data.go.kr/B553077/api/open/sdsc2/storeZoneInRadius?serviceKey=${keyEnc}&radius=1500&cx=${lon}&cy=${lat}&type=json`),
      parse: j => ({ code: j?.header?.resultCode, msg: j?.header?.resultMsg, cnt: j?.body?.items?.length ?? 0 }),
    },
    {
      name: '국세청 사업자상태',
      run: () => fetch(`https://api.odcloud.kr/api/nts-businessman/v1/status?serviceKey=${keyEnc}&returnType=JSON`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ b_no: ['1248100998'] }),
      }),
      parse: j => ({ code: j?.status_code === 'OK' ? '00' : 'ERR', msg: j?.status_code || '', cnt: j?.match_cnt ?? (j?.data?.length || 0) }),
    },
  ];

  const vwChecks = [
    (async () => {
      if (!vwKey) return { name: '브이월드 지오코더', ok: false, status: 401, summary: '키 미입력', hint: '브이월드 인증키를 입력하거나 Vault 잠금 해제 상태를 확인하세요.' };
      const t0 = performance.now();
      try {
        const res = await vwReverseAddr(lat, lon);
        const ms = Math.round(performance.now() - t0);
        if (res && (res.road || res.parcel)) return { name: '브이월드 지오코더', ok: true, status: 200, summary: `정상 연결 (JSONP · ${ms}ms)`, hint: (res.road || res.parcel).slice(0, 32) };
        return { name: '브이월드 지오코더', ok: false, status: 400, summary: `응답 없음 (${ms}ms)`, hint: '좌표 또는 인증키 상태를 확인하세요.' };
      } catch (e) {
        return { name: '브이월드 지오코더', ok: false, status: 0, summary: '연결 실패', hint: e.message };
      }
    })(),
    (async () => {
      if (!vwKey) return { name: '브이월드 지적·공시지가', ok: false, status: 401, summary: '키 미입력', hint: '브이월드 인증키를 입력하세요.' };
      const t0 = performance.now();
      try {
        const land = await vwLandInfo(lat, lon);
        const ms = Math.round(performance.now() - t0);
        const p = land?.parcel?.properties;
        const zn = land?.zoning?.[0] || '';
        if (p || zn) return { name: '브이월드 지적·공시지가', ok: true, status: 200, summary: `정상 연결 (JSONP · ${ms}ms)`, hint: `${zn || '필지 확인'}${p?.jiga ? ` · ${fmt(Number(p.jiga))}원/㎡` : ''}` };
        return { name: '브이월드 지적·공시지가', ok: true, status: 200, summary: `정상 연결 (${ms}ms)`, hint: '현재 중심 좌표에 필지 없음(해상/도로)' };
      } catch (e) {
        return { name: '브이월드 지적·공시지가', ok: false, status: 0, summary: '연결 실패', hint: e.message };
      }
    })(),
  ];

  const dataGoChecks = dataGoTargets.map(async t => {
    if (!rawKey) return { name: t.name, ok: false, status: 403, summary: '공공데이터 키 미입력', hint: '상단 공공데이터포털 일반 인증키를 입력하면 점검됩니다.' };
    const t0 = performance.now();
    try {
      const r = await t.run();
      const ms = Math.round(performance.now() - t0);
      const txt = await r.text();
      if (r.ok) {
        try {
          const j = JSON.parse(txt);
          const p = t.parse(j);
          if (p.code === '00' || p.code === '03' || !p.code) {
            return { name: t.name, ok: true, status: 200, summary: `정상 연결 (HTTP 200 · ${ms}ms)`, hint: p.code === '03' ? '정상 응답 (현재 좌표 결과 0건)' : `조회 가능 ${fmt(Number(p.cnt || 0))}건` };
          }
          return { name: t.name, ok: false, status: 400, summary: `API 오류 (${p.code} · ${ms}ms)`, hint: p.msg || '응답 코드를 확인하세요.' };
        } catch {
          const isAuthErr = /SERVICE_KEY_IS_NOT_REGISTERED|UNREGISTERED|KEY/i.test(txt);
          return {
            name: t.name, ok: false, status: isAuthErr ? 401 : 403,
            summary: isAuthErr ? `인증키 미등록 (${ms}ms)` : `XML/비정상 응답 (${ms}ms)`,
            hint: isAuthErr ? '공공데이터포털 일반 인증키를 다시 확인하세요.' : 'data.go.kr에서 해당 서비스 활용신청 승인 여부를 확인하세요.',
          };
        }
      }
      if (r.status === 401) return { name: t.name, ok: false, status: 401, summary: `인증키 오류 (HTTP 401 · ${ms}ms)`, hint: '입력창 키를 지우고 일반 인증키를 다시 붙여넣으세요.' };
      if (r.status === 403) return { name: t.name, ok: false, status: 403, summary: `활용신청 미승인 (HTTP 403 · ${ms}ms)`, hint: 'data.go.kr에서 해당 API 활용신청 승인 후 바로 열립니다.' };
      return { name: t.name, ok: false, status: r.status, summary: `응답 오류 (HTTP ${r.status} · ${ms}ms)`, hint: txt.slice(0, 60).replace(/\s+/g, ' ') };
    } catch {
      return { name: t.name, ok: false, status: 0, summary: '네트워크 / CORS 오류', hint: '브라우저 CORS 차단 시 하단 Node 수집기(fetch_sbiz_api.mjs)를 사용하세요.' };
    }
  });

  const items = await Promise.all([...vwChecks, ...dataGoChecks]);
  const okCnt = items.filter(x => x.ok).length;
  const nowStr = new Date().toTimeString().slice(0, 8);
  LAST_API_DIAG = { checkedAt: nowStr, keyMask: rawKey ? maskKeyPreview(rawKey) : `VW:${maskKeyPreview(vwKey)}`, items };
  renderDiagBoard();
  logApi(`[진단 완료 ${nowStr}] 6개 중 ${okCnt}개 API 정상 연결 (${items.map(x => `${x.name}:${x.ok ? 'OK' : x.status}`).join(', ')})`, true);
  toast(`API 진단 완료: ${okCnt}/6 정상 연결`);
}

function ingestSdscItems(items, sourceLabel, saveToIdb = true) {
  const dicts = {}, maps = {}, codes = {}, codeMaps = {};
  for (const f of CAT) { dicts[f] = []; maps[f] = new Map(); codes[f] = []; }
  for (const f of CODE_FIELDS) codeMaps[f] = [];
  const bldMap = new Map(), bldId = [];
  const lat = [], lon = [], strs = [], keptRaw = [];
  const JB_RE = /(\S+)\s+(산\s*\d+(?:-\d+)?|\d+(?:-\d+)?)\s*$/;
  const code = (f, k, cd) => {
    const m = maps[f]; let c = m.get(k);
    if (c === undefined) { c = dicts[f].length; dicts[f].push(k); m.set(k, c); if (codeMaps[f]) codeMaps[f].push(cd || ''); }
    else if (cd && codeMaps[f] && !codeMaps[f][c]) codeMaps[f][c] = cd;
    codes[f].push(c);
  };
  let dup = 0;
  for (const it of items) {
    const id = String(it.bizesId || '').trim();
    if (id && D.idSet.has(id)) { dup++; continue; }
    const x = parseFloat(it.lon), y = parseFloat(it.lat);
    if (!(x > 124 && x < 132 && y > 33 && y < 39.5)) continue;
    lat.push(y); lon.push(x);
    const sido = String(it.ctprvnNm || '(미상)').trim();
    const sggRaw = String(it.signguNm || '(미상)').trim();
    const sgg = sido + ' ' + sggRaw;
    const l1 = String(it.indsLclsNm || '(미상)').trim();
    const l2 = l1 + '>' + String(it.indsMclsNm || '(미상)').trim();
    code('l1', l1, it.indsLclsCd);
    code('l2', l2, it.indsMclsCd);
    code('l3', l2 + '>' + String(it.indsSclsNm || '(미상)').trim(), it.indsSclsCd);
    code('ksic', String(it.ksicNm || '').trim(), it.ksicCd);
    code('sido', sido, it.ctprvnCd);
    code('sgg', sgg, it.signguCd);
    code('dong', sgg + ' ' + String(it.adongNm || '(미상)').trim(), it.adongCd);
    code('bdong', sgg + ' ' + String(it.ldongNm || '(미상)').trim(), it.ldongCd);
    code('floor', String(it.flrNo || '(미상)').trim());
    code('roadNm', sgg + '>' + shortRoadName(it.rdnm, sido, sggRaw));
    code('zip', String(it.newZipcd || '(미상)').trim());
    const bm = String(it.bldMngNo || '').trim();
    if (bm) { let bid = bldMap.get(bm); if (bid === undefined) { bid = bldMap.size + 1; bldMap.set(bm, bid); } bldId.push(bid); }
    else bldId.push(0);
    const jm = String(it.lnoAdr || '').match(JB_RE);
    const jb = jm ? jm[1] + ' ' + jm[2].replace(/\s+/g, '') : '';
    strs.push([id, String(it.bizesNm || '').trim(), String(it.brchNm || '').trim(), String(it.rdnmAdr || '').trim(), String(it.bldNm || '').trim(), String(it.hoNo || '').trim(), jb].join('\x1f'));
    if (id) D.idSet.add(id);
    keptRaw.push(it);
  }
  const n = lat.length;
  if (n > 0) {
    const codeArr = {};
    for (const f of CAT) codeArr[f] = Uint32Array.from(codes[f]);
    parts.push({ n, dicts, codeMaps, codes: codeArr, bldId: Uint32Array.from(bldId), strs, lat: Float64Array.from(lat), lon: Float64Array.from(lon), isApi: true });
    finalize();
    const fid = ++fidSeq;
    D.files.set(fid, { fid, name: sourceLabel, size: 0, status: 'done', loaded: 1, n, enc: 'api' });
    renderFiles();
    afterLoad(false);
    if (saveToIdb) {
      idb.get('live_api_stores').then(prev => {
        const mapById = new Map((prev || []).map(x => [x.bizesId || Math.random(), x]));
        keptRaw.forEach(x => mapById.set(x.bizesId || Math.random(), x));
        idb.set('live_api_stores', [...mapById.values()].slice(-20000));
      });
    }
  }
  return { added: n, dup };
}

async function fetchSdscStores(mode) {
  const rawKey = getApiKeyOrWarn();
  if (!rawKey) return;
  const keyEnc = normalizeDataGoKey(rawKey);
  const maxRows = Number($('#apiMaxRows').value || 1000);
  const pages = Math.max(1, Math.ceil(maxRows / 1000));
  const perPage = Math.min(1000, maxRows);
  const l1Code = $('#apiL1').value || (sel.l1.size === 1 ? (D.codeMaps.l1[[...sel.l1][0]] || '') : '');
  const l1Param = l1Code ? `&indsLclsCd=${encodeURIComponent(l1Code)}` : '';

  let baseUrl = '', lbl = '', circlePreview = null;
  if (mode === 'radius') {
    const { lat, lon } = getEffectiveCoord();
    const rad = Number($('#apiRadius').value || 500);
    baseUrl = `https://apis.data.go.kr/B553077/api/open/sdsc2/storeListInRadius?serviceKey=${keyEnc}&radius=${rad}&cx=${lon}&cy=${lat}${l1Param}&type=json`;
    lbl = `API 반경 ${rad}m (${lat.toFixed(4)},${lon.toFixed(4)})`;
    circlePreview = L.circle([lat, lon], { radius: rad, color: '#2563eb', weight: 2, dashArray: '6 4', fillOpacity: .06, interactive: false }).addTo(map);
    if (map.getZoom() < 14) map.setView([lat, lon], 15);
  } else if (mode === 'dong') {
    let adongCd = '', dongNm = '';
    if (sel.dong.size) {
      const c = [...sel.dong][0];
      adongCd = D.codeMaps.dong[c] || '';
      dongNm = label('dong', c);
    } else if (D.N) {
      const { lat, lon } = getEffectiveCoord();
      const near = nearIds(lat, lon, 3000, null);
      if (near.length) {
        const dc = D.codes.dong[near[0]];
        adongCd = D.codeMaps.dong[dc] || '';
        dongNm = label('dong', dc);
      }
    }
    if (!adongCd) {
      toast('필터에서 행정동을 선택하거나 시도 데이터를 먼저 로드해 주세요 (행정동코드 자동 연동)');
      return;
    }
    baseUrl = `https://apis.data.go.kr/B553077/api/open/sdsc2/storeListInDong?serviceKey=${keyEnc}&divId=adongCd&key=${encodeURIComponent(adongCd)}${l1Param}&type=json`;
    lbl = `API 행정동 ${dongNm}(${adongCd})`;
  } else {
    if (map.getZoom() < 13) {
      toast('화면 영역 수집은 지도를 동/구 단위(줌 13 이상)로 확대한 뒤 실행하세요');
      return;
    }
    const b = map.getBounds();
    baseUrl = `https://apis.data.go.kr/B553077/api/open/sdsc2/storeListInRectangle?serviceKey=${keyEnc}&minx=${b.getWest().toFixed(6)}&miny=${b.getSouth().toFixed(6)}&maxx=${b.getEast().toFixed(6)}&maxy=${b.getNorth().toFixed(6)}${l1Param}&type=json`;
    lbl = `API 화면영역 (${b.getCenter().lat.toFixed(4)},${b.getCenter().lng.toFixed(4)})`;
  }

  logApi(`[시작] ${lbl} 실시간 수집 중…`, true);
  showBusy(`🔌 ${lbl} 호출 중…`, 0.15);
  const all = [];
  try {
    for (let p = 1; p <= pages; p++) {
      showBusy(`🔌 ${lbl} (${p}/${pages} 페이지)…`, p / (pages + 1));
      const r = await fetch(`${baseUrl}&pageNo=${p}&numOfRows=${perPage}`);
      const txt = await r.text();
      if (!r.ok) { logApi(`⚠ HTTP ${r.status}: 인증키 또는 활용신청 승인 상태를 확인하세요.`); break; }
      let j;
      try { j = JSON.parse(txt); } catch { logApi(`⚠ JSON 파싱 실패 (XML 오류 응답): ${txt.slice(0, 120).replace(/\s+/g, ' ')}`); break; }
      const code = j?.header?.resultCode;
      if (code && code !== '00' && code !== '03') { logApi(`⚠ API 오류 [${code}]: ${j?.header?.resultMsg || ''}`); break; }
      const items = j?.body?.items || [];
      const total = Number(j?.body?.totalCount || items.length);
      all.push(...items);
      logApi(`✓ ${p}페이지: ${fmt(items.length)}건 수신 (전체 ${fmt(total)}건 중 누적 ${fmt(all.length)}건)`);
      if (items.length < perPage || all.length >= total) break;
    }
    if (all.length) {
      const { added, dup } = ingestSdscItems(all, lbl, true);
      logApi(`✅ 지도 병합 완료! 신규 추가 ${fmt(added)}건${dup ? ` (기존 중복 ${fmt(dup)}건 제외)` : ''}`);
      toast(`실시간 API ${fmt(added)}건 지도에 반영`);
    } else {
      logApi('→ 해당 영역에 조회된 상가가 없습니다.');
    }
  } catch (err) {
    logApi(`⚠ 네트워크/CORS 오류: ${err.message}\n→ 브라우저 CORS 차단 시 하단 Node 수집기(scripts/fetch_sbiz_api.mjs)를 이용하세요.`);
  } finally {
    hideBusy();
    if (circlePreview) setTimeout(() => map.removeLayer(circlePreview), 3500);
  }
}

async function fetchCommercialZones() {
  const rawKey = getApiKeyOrWarn();
  if (!rawKey) return;
  const keyEnc = normalizeDataGoKey(rawKey);
  const { lat, lon } = getEffectiveCoord();
  const rad = Math.max(1000, Number($('#apiRadius').value || 1000));
  logApi(`[시작] 주요 상권 영역 조회 (반경 ${rad}m)…`, true);
  try {
    const r = await fetch(`https://apis.data.go.kr/B553077/api/open/sdsc2/storeZoneInRadius?serviceKey=${keyEnc}&radius=${rad}&cx=${lon}&cy=${lat}&type=json`);
    const txt = await r.text();
    if (!r.ok) { logApi(`⚠ 상권 조회 HTTP ${r.status}`); return; }
    const j = JSON.parse(txt);
    const items = j?.body?.items || [];
    zoneLayer.clearLayers();
    let drawn = 0;
    for (const z of items) {
      const wkt = String(z.coords || '');
      const polyPts = [];
      for (const m of wkt.matchAll(/(\d+\.\d+)\s+(\d+\.\d+)/g)) {
        const x = parseFloat(m[1]), y = parseFloat(m[2]);
        if (x > 124 && x < 132 && y > 33 && y < 39.5) polyPts.push([y, x]);
      }
      if (polyPts.length >= 3) {
        const poly = L.polygon(polyPts, { color: '#7c3aed', weight: 2, fillColor: '#8b5cf6', fillOpacity: 0.16 });
        const center = poly.getBounds().getCenter();
        poly.bindPopup(`<div class="pp-h">🗺 ${esc(z.mainTrarNm || z.trarNm || '주요 상권')}</div>
          <div class="b">${esc(z.ctprvnNm || '')} ${esc(z.signguNm || '')}</div>
          <div class="c">상권번호: ${esc(z.trarNo || '-')} · 면적: ${z.trarArea ? fmt(Number(z.trarArea)) + '㎡' : '-'}</div>
          <div class="pbtn"><button data-rad="${center.lat},${center.lng},300,0">중심 300m 선택</button><button data-rad="${center.lat},${center.lng},500,0">500m 선택</button></div>`);
        poly.bindTooltip(esc(z.mainTrarNm || z.trarNm || '상권'), { sticky: true });
        zoneLayer.addLayer(poly);
        drawn++;
      }
    }
    if (drawn && zoneLayer.getBounds().isValid()) map.fitBounds(zoneLayer.getBounds(), { padding: [40, 40], maxZoom: 15 });
    logApi(`✅ 주요 상권 ${drawn}개 영역을 지도에 표시했습니다.`);
    toast(`주요 상권 ${drawn}개 표시`);
  } catch (err) {
    logApi(`⚠ 상권 조회 실패: ${err.message}`);
  }
}

/* ==================== NTS Business Status Live Lookup ==================== */
async function queryNtsStatus(bizNos) {
  const rawKey = getApiKeyOrWarn();
  if (!rawKey) return null;
  const keyEnc = normalizeDataGoKey(rawKey);
  const clean = [...new Set(bizNos.map(s => String(s || '').replace(/\D/g, '')).filter(s => s.length === 10))];
  if (!clean.length) { toast('유효한 10자리 사업자번호가 없습니다'); return null; }

  const out = [];
  for (let i = 0; i < clean.length; i += 100) {
    const chunk = clean.slice(i, i + 100);
    const r = await fetch(`https://api.odcloud.kr/api/nts-businessman/v1/status?serviceKey=${keyEnc}&returnType=JSON`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ b_no: chunk }),
    });
    if (!r.ok) throw new Error(`국세청 API HTTP ${r.status}`);
    const j = await r.json();
    if (Array.isArray(j.data)) out.push(...j.data);
  }
  return out;
}
async function runNtsLookupPanel() {
  const raw = $('#ntsInput').value || '';
  const nums = raw.split(/[\n,;\s]+/).map(s => s.trim()).filter(Boolean);
  if (!nums.length) { toast('사업자등록번호를 입력하세요'); $('#ntsInput').focus(); return; }
  $('#ntsResult').innerHTML = '<div class="note">국세청 API 실시간 조회 중…</div>';
  try {
    const rows = await queryNtsStatus(nums);
    if (!rows) { $('#ntsResult').innerHTML = ''; return; }
    LAST_NTS_ROWS = rows;
    $('#btnNtsCsv').disabled = !rows.length;
    const stCls = cd => cd === '01' ? 'bn' : cd === '02' ? 'bw' : 'bc';
    $('#ntsResult').innerHTML = `<table class="cmptbl">
      <tr><th>사업자번호</th><th>상태</th><th>과세유형 / 폐업일</th></tr>
      ${rows.map(x => `<tr>
        <td><code>${esc(x.b_no)}</code></td>
        <td><span class="bdg ${stCls(x.b_stt_cd)}">${esc(x.b_stt || '미등록')}</span></td>
        <td style="text-align:left">${esc(x.tax_type || '-')}${x.end_dt ? ` (폐업 ${esc(x.end_dt)})` : ''}</td>
      </tr>`).join('')}
    </table>`;
    toast(`국세청 사업자상태 ${rows.length}건 조회 완료`);
  } catch (err) {
    $('#ntsResult').innerHTML = `<div class="note" style="color:var(--err)">조회 실패: ${esc(err.message)}</div>`;
  }
}

/* ==================== Gemini AI Commercial Analysis & NL Filter ==================== */
function openAiModal(title, text) {
  $('#aiModalTitle').textContent = title;
  $('#aiModalBody').textContent = text;
  $('#aiModal').classList.add('on');
  $('#aiModal').setAttribute('aria-hidden', 'false');
  updateScrim();
}
async function callGemini(prompt) {
  const key = store.get('geminiKey', '').replace(/\s+/g, '');
  if (!key) {
    toast('설정(⚙️)에서 Gemini API 키를 먼저 입력하세요');
    openSettings(true);
    return null;
  }
  const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${encodeURIComponent(key)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
  });
  if (!r.ok) throw new Error(`Gemini HTTP ${r.status}`);
  const j = await r.json();
  return j?.candidates?.[0]?.content?.parts?.[0]?.text || '응답 없음';
}

async function runAiCommercialAnalysis(useSelectedOnly) {
  if (!D.N) { toast('먼저 시도 데이터를 복호화하거나 API/ZIP 데이터를 불러오세요'); return; }
  const ids = (useSelectedOnly && selCount) ? selIndices() : (selCount ? selIndices() : inViewIds());
  if (!ids.length) { toast('분석할 업소가 화면 또는 선택 목록에 없습니다'); return; }
  const scopeLabel = (useSelectedOnly || selCount) ? `선택 업소 ${fmt(ids.length)}건` : `현재 화면 상권 ${fmt(ids.length)}건`;

  const topOf = (f, k) => {
    const m = new Map(), C = D.codes;
    for (const i of ids) { const c = C[f][i]; if (label(f, c) === '(미상)') continue; m.set(c, (m.get(c) || 0) + 1); }
    return [...m].sort((a, b) => b[1] - a[1]).slice(0, k).map(([c, v]) => {
      const lb = f === 'sgg' ? sggFull(c) : label(f, c);
      const cd = f === 'ksic' && D.codeMaps.ksic[c] ? `[${D.codeMaps.ksic[c]}]` : '';
      return `${cd}${lb}:${v}건`;
    });
  };
  let franN = 0, new6N = 0, bigBldN = 0;
  const cut6 = ymSubMonths(D.maxYM, 6);
  for (const i of ids) {
    if (D.isFran[i]) franN++;
    if (D.regYM[i] >= cut6) new6N++;
    if (D.bldId[i] && D.bldCnt[D.bldId[i]] >= 10) bigBldN++;
  }
  let cmpInfo = '';
  if (CMP.on) {
    const st = [0, 0, 0, 0];
    for (const i of ids) st[D.codes.st[i]]++;
    cmpInfo = `개폐업(${CMP.baseYM}→${CMP.curYM}): 유지 ${st[0]}건, 신규 ${st[1]}건, 폐업 ${st[2]}건`;
  }
  const summaryPayload = {
    범위: scopeLabel,
    개인점포비율: `${((1 - franN / ids.length) * 100).toFixed(1)}% (프랜차이즈 ${franN}건)`,
    최근6개월신규등재: `${new6N}건 (${(new6N / ids.length * 100).toFixed(1)}%)`,
    대형복합상가입점: `${bigBldN}건 (10개 이상 입점 건물)`,
    대분류TOP6: topOf('l1', 6),
    중분류TOP8: topOf('l2', 8),
    KSIC표준산업TOP5: topOf('ksic', 5),
    핵심가로상권TOP5: topOf('roadNm', 5),
    주요행정동: topOf('dong', 6),
    개폐업: cmpInfo || '미비교',
    샘플상호: ids.slice(0, 12).map(i => `${S(i).name}(${label('l3', D.codes.l3[i])})`),
  };

  openAiModal(`✨ Gemini AI 상권 분석 · ${scopeLabel}`, 'Gemini AI가 상권·건물집적·신규등재·프랜차이즈 데이터를 분석하고 있습니다…');
  try {
    const prompt = `당신은 대한민국 상권 분석 및 소상공인 B2B 영업 전략 전문가입니다. 아래 상권 집계 데이터만 근거로 한국어로 간결하고 실전적인 브리핑을 작성하세요:
1) 상권 핵심 성격·가로상권(도로명) 및 대형복합상가 집적도 진단
2) 개인 점포 vs 프랜차이즈 구성과 최근 6개월 신규 개업 활력도 해석
3) 과밀(레드오션) 업종 vs 틈새 유망 업종
4) B2B 영업(보안/CCTV, 통신, 결제/POS, 마케팅 등) 우선 타깃 업종과 접근 멘트
5) 즉시 실행할 현장 영업 액션 2가지

데이터: ${JSON.stringify(summaryPayload)}`;
    const txt = await callGemini(prompt);
    if (txt) $('#aiModalBody').textContent = txt;
  } catch (err) {
    $('#aiModalBody').textContent = `AI 분석 오류: ${err.message}`;
  }
}

async function runAiNaturalFilter() {
  if (!D.N) { toast('먼저 데이터를 불러와 주세요'); return; }
  const q = $('#kw').value.trim();
  if (!q) { toast('검색창에 조건을 자연어로 입력하세요 (예: 인천 부평구 개인 카페 2026년 신규 대형상가)'); $('#kw').focus(); return; }
  toast('✨ Gemini AI가 조건을 분석 중…');
  try {
    const prompt = `사용자 검색 문장을 상권 필터 JSON으로만 변환하세요. 마크다운 없이 JSON 객체 하나만 출력하세요.
키: {"sido":"","sgg":"","dong":"","roadNm":"","zip":"","l1":"","l2":"","l3":"","floor":"","regym":"all|3m|6m|1y|2026|old","fran":"all|ind|fran","bld":"all|1-2|3-9|10|30|100","kw":""}
가능한 대분류: ${D.dict.l1.join(', ')}
사용자 문장: "${q}"`;
    const raw = await callGemini(prompt);
    if (!raw) return;
    const m = raw.match(/\{[\s\S]*\}/);
    if (!m) throw new Error('JSON 파싱 불가');
    const obj = JSON.parse(m[0]);
    for (const f in sel) sel[f].clear();
    const matchDict = (f, val) => {
      if (!val) return;
      const v = String(val).trim().toLowerCase();
      for (let c = 0; c < D.dict[f].length; c++) {
        if (label(f, c).toLowerCase().includes(v) || D.dict[f][c].toLowerCase().includes(v)) sel[f].add(c);
      }
    };
    matchDict('sido', obj.sido); matchDict('sgg', obj.sgg); matchDict('dong', obj.dong);
    matchDict('roadNm', obj.roadNm); matchDict('zip', obj.zip);
    matchDict('l1', obj.l1); matchDict('l2', obj.l2); matchDict('l3', obj.l3); matchDict('floor', obj.floor);
    regYmFilter = ['all', '3m', '6m', '1y', '2026', 'old'].includes(obj.regym) ? obj.regym : 'all';
    franFilter = ['all', 'ind', 'fran'].includes(obj.fran) ? obj.fran : 'all';
    bldFilter = ['all', '1-2', '3-9', '10', '30', '100'].includes(obj.bld) ? obj.bld : 'all';
    prune();
    const kwStr = String(obj.kw || '').trim();
    $('#kw').value = kwStr;
    kwTerms = kwStr ? kwStr.toLowerCase().split(',').map(g => g.trim().split(/\s+/).filter(Boolean)).filter(g => g.length) : [];
    applyFilter(); renderFilterUI();
    if (filtered.length) fitTo(filtered);
    toast(`✨ AI 필터 적용 완료 · ${fmt(filtered.length)}건`);
  } catch (err) {
    toast(`AI 필터 변환 실패: ${err.message}`);
  }
}

/* ==================== Search, Geocoding, Customers, Comparison ==================== */
let gpin = null;
function dropPin(lat, lon, zoom, title) {
  if (gpin) map.removeLayer(gpin);
  gpin = L.marker([lat, lon], { icon: L.divIcon({ className: '', html: '<div class="gpin"></div>', iconSize: [22, 22], iconAnchor: [11, 24] }), title: title || '' }).addTo(map);
  map.setView([lat, lon], zoom || 17);
}
function gsearch() {
  const q = $('#gq').value.trim(), box = $('#gres');
  if (!q) { box.style.display = 'none'; return; }
  let h = ''; const qn = q.replace(/\s+/g, '');
  if (D.N) {
    const ce = getCentroids(), regs = [];
    for (const f of ['sgg', 'dong', 'bdong']) for (let c = 0; c < D.dict[f].length; c++) { const k = D.dict[f][c]; if (k.replace(/\s+/g, '').indexOf(qn) >= 0 && ce[f].c[c]) regs.push([f, c, k]); }
    regs.sort((a, b) => a[2].length - b[2].length);
    if (regs.length) h += `<div class="gh">지역</div>` + regs.slice(0, 8).map(([f, c, k]) => `<div class="gi" data-ll="${ce[f].y[c]},${ce[f].x[c]},${f === 'sgg' ? 13 : 15}" data-t="${esc(k)}">${esc(k)}<small>${f === 'sgg' ? '시군구' : f === 'dong' ? '행정동' : '법정동'} · 업소 ${fmt(D.cnt[f][c])}개</small></div>`).join('');
    const addrs = new Map(), names = []; const ql = q.toLowerCase();
    for (let i = 0; i < D.N && (addrs.size < 12 || names.length < 12); i++) {
      const s = D.strs[i]; if (s.toLowerCase().indexOf(ql) < 0) continue;
      const o = S(i);
      if ((o.road + ' ' + o.bld + ' ' + o.jb).toLowerCase().indexOf(ql) >= 0) { const key = o.addr; const a = addrs.get(key); if (a) a.n++; else if (addrs.size < 12) addrs.set(key, { i, n: 1, bld: o.bld }); }
      else if (o.name.toLowerCase().indexOf(ql) >= 0 && names.length < 12) names.push(i);
    }
    if (addrs.size) h += `<div class="gh">주소 · 건물</div>` + [...addrs].map(([k, v]) => `<div class="gi" data-ll="${D.lat[v.i]},${D.lon[v.i]},18" data-t="${esc(k)}" data-open="${v.i}">${esc(k)}${v.bld ? ' · ' + esc(v.bld) : ''}<small>업소 ${v.n}${v.n >= 12 ? '+' : ''}개</small></div>`).join('');
    if (names.length) h += `<div class="gh">상호</div>` + names.map(i => { const o = S(i); return `<div class="gi" data-ll="${D.lat[i]},${D.lon[i]},18" data-open="${i}">${esc(o.name)} ${esc(o.branch)}<small>${esc(label('l3', D.codes.l3[i]))} · ${esc(o.addr)}</small></div>`; }).join('');
  }
  if (getVWorldKey()) {
    h += `<div class="gh">브이월드 디지털트윈국토</div><div class="gi" data-vw="1">🇰🇷 "${esc(q)}" 브이월드 장소·도로명주소 검색<small>국토교통부 공식 POI · 정밀 주소 검색</small></div>`;
  }
  h += `<div class="gh">인터넷 검색</div><div class="gi" data-osm="1">🌐 "${esc(q)}" OpenStreetMap에서 찾기<small>해외/보조 검색</small></div>`;
  box.innerHTML = h; box.style.display = 'block';
}
async function osmSearch(q, limit) {
  const r = await fetch(`https://nominatim.openstreetmap.org/search?format=json&countrycodes=kr&accept-language=ko&limit=${limit || 1}&q=${encodeURIComponent(q)}`);
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

const cust = { wb: null, rows: [], head: [], list: [], show: true, layer: null, renderer: null, cols: {} };
async function readCust(f) {
  try {
    showBusy('고객 파일 읽는 중…', .3);
    const buf = await f.arrayBuffer(); let wb;
    if (/\.csv$/i.test(f.name)) {
      let t; try { t = new TextDecoder('utf-8', { fatal: true }).decode(buf); } catch { t = new TextDecoder('euc-kr').decode(buf); }
      wb = XLSX.read(t.replace(/^\uFEFF/, ''), { type: 'string', raw: true });
    } else wb = XLSX.read(buf, { type: 'array', cellDates: true });
    cust.wb = wb; cust.fname = f.name;
    $('#cSheet').innerHTML = wb.SheetNames.map(n => `<option>${esc(n)}</option>`).join('');
    $('#cSheet').onchange = () => loadSheet($('#cSheet').value);
    let best = wb.SheetNames[0], bn = 0;
    for (const n of wb.SheetNames) { const r = XLSX.utils.sheet_to_json(wb.Sheets[n], { header: 1, blankrows: false }); if (r.length > bn) { bn = r.length; best = n; } }
    $('#cSheet').value = best; loadSheet(best);
    $('#cmap').style.display = 'block'; $('#cdrop').querySelector('b').textContent = f.name;
  } catch (err) { alert('파일을 읽을 수 없습니다: ' + (err.message || err)); }
  finally { hideBusy(); }
}
function loadSheet(n) {
  const rows = XLSX.utils.sheet_to_json(cust.wb.Sheets[n], { header: 1, blankrows: false, defval: '', raw: false });
  let hi = 0;
  for (let r = 0; r < Math.min(15, rows.length); r++) {
    const t = rows[r].join('|');
    if (/주소|소재지|설치|상호|고객|업체|사업자|위도|경도/.test(t) && rows[r].filter(v => String(v).trim()).length >= 2) { hi = r; break; }
  }
  cust.head = (rows[hi] || []).map((h, i) => String(h).trim() || `열${i + 1}`);
  cust.rows = rows.slice(hi + 1).filter(r => r.some(v => String(v).trim()));
  const opts = none => (none ? '<option value="-1">(없음)</option>' : '') + cust.head.map((h, i) => `<option value="${i}">${esc(h)}</option>`).join('');
  $('#cAddr').innerHTML = opts(false); $('#cName').innerHTML = opts(true); $('#cBiz').innerHTML = opts(true);
  $('#cLat').innerHTML = opts(true); $('#cLon').innerHTML = opts(true);
  const find = res => { for (const re of res) { const i = cust.head.findIndex(h => re.test(h)); if (i >= 0) return i; } return -1; };
  let ai = find([/도로명.*주소/, /설치.*주소/, /^주소$/, /주소/, /소재지/, /위치/]); if (ai < 0) ai = 0;
  $('#cAddr').value = ai;
  $('#cName').value = find([/상호/, /고객명/, /업체명/, /시설명/, /사업장명/, /가입자/, /명$/]);
  $('#cBiz').value = find([/사업자/, /b_no/i]);
  $('#cLat').value = find([/위도/, /^lat/i, /^y$/i]);
  $('#cLon').value = find([/경도/, /^lo?ng?/i, /^x$/i]);
  $('#cPreview').innerHTML = `${fmt(cust.rows.length)}행 · 예) ${esc(String((cust.rows[0] || [])[ai] || ''))}`;
  $('#cAddr').onchange = () => { $('#cPreview').innerHTML = `${fmt(cust.rows.length)}행 · 예) ${esc(String((cust.rows[0] || [])[+$('#cAddr').value] || ''))}`; };
}
const SIDO_RE = /^(서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충북|충남|전북|전남|경북|경남|제주|충청|전라|경상)/;
function parseAddr(raw) {
  let a = String(raw || '').replace(/\(.*?\)/g, ' ').replace(/,.*$/, ' ').replace(/\s+/g, ' ').trim();
  const out = { sgg: '', rk: '', jk: '', dong: '', clean: a };
  const rm = a.match(/([가-힣A-Za-z0-9·.]*[가-힣](?:로|길))\s*(?:지하\s*)?(\d+)(?:\s*-\s*(\d+))?(?![\d가])/);
  const jm = a.match(/([가-힣][가-힣0-9]*(?:동|리|가))\s*(산\s*)?(\d+)(?:\s*-\s*(\d+))?(?![\d층호])/);
  const cut = Math.min(rm ? rm.index : 1e9, jm ? jm.index : 1e9);
  const toks = a.slice(0, cut === 1e9 ? a.length : cut).split(' ').filter(Boolean);
  for (let i = toks.length - 1; i >= 0; i--) {
    const t = toks[i];
    if (/[시군구]$/.test(t) && !(i === 0 && SIDO_RE.test(t) && /(특별시|광역시|자치시)$/.test(t)) && !/^(서울|부산|대구|인천|광주|대전|울산|세종)(시)?$/.test(t)) { out.sgg = t; break; }
  }
  if (rm) out.rk = rm[1] + '|' + rm[2] + (rm[3] && rm[3] !== '0' ? '-' + rm[3] : '');
  if (jm) { out.dong = jm[1]; out.jk = jm[1] + '|' + (jm[2] ? '산' : '') + jm[3] + (jm[4] && jm[4] !== '0' ? '-' + jm[4] : ''); }
  else { const dm = a.match(/([가-힣][가-힣0-9]*(?:동|읍|면|리|가))(?=\s|$)/g); if (dm) out.dong = dm[dm.length - 1]; }
  return out;
}
function sggLast(c) { const l = label('sgg', c); return l.slice(l.lastIndexOf(' ') + 1); }
async function geocode() {
  if (!D.N && !(+$('#cLat').value >= 0)) return alert('먼저 시도 데이터를 불러와 주세요. (좌표 열이 있는 파일은 바로 표시 가능)');
  const ai = +$('#cAddr').value, ni = +$('#cName').value, bi = +$('#cBiz').value, yi = +$('#cLat').value, xi = +$('#cLon').value;
  showBusy('주소 분석 중…', .05); await new Promise(r => setTimeout(r, 20));
  const list = cust.rows.map((r, k) => {
    const addr = String(r[ai] || '').trim(); let lat = null, lon = null, method = '';
    if (yi >= 0 && xi >= 0) {
      let y = parseFloat(String(r[yi]).replace(/,/g, '')), x = parseFloat(String(r[xi]).replace(/,/g, ''));
      if (y > 124 && x < 40) { const t = y; y = x; x = t; }
      if (y > 33 && y < 39.5 && x > 124 && x < 132) { lat = y; lon = x; method = '좌표'; }
    }
    const biz = bi >= 0 ? String(r[bi] || '').replace(/\D/g, '') : '';
    return { k, row: r, addr, name: ni >= 0 ? String(r[ni] || '').trim() : '', biz, nts: '', p: parseAddr(addr), lat, lon, method };
  });
  const need = list.filter(c => !c.method);
  const NK = { r1: new Set(), j1: new Set(), r2: new Set(), j2: new Set() };
  for (const c of need) { const p = c.p; if (p.rk) { NK.r2.add(p.rk); if (p.sgg) NK.r1.add(p.sgg + '|' + p.rk); } if (p.jk) { NK.j2.add(p.jk); if (p.sgg) NK.j1.add(p.sgg + '|' + p.jk); } }
  const acc = new Map(); const add = (key, i, sg) => { let a = acc.get(key); if (!a) { a = { y: 0, x: 0, n: 0, i, sg, multi: false }; acc.set(key, a); } a.y += D.lat[i]; a.x += D.lon[i]; a.n++; if (a.sg !== sg) a.multi = true; };
  const RR = /([가-힣A-Za-z0-9·.]*[가-힣](?:로|길))\s*(?:지하\s*)?(\d+)(?:-(\d+))?\s*$/;
  const sgL = D.dict.sgg.map((_, c) => sggLast(c));
  if (need.length && D.N) {
    for (let i = 0; i < D.N; i++) {
      if ((i & 262143) === 0) { showBusy(`상가 주소와 대조 중… ${fmt(i)}/${fmt(D.N)}`, i / D.N); await new Promise(r => setTimeout(r, 0)); }
      const s = D.strs[i], a = s.split('\x1f'), sc = D.codes.sgg[i], sg = sgL[sc];
      if (a[3]) { const m = a[3].match(RR); if (m) { const rk = m[1] + '|' + m[2] + (m[3] && m[3] !== '0' ? '-' + m[3] : ''); if (NK.r1.has(sg + '|' + rk)) add('r1|' + sg + '|' + rk, i, sc); if (NK.r2.has(rk)) add('r2|' + rk, i, sc); } }
      if (a[6]) { const sp = a[6].lastIndexOf(' '); const jk = a[6].slice(0, sp) + '|' + a[6].slice(sp + 1).replace(/-0$/, ''); if (NK.j1.has(sg + '|' + jk)) add('j1|' + sg + '|' + jk, i, sc); if (NK.j2.has(jk)) add('j2|' + jk, i, sc); }
    }
  }
  const ce = D.N ? getCentroids() : null; const dongIdx = new Map();
  if (ce) for (const f of ['bdong', 'dong']) for (let c = 0; c < D.dict[f].length; c++) {
    const l = label(f, c), sg = sgL[D.parent[f === 'bdong' ? 'bdong' : 'dong'][c]];
    const k1 = sg + '|' + l; if (!dongIdx.has(k1)) dongIdx.set(k1, [f, c]);
    const k2 = '|' + l; if (!dongIdx.has(k2)) dongIdx.set(k2, [f, c]);
    else { const pv = dongIdx.get(k2); if (pv && (pv[0] !== f || pv[1] !== c)) dongIdx.set(k2, null); }
  }
  for (const c of need) {
    const p = c.p; let a;
    const pick = (key, m) => { a = acc.get(key); if (a && !(m && a.multi)) { c.lat = a.y / a.n; c.lon = a.x / a.n; c.method = key[0] === 'r' ? (key[1] === '1' ? '도로명' : '도로명(시군구 추정)') : (key[1] === '1' ? '지번' : '지번(시군구 추정)'); return true; } return false; };
    if (p.rk && p.sgg && pick('r1|' + p.sgg + '|' + p.rk)) continue;
    if (p.jk && p.sgg && pick('j1|' + p.sgg + '|' + p.jk)) continue;
    if (p.rk && pick('r2|' + p.rk, true)) continue;
    if (p.jk && pick('j2|' + p.jk, true)) continue;
    if (p.dong && dongIdx.size) { const d = dongIdx.get(p.sgg + '|' + p.dong) || dongIdx.get('|' + p.dong); if (d) { c.lat = ce[d[0]].y[d[1]]; c.lon = ce[d[0]].x[d[1]]; c.method = '동 중심(근사)'; continue; } }
    c.method = '실패';
  }
  cust.list = list; hideBusy(); renderCust(); fitCust();
}
function custColor(m, c) {
  if (c && (c.risk != null || c.nts === '폐업자')) return '#e11d48';
  if (c && c.nts === '휴업자') return '#f59e0b';
  return m === '좌표' || m === '도로명' || m === '지번' || m === 'OSM' || m.startsWith('브이월드') ? '#ffd400' : m.indexOf('추정') >= 0 ? '#ffb020' : '#bbbbbb';
}
function renderCust() {
  if (cust.layer) map.removeLayer(cust.layer);
  cust.layer = L.layerGroup();
  for (const c of cust.list) {
    if (c.lat == null) continue;
    const approx = c.method.indexOf('동 중심') >= 0;
    const mk = L.circleMarker([c.lat, c.lon], { renderer: cust.renderer, radius: approx ? 8 : 7, color: '#111', weight: approx ? 1.5 : 2.2, dashArray: approx ? '3 3' : null, fillColor: custColor(c.method, c), fillOpacity: approx ? .55 : .95 });
    mk.bindPopup(() => custPopup(c), { maxWidth: 360 });
    mk.bindTooltip(esc((c.name || c.addr) + (c.nts ? ` [${c.nts}]` : '')), { direction: 'top', offset: [0, -6] });
    cust.layer.addLayer(mk);
  }
  if (cust.show) cust.layer.addTo(map);
  const by = {}; for (const c of cust.list) by[c.method] = (by[c.method] || 0) + 1;
  const ok = cust.list.filter(c => c.lat != null).length;
  $('#cres').style.display = 'block'; $('#stCust').style.display = ''; $('#sCust').textContent = fmt(ok);
  const kp = [['전체', cust.list.length], ['위치 찾음', ok], ['정확(도로명·지번·브이월드)', (by['도로명'] || 0) + (by['지번'] || 0) + (by['좌표'] || 0) + (by['브이월드(도로명)'] || 0) + (by['브이월드(지번)'] || 0) + (by['OSM'] || 0)], ['실패', by['실패'] || 0]];
  $('#cKpi').innerHTML = kp.map(([k, v]) => `<div class="kpi"><span>${k}</span><b>${fmt(v)}</b></div>`).join('') +
    `<div class="kpi" style="grid-column:1/3"><span>매칭 방법</span>${Object.entries(by).map(([k, v]) => `<span class="mth" style="display:inline-block;margin:2px 3px 0 0">${esc(k)} ${fmt(v)}</span>`).join('')}</div>`;
  const fails = cust.list.filter(c => c.method === '실패');
  $('#cFail').innerHTML = fails.length ? `<h4 style="font-size:12px;margin:6px 0">실패 ${fmt(fails.length)}건</h4>` + fails.slice(0, 100).map(c => `<div class="li"><div class="t"><div class="a">${esc(c.name || '(이름없음)')}</div><div class="b">${esc(c.addr || '(주소 없음)')}</div></div></div>`).join('') : '';
  renderLegend();
}
function custPopup(c) {
  const rows = cust.head.map((h, i) => [h, c.row[i]]).filter(([, v]) => String(v).trim() !== '').slice(0, 18);
  const ll = `${c.lat},${c.lon}`;
  const ntsBdg = c.nts ? ` <span class="bdg ${c.nts === '계속사업자' ? 'bn' : c.nts === '휴업자' ? 'bw' : 'bc'}">${esc(c.nts)}</span>` : '';
  return `<div class="pp-h"><span class="custmk"></span>${esc(c.name || '고객')}${ntsBdg}</div><div class="b">${esc(c.addr)}</div>
   <div class="c">매칭: <span class="mth">${esc(c.method)}</span>${c.risk != null ? ` <span class="bdg bc">폐업 의심</span> ${esc(S(c.risk).name)}` : ''}</div>
   <div class="pbtn">${[100, 300, 500].map(m => `<button data-rad="${ll},${m},1">반경 ${m}m 상가</button>`).join('')}<button data-same="${ll}">같은 건물 업소</button></div>
   <div class="pbtn">${links(c.name, c.p.clean, c.lat, c.lon)}</div>
   <table class="ptbl">${rows.map(([h, v]) => `<tr><td>${esc(h)}</td><td>${esc(v)}</td></tr>`).join('')}</table>`;
}
function fitCust() {
  const pts = cust.list.filter(c => c.lat != null); if (!pts.length) return;
  if (pts.length === 1) return map.setView([pts[0].lat, pts[0].lon], 17);
  map.fitBounds(pts.map(c => [c.lat, c.lon]), { padding: [40, 40], maxZoom: 17 });
}

/* ==================== Quarter Comparison ==================== */
const ymOf = name => { const m = String(name).match(/_(20\d{2})(\d{2})(\d{2})?\.(csv|zip)$/i); return m ? `${m[1]}.${m[2]}` : ''; };
function renderBFiles() { renderFileList(CMP.files, $('#blist')); }
async function loadBaseline(input) {
  if (!D.N) return alert('먼저 [데이터] 탭에서 현재 분기 데이터를 불러와 주세요.');
  if (CMP.on) return alert('이미 비교를 마쳤습니다. 다른 분기와 비교하려면 [데이터 비우기] 후 다시 진행하세요.');
  const files = await gatherFiles(input); if (!files.length) return;
  const dup = files.find(f => [...D.files.values()].some(x => x.name === f.name && x.size === f.size));
  if (dup) return alert(`${dup.name}\n현재 데이터와 같은 파일입니다. 이전 분기 파일을 선택하세요.`);
  const queue = register(CMP.files, files); if (!queue.length) return;
  renderBFiles();
  showBusy('현재 데이터 색인 중…', 0); await new Promise(r => setTimeout(r, 20));
  const N0 = D.N, idH = new Float64Array(N0), keyH = new Float64Array(N0);
  for (let i = 0; i < N0; i++) { const a = D.strs[i].split('\x1f'); idH[i] = a[0] ? H(a[0]) : -1; keyH[i] = H(a[1] + '|' + (a[3] || a[6] || '')); }
  const idS = Float64Array.from(idH).sort(), keyS = Float64Array.from(keyH).sort();
  runPool(queue, { cmp: { idH: idS, keyH: keyS, sidos: D.dict.sido.slice() } }, '이전 분기 대조 중', renderBFiles, res => finishCompare(res, idH, keyH, N0));
}
function finishCompare(res, idH, keyH, N0) {
  if (!res.length) { alert('이전 분기 파일을 읽지 못했습니다.'); return; }
  let tot = 0; for (const m of res) tot += m.bId.length;
  const bId = new Float64Array(tot), bKey = new Float64Array(tot); let o = 0;
  const bs = new Set();
  for (const m of res) { bId.set(m.bId, o); bKey.set(m.bKey, o); o += m.bId.length; m.bSidos.forEach(x => bs.add(x)); delete m.bId; delete m.bKey; }
  bId.sort(); bKey.sort();
  const ST = D.codes.st, SD = D.codes.sido; const inBase = D.dict.sido.map(x => bs.has(x));
  for (let i = 0; i < N0; i++) ST[i] = !inBase[SD[i]] ? 3 : ((idH[i] !== -1 && hasS(bId, idH[i])) || hasS(bKey, keyH[i])) ? 0 : 1;
  parts.push(...res); finalize();
  const ST2 = D.codes.st; for (let i = N0; i < D.N; i++) ST2[i] = 2;
  const c = [0, 0, 0, 0]; for (let i = 0; i < D.N; i++) c[ST2[i]]++; D.cnt.st = c;
  CMP.on = true; CMP.keepN = c[0]; CMP.newN = c[1]; CMP.closedN = c[2]; CMP.exN = c[3]; CMP.baseTotal = tot;
  CMP.baseYM = [...CMP.files.values()].map(f => ymOf(f.name) || ymOf(f.from || '')).find(Boolean) || '이전';
  CMP.curYM = VAULT_SUMMARY?.dataYM || [...D.files.values()].map(f => ymOf(f.name) || ymOf(f.from || '')).find(Boolean) || '현재';
  $('#stNew').style.display = ''; $('#stClosed').style.display = ''; $('#sNew').textContent = fmt(c[1]); $('#sClosed').textContent = fmt(c[2]);
  $('#sTotal').textContent = fmt(D.N - c[2]); $('#cmpres').style.display = 'block';
  $('#dataDate').textContent = `상가(상권)정보 · ${CMP.baseYM} → ${CMP.curYM} 비교`;
  colorMode = 'st'; syncCmpButtons(); applyFilter(); renderFilterUI(); renderCmp();
  if (c[3]) flash(`비교 제외 ${fmt(c[3])}건: 이전 분기 파일에 없는 시도`);
}
function setColorMode(m) { colorMode = m; syncCmpButtons(); renderLegend(); layer.redraw(); }
function syncCmpButtons() {
  $$('[data-cm]').forEach(b => b.classList.toggle('on', b.dataset.cm === colorMode));
  const k = sel.st.size ? [...sel.st].sort().join('') : 'all';
  $$('[data-sv]').forEach(b => b.classList.toggle('on', b.dataset.sv === k || (k === 'all' && b.dataset.sv === 'all')));
}
function renderCmp() {
  if (!CMP.on) return; syncCmpButtons();
  const base = computeFilter('st'), ST = D.codes.st, C = D.codes; const c = [0, 0, 0, 0];
  for (let k = 0; k < base.length; k++) c[ST[base[k]]]++;
  const prev = c[0] + c[2], net = c[1] - c[2], pct = (a, b) => b ? (a / b * 100).toFixed(1) + '%' : '-';
  $('#cmpKpi').innerHTML = [[`이전 ${CMP.baseYM}`, fmt(prev)], [`현재 ${CMP.curYM}`, fmt(c[0] + c[1])],
    ['신규 개업', `<span class="up">${fmt(c[1])}</span> <small class="note">${pct(c[1], prev)}</small>`],
    ['폐업', `<span class="dn">${fmt(c[2])}</span> <small class="note">${pct(c[2], prev)}</small>`],
    ['순증감', `<span class="${net >= 0 ? 'up' : 'dn'}">${net >= 0 ? '+' : ''}${fmt(net)}</span>`], ['비교 제외', fmt(c[3])]]
    .map(([k, v]) => `<div class="kpi"><span>${k}</span><b>${v}</b></div>`).join('');
  const agg = f => { const m = new Map(); for (let k = 0; k < base.length; k++) { const i = base[k], t = ST[i]; if (t === 3) continue; const key = C[f][i]; let a = m.get(key); if (!a) { a = [0, 0, 0]; m.set(key, a); } a[t]++; } return m; };
  const l1 = [...agg('l1')].sort((a, b) => (b[1][0] + b[1][2]) - (a[1][0] + a[1][2]));
  const row = (name, a, attr) => { const p = a[0] + a[2], n = a[1] - a[2]; return `<tr ${attr || ''}><td>${name}</td><td>${fmt(p)}</td><td class="up">${fmt(a[1])}</td><td class="dn">${fmt(a[2])}</td><td class="${n >= 0 ? 'up' : 'dn'}">${n >= 0 ? '+' : ''}${fmt(n)}</td><td>${pct(a[2], p)}</td></tr>`; };
  const th = '<tr><th></th><th>이전</th><th>신규</th><th>폐업</th><th>순증</th><th>폐업률</th></tr>';
  $('#cmpL1').innerHTML = th + l1.map(([k, a]) => row(`<span class="dot" style="background:${colorOf[k]}"></span> ${esc(D.dict.l1[k])}`, a)).join('');
  const l2 = [...agg('l2')];
  const top = (idx, col) => {
    const arr = l2.filter(x => x[1][idx]).sort((a, b) => b[1][idx] - a[1][idx]).slice(0, 10), mx = arr.length ? arr[0][1][idx] : 1;
    return arr.map(([k, a]) => `<div class="r"><span class="lb" title="${esc(label('l2', k))}">${esc(label('l2', k))}</span><span class="bb"><i style="width:${a[idx] / mx * 100}%;background:${col}"></i></span><span class="v">${fmt(a[idx])}</span></div>`).join('') || '<div class="note">없음</div>';
  };
  $('#cmpNewL2').innerHTML = top(1, '#16a34a'); $('#cmpClosedL2').innerHTML = top(2, '#e11d48');
  const regF = sel.sgg.size === 1 || sel.dong.size ? 'dong' : 'sgg';
  $('#cmpRegT').textContent = regF === 'dong' ? '지역별 (행정동)' : '지역별 (시군구)';
  const reg = [...agg(regF)].sort((a, b) => (b[1][1] + b[1][2]) - (a[1][1] + a[1][2])).slice(0, 25);
  $('#cmpReg').innerHTML = th + reg.map(([k, a]) => row(esc(regF === 'sgg' ? sggFull(k) : label('dong', k)), a, `data-go2="${regF}:${k}"`)).join('');
}

/* ==================== View List, Fit, Export, Modals ==================== */
function inViewIds() {
  const sz = map.getSize(), out = [];
  for (let k = 0; k < vis.n; k++) { const x = vis.x[k], y = vis.y[k]; if (x >= 0 && y >= 0 && x <= sz.x && y <= sz.y) out.push(vis.idx[k]); }
  return out;
}
function renderViewList() {
  if (!D.N) { $('#vlist').innerHTML = ''; return; }
  const ids = inViewIds(), LIM = 300, C = D.codes;
  $('#listInfo').innerHTML = `화면 안 <b>${fmt(ids.length)}</b>개${ids.length > LIM ? ` · 앞 ${LIM}개만 표시` : ''}`;
  const show = ids.length > 5000 ? ids.slice(0, LIM) : ids.sort((a, b) => S(a).name.localeCompare(S(b).name, 'ko')).slice(0, LIM);
  $('#vlist').innerHTML = show.map(i => { const s = S(i); return `<div class="li" data-go="${i}"><input type="checkbox" data-ck="${i}" ${selMask[i] ? 'checked' : ''}><div class="t"><div class="a"><span class="dot" style="background:${colorOf[C.l1[i]]}"></span> ${badge(i)}${esc(s.name)}${s.branch ? ' ' + esc(s.branch) : ''}</div><div class="b">${esc(label('l3', C.l3[i]))} · ${esc(s.addr)}</div></div></div>`; }).join('');
}
function fitTo(ids) {
  if (!ids.length) return;
  let a = 90, b = -90, c = 180, d = -180;
  for (const i of ids) { const y = D.lat[i], x = D.lon[i]; if (y < a) a = y; if (y > b) b = y; if (x < c) c = x; if (x > d) d = x; }
  map.fitBounds([[a, c], [b, d]], { padding: [30, 30], maxZoom: 17 });
}
function download(partsArr, name, mime = 'text/csv;charset=utf-8') {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob(Array.isArray(partsArr) ? partsArr : [partsArr], { type: mime }));
  a.download = name; document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 2000);
}
function exportCSV(ids, tag) {
  const C = D.codes, q = v => { v = v == null ? '' : String(v); return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  const head = [
    '상가업소번호', '상호명', '지점명', '점포유형', '등재연월', '건물입점수',
    '업종대분류', '업종중분류', '업종소분류', '업종소분류코드', '표준산업분류코드', '표준산업분류명',
    '시도', '시군구', '시군구코드', '행정동', '행정동코드', '법정동',
    '도로명', '도로명주소', '지번(동 번지)', '신우편번호', '건물명', '층', '호', '경도', '위도', '출처',
  ].concat(CMP.on ? [`개폐업(${CMP.baseYM}→${CMP.curYM})`] : []);
  const out = ['\uFEFF' + head.join(',') + '\r\n']; let buf = [];
  for (const i of ids) {
    const s = S(i);
    const ym = D.regYM[i];
    const bcnt = D.bldId[i] ? D.bldCnt[D.bldId[i]] : 1;
    buf.push([
      s.id, s.name, s.branch, D.isFran[i] ? '프랜차이즈/지점' : '개인점포', ym ? `${String(ym).slice(0, 4)}-${String(ym).slice(4, 6)}` : '', bcnt,
      D.dict.l1[C.l1[i]], label('l2', C.l2[i]), label('l3', C.l3[i]), D.codeMaps.l3[C.l3[i]] || '',
      D.codeMaps.ksic[C.ksic[i]] || '', D.dict.ksic[C.ksic[i]],
      D.dict.sido[C.sido[i]], label('sgg', C.sgg[i]), D.codeMaps.sgg[C.sgg[i]] || '',
      label('dong', C.dong[i]), D.codeMaps.dong[C.dong[i]] || '', label('bdong', C.bdong[i]),
      label('roadNm', C.roadNm[i]).replace('(미상)', ''), s.road, s.jb, label('zip', C.zip[i]).replace('(미상)', ''),
      s.bld, label('floor', C.floor[i]).replace('(미상)', ''), s.ho, D.lon[i], D.lat[i], D.apiMask[i] ? 'OpenAPI' : 'Vault/CSV',
    ].concat(CMP.on ? [D.dict.st[D.codes.st[i]]] : []).map(q).join(','));
    if (buf.length >= 20000) { out.push(buf.join('\r\n') + '\r\n'); buf = []; }
  }
  if (buf.length) out.push(buf.join('\r\n') + '\r\n');
  const d = new Date(), ds = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
  download(out, `소상공인_상가정보_${tag}_${ids.length}건_${ds}.csv`);
}
function afterLoad(fit = true) {
  $('#sTotal').textContent = fmt(D.N - CMP.closedN);
  $('#empty').style.display = D.N ? 'none' : 'flex';
  $('#bExportFilt').disabled = !D.N; $('#bReset').disabled = !D.N;
  if (D.apiCount > 0) { $('#stApi').style.display = ''; $('#sApi').textContent = fmt(D.apiCount); }
  const ym = VAULT_SUMMARY?.dataYM || [...D.files.values()].map(f => (f.name.match(/_(20\d{2})(\d{2})\.csv$/) || [])).find(m => m[1])?.slice(1).join('.') || '';
  $('#dataDate').textContent = `상가(상권)정보${ym ? ` · ${ym} 기준` : ''} · ${D.files.size}개 소스 로드됨`;
  applyFilter(); renderFilterUI();
  if (fit && D.N) fitTo(filtered);
}

function updateScrim() {
  const on = $('#settingsModal').classList.contains('on') || $('#aiModal').classList.contains('on');
  $('#scrim').classList.toggle('on', on);
}
function openSettings(on) {
  $('#settingsModal').classList.toggle('on', on);
  $('#settingsModal').setAttribute('aria-hidden', String(!on));
  if (on) {
    syncApiKeyUI();
    setTheme(store.get('theme', 'clean'));
    if (VAULT_META) {
      $('#vaultInfo').textContent = `Vault v${VAULT_META.v || 2} · 빌드 ${VAULT_META.builtAt} · 기준 ${VAULT_META.dataYM} · 전국 ${fmt(VAULT_META.totalStores)}건 · AES-256-GCM (${(VAULT_META.totalBytes / 1048576).toFixed(1)} MB)`;
    } else {
      $('#vaultInfo').textContent = '로컬 모드 (vault.json 미감지)';
    }
  }
  updateScrim();
}
function closeModals() {
  $('#settingsModal').classList.remove('on'); $('#settingsModal').setAttribute('aria-hidden', 'true');
  $('#aiModal').classList.remove('on'); $('#aiModal').setAttribute('aria-hidden', 'true');
  updateScrim();
}
function switchTab(tab) {
  curTab = tab;
  $$('.tabs button').forEach(x => x.classList.toggle('act', x.dataset.tab === tab));
  $$('.tabpane').forEach(p => p.classList.toggle('act', p.id === 'tab-' + tab));
  if (tab === 'list') renderViewList();
  if (tab === 'cmp') renderCmp();
  if (tab === 'api') { syncApiKeyUI(); renderDiagBoard(); updateApiDongHint(); }
}

/* ==================== App Initialization ==================== */
function initAppUI() {
  if (APP_BOOTED) return;
  APP_BOOTED = true;

  map = L.map('map', { zoomControl: false, boxZoom: false, minZoom: 6, maxZoom: 20, zoomSnap: 0.5, zoomDelta: 0.5 }).setView([36.4, 127.8], 7);
  L.control.zoom({ position: 'bottomright' }).addTo(map);
  L.control.scale({ metric: true, imperial: false, position: 'bottomleft' }).addTo(map);
  const b = store.get('base', getVWorldKey() ? 'vbase' : 'gsoft');
  setBase(BASES[b] ? b : (getVWorldKey() ? 'vbase' : 'gsoft'));
  setTheme(store.get('theme', 'clean'));
  layer = new PointLayer().addTo(map);
  zoneLayer = L.layerGroup().addTo(map);
  parcelLayer = L.layerGroup().addTo(map);
  measureLayer = L.layerGroup().addTo(map);
  map.createPane('custPane'); map.getPane('custPane').style.zIndex = 640;
  cust.renderer = L.canvas({ pane: 'custPane', padding: .3 });

  $('#ovSido').onclick = () => toggleWmsOverlay('sido');
  $('#ovSgg').onclick = () => toggleWmsOverlay('sgg');
  $('#ovEmd').onclick = () => toggleWmsOverlay('emd');
  $('#ovCadastral').onclick = () => toggleWmsOverlay('cadastral');
  $('#ovZoning').onclick = () => toggleWmsOverlay('zoning');
  $('#ovBldg').onclick = () => toggleWmsOverlay('bldg');
  $('#ovLabel').onclick = e => {
    showStoreLabels = !showStoreLabels;
    e.currentTarget.classList.toggle('on', showStoreLabels);
    layer.redraw();
    toast(showStoreLabels ? '🏷 상가 명칭 표시 ON (줌 17+ 자동 표시)' : '🏷 상가 명칭 표시 OFF');
  };
  $('#ovMarker').onclick = e => {
    showStoreMarkers = !showStoreMarkers;
    e.currentTarget.classList.toggle('on', showStoreMarkers);
    layer.redraw();
    toast(showStoreMarkers ? '📍 상가 마커 표시 ON' : '📍 상가 마커 표시 OFF');
  };
  $('#ovMeasure').onclick = e => {
    measureMode = !measureMode;
    e.currentTarget.classList.toggle('on', measureMode);
    if (measureMode) {
      measurePts = []; measureLayer.clearLayers();
      toast('📏 거리·면적 측정 모드 ON — 지도를 차례로 클릭하세요');
    } else {
      measurePts = []; measureLayer.clearLayers();
      toast('📏 측정 모드 종료');
    }
  };

  $('#bMobSide').onclick = () => $('#side').classList.toggle('open');
  $$('.tabs button').forEach(btn => btn.onclick = () => switchTab(btn.dataset.tab));
  $$('[data-mode]').forEach(btn => btn.onclick = () => { dispMode = btn.dataset.mode; $$('[data-mode]').forEach(x => x.classList.toggle('on', x === btn)); layer.redraw(); });
  $('#baseSel').onchange = e => setBase(e.target.value);
  $('#themeSel').onchange = e => setTheme(e.target.value);
  $('#bLocate').onclick = () => map.locate({ setView: true, maxZoom: 16 });
  map.on('locationerror', () => toast('위치를 가져올 수 없습니다'));
  $('#bSettings').onclick = () => openSettings(true);
  $('#closeSettings').onclick = () => openSettings(false);
  $('#closeAiModal').onclick = closeModals;
  $('#scrim').onclick = closeModals;
  $('#bLockNow').onclick = lockAppNow;
  $('#modalLockBtn').onclick = lockAppNow;
  $('#clearCacheBtn').onclick = async () => {
    if ('caches' in window) { const ks = await caches.keys(); await Promise.all(ks.map(k => caches.delete(k))); }
    toast('오프라인 캐시를 비웠습니다…');
    setTimeout(() => location.reload(), 500);
  };

  // Vault Sido Clicks
  const onSidoClick = e => {
    const btn = e.target.closest('[data-sido-slug]');
    if (btn) loadVaultSido(btn.dataset.sidoSlug, true);
  };
  $('#sidoGrid').onclick = onSidoClick;
  $('#emptySidoGrid').onclick = onSidoClick;
  $('#bLoadCapital').onclick = async () => {
    for (const slug of ['incheon', 'seoul', 'gyeonggi']) {
      if (!loadedSidos.has(slug)) await loadVaultSido(slug, false);
    }
    map.setView([37.52, 126.95], 10);
  };
  $('#bOpenApiTab').onclick = () => { switchTab('api'); $('#empty').style.display = 'none'; $('#side').classList.add('open'); };

  // API Key Controls
  const toggleEye = id => { const inp = $(id); inp.type = inp.type === 'password' ? 'text' : 'password'; };
  $('#apiToggleEye').onclick = () => toggleEye('#apiKeyIn');
  $('#setDataGoEye').onclick = () => toggleEye('#setDataGoKey');
  $('#setGeminiEye').onclick = () => toggleEye('#setGeminiKey');
  $('#vwToggleEye').onclick = () => toggleEye('#vwKeyIn');
  $('#setVwEye').onclick = () => toggleEye('#setVwKey');
  const saveDataGo = srcId => {
    const k = $(srcId).value.replace(/\s+/g, '');
    if (k) { store.set('dataGoKey', k); toast('공공데이터포털 인증키 저장'); }
    else { store.del('dataGoKey'); toast('공공데이터포털 인증키 삭제'); }
    syncApiKeyUI();
  };
  const saveVw = srcId => {
    const k = $(srcId).value.replace(/\s+/g, '');
    if (k) { store.set('vworldKey', k); toast('브이월드 인증키 저장 (수동 키 적용)'); }
    else { store.del('vworldKey'); toast('수동 키 해제 · Vault 기본 브이월드 키 사용'); }
    syncApiKeyUI();
    if ($('#baseSel').value.startsWith('v')) setBase($('#baseSel').value);
  };
  $('#apiSaveKey').onclick = () => saveDataGo('#apiKeyIn');
  $('#saveDataGoKey').onclick = () => saveDataGo('#setDataGoKey');
  $('#vwSaveKey').onclick = () => saveVw('#vwKeyIn');
  $('#saveVwKey').onclick = () => saveVw('#setVwKey');
  $('#saveGeminiKey').onclick = () => {
    const k = $('#setGeminiKey').value.replace(/\s+/g, '');
    if (k) { store.set('geminiKey', k); toast('Gemini API 키 저장'); }
    else { store.del('geminiKey'); toast('Gemini API 키 삭제'); }
    syncApiKeyUI();
  };
  $('#setThemeChips').onclick = e => { const c = e.target.closest('.chip'); if (c) setTheme(c.dataset.th); };

  // API Actions
  $('#btnCheckApis').onclick = runApiHealthCheck;
  $('#btnApiRadius').onclick = () => fetchSdscStores('radius');
  $('#btnApiRect').onclick = () => fetchSdscStores('rect');
  $('#btnApiDong').onclick = () => fetchSdscStores('dong');
  $('#btnApiZones').onclick = fetchCommercialZones;
  $('#btnApiClearZones').onclick = () => { zoneLayer.clearLayers(); toast('상권 영역 오버레이를 숨겼습니다'); };
  $('#btnClearApiCache').onclick = async () => {
    await idb.del('live_api_stores');
    toast('저장된 API 캐시를 비웠습니다 (새로고침 시 반영)');
  };
  $('#btnNtsCheck').onclick = runNtsLookupPanel;
  $('#btnNtsCsv').onclick = () => {
    if (!LAST_NTS_ROWS.length) return;
    const q = v => { v = v == null ? '' : String(v); return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
    const lines = ['\uFEFF' + ['사업자번호', '납세자상태', '상태코드', '과세유형', '폐업일'].join(',')];
    for (const x of LAST_NTS_ROWS) lines.push([x.b_no, x.b_stt, x.b_stt_cd, x.tax_type, x.end_dt].map(q).join(','));
    download(lines.join('\r\n') + '\r\n', `국세청_사업자상태_${LAST_NTS_ROWS.length}건.csv`);
  };
  $('#btnCopyCli').onclick = () => copyText($('#cliCmd').textContent, 'CLI 수집 명령어를 복사했습니다');

  // Gemini AI Buttons
  $('#bAiAnalyze').onclick = () => runAiCommercialAnalysis(false);
  $('#bAiSel').onclick = () => runAiCommercialAnalysis(true);
  $('#bAiFilter').onclick = runAiNaturalFilter;
  $('#aiCopyBtn').onclick = () => copyText($('#aiModalBody').textContent, 'AI 상권 분석 내용을 복사했습니다');

  // Backup / Restore
  $('#backupExport').onclick = async () => {
    const payload = {
      version: 2,
      exportedAt: new Date().toISOString(),
      theme: store.get('theme', 'clean'),
      base: store.get('base', 'gsoft'),
      liveApiStores: (await idb.get('live_api_stores')) || [],
    };
    download(JSON.stringify(payload, null, 2), `상권지도_백업_${new Date().toISOString().slice(0, 10)}.json`, 'application/json');
    toast('설정 및 실시간 API 수집 데이터 백업 완료');
  };
  $('#backupImport').onchange = async e => {
    const f = e.target.files[0]; if (!f) return;
    try {
      const j = JSON.parse(await f.text());
      if (j.theme) setTheme(j.theme);
      if (j.base) setBase(j.base);
      if (Array.isArray(j.liveApiStores) && j.liveApiStores.length) {
        ingestSdscItems(j.liveApiStores, `복원 API 데이터 (${j.liveApiStores.length}건)`, true);
      }
      toast('백업을 복원했습니다');
    } catch { toast('올바른 백업 JSON 파일이 아닙니다'); }
    e.target.value = '';
  };

  // Filter Controls (including v2 quick chips)
  $('#kw').addEventListener('input', e => {
    const v = e.target.value.trim().toLowerCase();
    kwTerms = v ? v.split(',').map(g => g.trim().split(/\s+/).filter(Boolean)).filter(g => g.length) : [];
    clearTimeout(fTimer); fTimer = setTimeout(applyFilter, 250);
  });
  $('#f-regym').onclick = e => {
    const ch = e.target.closest('[data-regym]'); if (!ch) return;
    regYmFilter = ch.dataset.regym; syncQuickChipCounts(); applyFilter();
  };
  $('#f-fran').onclick = e => {
    const ch = e.target.closest('[data-fran]'); if (!ch) return;
    franFilter = ch.dataset.fran; syncQuickChipCounts(); applyFilter();
  };
  $('#f-bld').onclick = e => {
    const ch = e.target.closest('[data-bld]'); if (!ch) return;
    bldFilter = ch.dataset.bld; syncQuickChipCounts(); applyFilter();
  };
  $$('[data-clr]').forEach(btn => btn.onclick = () => { sel[btn.dataset.clr].clear(); prune(); refilter(); });
  $('#clearAll').onclick = () => {
    for (const f in sel) sel[f].clear();
    $('#kw').value = ''; kwTerms = []; onlySel = false; onlyApi = false;
    regYmFilter = 'all'; franFilter = 'all'; bldFilter = 'all';
    $('#onlySel').checked = false; $('#onlyApi').checked = false;
    refilter();
  };
  $('#onlySel').onchange = e => { onlySel = e.target.checked; refilter(); };
  $('#onlyApi').onchange = e => { onlyApi = e.target.checked; refilter(); };
  $('#bFit').onclick = () => fitTo(filtered);

  // Legend
  $('#legend').onclick = e => {
    if (e.target.id === 'lgCat' || e.target.id === 'lgSt') { setColorMode(e.target.id === 'lgSt' ? 'st' : 'l1'); return; }
    const sr = e.target.closest('[data-st]'); if (sr) { stToggle(+sr.dataset.st); return; }
    if (e.target.id === 'lgAll') { hiddenL1.clear(); renderLegend(); layer.redraw(); return; }
    if (e.target.id === 'lgNone') { D.dict.l1.forEach((_, c) => hiddenL1.add(c)); renderLegend(); layer.redraw(); return; }
    const r = e.target.closest('.row'); if (!r) return;
    if (r.dataset.cust) { $('#cShow').checked = !cust.show; $('#cShow').onchange(); return; }
    const c = +r.dataset.c; hiddenL1.has(c) ? hiddenL1.delete(c) : hiddenL1.add(c); renderLegend(); layer.redraw();
  };

  // Selection Panel & Drawing
  $('#tPan').onclick = () => setTool('pan'); $('#tRect').onclick = () => setTool('rect');
  $('#tLasso').onclick = () => setTool('lasso'); $('#tCircle').onclick = () => setTool('circle');
  document.addEventListener('keydown', e => { if (e.key === 'Escape') { setTool('pan'); $('#gres').style.display = 'none'; closeModals(); } });
  $('#selBody').onclick = e => {
    const rm = e.target.closest('[data-rm]'); if (rm) { setSel([+rm.dataset.rm], false); return; }
    const g = e.target.closest('[data-go]'); if (g) goTo(+g.dataset.go);
  };
  $('#bSelPanel').onclick = () => { $('#selpanel').classList.toggle('hide'); renderSelPanel(); };
  $('#selClose').onclick = () => $('#selpanel').classList.add('hide');
  $('#bClearSel').onclick = () => {
    if (selCount && confirm(`선택 ${fmt(selCount)}개를 모두 해제할까요?`)) {
      selMask.fill(0); selCount = 0; $('#sSel').textContent = '0'; layer.redraw(); renderSelPanel();
      if (onlySel) applyFilter();
    }
  };
  $('#bFitSel').onclick = () => fitTo(selIndices());
  $('#bExportSel').onclick = () => { if (!selCount) return alert('선택된 업소가 없습니다.'); exportCSV(selIndices(), '선택'); };

  map.on('mousedown', e => {
    if (tool === 'pan') return;
    const oe = e.originalEvent; if (oe.button !== 0) return;
    drawing = { start: e.containerPoint, ll: e.latlng, pts: [e.containerPoint], lls: [e.latlng], remove: oe.altKey };
    const st = { color: drawing.remove ? '#555' : '#e60012', weight: 2, dashArray: '6 4', fillOpacity: .08, interactive: false };
    drawing.shape = (tool === 'rect' ? L.rectangle([e.latlng, e.latlng], st) : tool === 'circle' ? L.circle(e.latlng, { ...st, radius: 1 }) : L.polygon([e.latlng], st)).addTo(map);
  });
  map.on('mousemove', e => {
    if (drawing) {
      if (tool === 'rect') drawing.shape.setBounds([drawing.ll, e.latlng]);
      else if (tool === 'circle') { drawing.shape.setRadius(drawing.ll.distanceTo(e.latlng)); $('#hint').textContent = `반경 ${fmt(drawing.ll.distanceTo(e.latlng))} m`; }
      else { const last = drawing.pts[drawing.pts.length - 1]; if (Math.abs(last.x - e.containerPoint.x) + Math.abs(last.y - e.containerPoint.y) > 3) { drawing.pts.push(e.containerPoint); drawing.lls.push(e.latlng); drawing.shape.setLatLngs(drawing.lls); } }
      drawing.end = e.containerPoint;
      return;
    }
    if (tool !== 'pan' || !D.N) return;
    const cp = e.containerPoint; let on = false;
    if (vis.mode === 'cluster') { for (const c of vis.clusters) if (Math.hypot(c.x - cp.x, c.y - cp.y) <= c.r) { on = true; break; } }
    else if (vis.mode === 'point' && vis.n < 400000) on = hits(cp, 2).length > 0;
    map.getContainer().style.cursor = on ? 'pointer' : '';
  });
  map.on('mouseup', finishDraw);
  document.addEventListener('mouseup', () => { if (drawing) finishDraw(); });
  map.on('click', e => {
    if (measureMode) {
      measurePts.push([e.latlng.lat, e.latlng.lng]);
      renderMeasureOverlay();
      return;
    }
    if (tool !== 'pan' || !D.N) return;
    if (vis.mode === 'cluster') {
      const cp = e.containerPoint; let best = null, bd = 1e9;
      for (const c of vis.clusters) { const d = Math.hypot(c.x - cp.x, c.y - cp.y); if (d <= c.r + 2 && d < bd) { bd = d; best = c; } }
      if (best) map.setView(map.containerPointToLatLng([best.x, best.y]), Math.min(19, map.getZoom() + (best.c > 2000 ? 3 : 2)));
      return;
    }
    const ids = hits(e.containerPoint); if (!ids.length) return;
    if (e.originalEvent.ctrlKey || e.originalEvent.metaKey) { const i = ids[0]; setSel([i], !selMask[i]); flash(`${S(i).name} ${selMask[i] ? '선택' : '제외'}`); return; }
    openPopup(ids, e.latlng);
  });
  map.on('contextmenu', e => {
    const { lat, lng } = e.latlng; let best = -1, bd = 1e18; const cl = Math.cos(lat * Math.PI / 180);
    const src = D.N ? nearIds(lat, lng, 500, null) : [];
    for (const i of src) { const dy = (D.lat[i] - lat) * mPerDegLat, dx = (D.lon[i] - lng) * mPerDegLat * cl, d = dx * dx + dy * dy; if (d < bd) { bd = d; best = i; } }
    let localAddr = '';
    if (best >= 0) {
      const s = S(best), dCd = D.codeMaps.dong[D.codes.dong[best]] || '';
      localAddr = `<div class="c">인근 상가 기준(약 ${fmt(Math.sqrt(bd))}m): ${esc(s.addr)} · ${esc(label('sgg', D.codes.sgg[best]))} ${esc(label('dong', D.codes.dong[best]))}${dCd ? ` (${esc(dCd)})` : ''}</div>`;
    }
    const ll = `${lat.toFixed(6)},${lng.toFixed(6)}`;
    const slotId = `vwSlot_${Date.now()}`;
    const hasVw = !!getVWorldKey();
    L.popup({ maxWidth: 360 }).setLatLng(e.latlng).setContent(`<div class="pp-h">📍 이 위치 (디지털트윈국토)</div>
      <div id="${slotId}">${hasVw ? '<div class="c">🇰🇷 브이월드 주소·공시지가·용도지역 조회 중…</div>' : ''}</div>
      ${localAddr}<div class="c" style="margin-top:3px">${ll}</div>
      <div class="pbtn">${D.N ? [100, 300, 500, 1000].map(m => `<button data-rad="${lat},${lng},${m},0">반경 ${m >= 1000 ? m / 1000 + 'km' : m + 'm'} 선택</button>`).join('') : ''}</div>
      <div class="pbtn">${links('', best >= 0 ? S(best).addr : '', lat, lng)}<a href="https://www.google.com/maps?q=${ll}" target="_blank">구글</a></div>`).openOn(map);
    if (hasVw) {
      Promise.allSettled([vwReverseAddr(lat, lng), vwLandInfo(lat, lng)]).then(([aR, lR]) => {
        const slot = document.getElementById(slotId);
        const addrInfo = aR.status === 'fulfilled' ? aR.value : null;
        const land = lR.status === 'fulfilled' ? lR.value : null;
        if (land?.parcel) drawParcelHighlight(land.parcel);
        if (slot) slot.innerHTML = formatLandCardHtml(addrInfo, land);
      });
    }
  });

  // Global Popup Actions (Building + VWorld Land Price/Zoning!)
  document.addEventListener('click', e => {
    const tg = e.target.closest('[data-tg]');
    if (tg) { const i = +tg.dataset.tg; setSel([i], !selMask[i]); tg.classList.toggle('on', !!selMask[i]); tg.textContent = selMask[i] ? '선택됨 ✓' : '+ 선택'; return; }
    if (e.target.closest('[data-tgall]')) { setSel(popIds, true); $$('.pp [data-tg]').forEach(x => { x.classList.add('on'); x.textContent = '선택됨 ✓'; }); return; }
    const vwl = e.target.closest('[data-vwland]');
    if (vwl) {
      const parts = vwl.dataset.vwland.split(',');
      const la = +parts[0], lo = +parts[1], title = parts.slice(2).join(',') || '선택 위치';
      if (!getVWorldKey()) { toast('브이월드 인증키가 없습니다'); return; }
      const sid = `vwStore_${Date.now()}`;
      L.popup({ maxWidth: 360 }).setLatLng([la, lo]).setContent(`<div class="pp-h">📐 ${esc(title)} · 필지·공시지가</div><div id="${sid}" class="c">🇰🇷 브이월드 지적·공시지가·용도지역 조회 중…</div>`).openOn(map);
      Promise.allSettled([vwReverseAddr(la, lo), vwLandInfo(la, lo)]).then(([aR, lR]) => {
        const slot = document.getElementById(sid);
        const addrInfo = aR.status === 'fulfilled' ? aR.value : null;
        const land = lR.status === 'fulfilled' ? lR.value : null;
        if (land?.parcel) drawParcelHighlight(land.parcel);
        if (slot) slot.innerHTML = formatLandCardHtml(addrInfo, land);
      });
      return;
    }
    const bld = e.target.closest('[data-bld]');
    if (bld) {
      const ids = sameBuildingIds(+bld.dataset.bld);
      if (ids.length) openPopup(ids, [D.lat[ids[0]], D.lon[ids[0]]]);
      return;
    }
    const bldsel = e.target.closest('[data-bldsel]');
    if (bldsel) {
      const ids = sameBuildingIds(+bldsel.dataset.bldsel);
      setSel(ids, true); openSelPanel();
      flash(`🏢 같은 건물 ${fmt(ids.length)}개 업소 일괄 선택`);
      return;
    }
    const rb = e.target.closest('[data-rad]');
    if (rb) { const [la, lo, m, ex] = rb.dataset.rad.split(',').map(Number); radiusSelect(la, lo, m, ex); map.closePopup(); return; }
    const sb = e.target.closest('[data-same]');
    if (sb) { const [la, lo] = sb.dataset.same.split(',').map(Number); const ids = nearIds(la, lo, 15); ids.length ? openPopup(ids, [la, lo]) : alert('15m 이내 업소가 없습니다.'); }
  });

  // Address / Place Search
  $('#gq').addEventListener('keydown', e => { if (e.key === 'Enter') gsearch(); });
  $('#gbtn').onclick = gsearch;
  $('#gres').onclick = async e => {
    const it = e.target.closest('.gi'); if (!it) return;
    if (it.dataset.vw) {
      it.innerHTML = '🇰🇷 브이월드 검색 중…';
      try {
        const r = await vwSearchPlaceAndAddr($('#gq').value.trim());
        it.outerHTML = r.length
          ? r.map(x => `<div class="gi" data-ll="${x.lat},${x.lon},17" data-t="${esc(x.title)}">${esc(x.title)}<small>🇰🇷 브이월드 ${esc(x.kind)}${x.addr ? ' · ' + esc(x.addr) : ''}</small></div>`).join('')
          : '<div class="gi">브이월드 검색 결과 없음</div>';
      } catch (err) { it.innerHTML = `브이월드 검색 실패 (${esc(err.message)})`; }
      return;
    }
    if (it.dataset.osm) {
      it.innerHTML = '검색 중…';
      try {
        const r = await osmSearch($('#gq').value.trim(), 5);
        it.outerHTML = r.length ? r.map(x => `<div class="gi" data-ll="${x.lat},${x.lon},17" data-t="${esc(x.display_name)}">${esc(x.display_name)}<small>OpenStreetMap</small></div>`).join('') : '<div class="gi">결과 없음</div>';
      } catch { it.innerHTML = '인터넷 검색 실패'; }
      return;
    }
    const [la, lo, z] = it.dataset.ll.split(',').map(Number);
    $('#gres').style.display = 'none';
    if (it.dataset.open) { map.setView([la, lo], z); if (gpin) { map.removeLayer(gpin); gpin = null; } setTimeout(() => { layer.redraw(); openPopup(nearIds(la, lo, 3), [la, lo]); }, 350); }
    else dropPin(la, lo, z, it.dataset.t);
  };

  // Customers
  $('#cdrop').onclick = () => $('#custIn').click();
  $('#custIn').onchange = async () => { const f = $('#custIn').files[0]; $('#custIn').value = ''; if (f) readCust(f); };
  $('#bGeo').onclick = geocode;
  $('#bCustFit').onclick = fitCust;
  $('#cShow').onchange = () => { cust.show = $('#cShow').checked; if (cust.layer) { cust.show ? cust.layer.addTo(map) : map.removeLayer(cust.layer); } renderLegend(); };
  $('#bCustClear').onclick = () => { if (!confirm('고객 표시를 지울까요?')) return; if (cust.layer) map.removeLayer(cust.layer); cust.list = []; cust.layer = null; $('#cres').style.display = 'none'; $('#stCust').style.display = 'none'; renderLegend(); };
  $('#bCustRad').onclick = () => {
    const R = Math.max(10, +$('#cRad').value || 300), ex = $('#cExSame').checked, pts = cust.list.filter(c => c.lat != null);
    if (!pts.length || !D.N) return;
    const cell = R / mPerDegLat * 1.2, grid = new Map(), key = (y, x) => Math.floor(y / cell) + '_' + Math.floor(x / cell);
    for (const c of pts) { const k = key(c.lat, c.lon); (grid.get(k) || grid.set(k, []).get(k)).push(c); }
    const ids = [], R2 = R * R, E2 = 15 * 15; let exN = 0;
    for (let k = 0; k < filtered.length; k++) {
      const i = filtered[k], y = D.lat[i], x = D.lon[i], gy = Math.floor(y / cell), gx = Math.floor(x / cell);
      let inR = false, same = false; const cl = Math.cos(y * Math.PI / 180);
      for (let a = -1; a <= 1 && !same; a++) for (let b = -1; b <= 1 && !same; b++) {
        const g = grid.get((gy + a) + '_' + (gx + b)); if (!g) continue;
        for (const c of g) { const dy = (c.lat - y) * mPerDegLat, dx = (c.lon - x) * mPerDegLat * cl, d = dx * dx + dy * dy; if (d <= R2) inR = true; if (ex && d <= E2 && c.method.indexOf('동 중심') < 0) { same = true; break; } }
      }
      if (same) { exN++; continue; } if (inR) ids.push(i);
    }
    setSel(ids, true); openSelPanel();
    flash(`고객 ${fmt(pts.length)}곳 반경 ${fmt(R)}m · ${fmt(ids.length)}개 선택${ex ? ` (같은 건물 ${fmt(exN)}개 제외)` : ''}`);
  };
  $('#bCustNts').onclick = async () => {
    const targets = cust.list.filter(c => c.biz && c.biz.length === 10);
    if (!targets.length) { toast('고객 파일에 유효한 10자리 사업자번호 열이 없습니다'); return; }
    showBusy(`🏛 국세청 API 사업자상태 ${fmt(targets.length)}건 조회 중…`, 0.3);
    try {
      const rows = await queryNtsStatus(targets.map(c => c.biz));
      if (!rows) return;
      const byBiz = new Map(rows.map(r => [r.b_no, r.b_stt || '미등록']));
      let closed = 0, paused = 0;
      for (const c of targets) {
        c.nts = byBiz.get(c.biz) || '';
        if (c.nts === '폐업자') closed++;
        else if (c.nts === '휴업자') paused++;
      }
      renderCust();
      toast(`국세청 조회 완료: 폐업 ${closed}건 · 휴업 ${paused}건`);
    } catch (err) { toast(`국세청 조회 오류: ${err.message}`); }
    finally { hideBusy(); }
  };
  $('#bCustExp').onclick = () => {
    const q = v => { v = v == null ? '' : String(v); return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
    const lines = ['\uFEFF' + [...cust.head, '위도', '경도', '매칭방법', '국세청상태'].map(q).join(',')];
    for (const c of cust.list) lines.push([...cust.head.map((_, i) => c.row[i]), c.lat ?? '', c.lon ?? '', c.method, c.nts || ''].map(q).join(','));
    download(lines.join('\r\n') + '\r\n', `${(cust.fname || '고객').replace(/\.[^.]+$/, '')}_좌표.csv`);
  };
  let vwRun = false;
  $('#bCustVw').onclick = async () => {
    if (vwRun) { vwRun = false; return; }
    if (!getVWorldKey()) { toast('브이월드 인증키를 먼저 확인하세요'); return; }
    const fails = cust.list.filter(c => (c.method === '실패' || c.method.includes('근사')) && c.addr);
    if (!fails.length) return alert('브이월드로 보완할 실패/근사 건이 없습니다.');
    if (!confirm(`실패·근사 ${fails.length}건을 브이월드 도로명·지번 API로 정밀 지오코딩합니다. 진행할까요?`)) return;
    vwRun = true; $('#bCustVw').textContent = '■ 중지'; let ok = 0, k = 0;
    for (const c of fails) {
      if (!vwRun) break;
      k++; flash(`🇰🇷 브이월드 보완 ${k}/${fails.length} · 성공 ${ok}`);
      const r = await vwGeocodeAddr(c.p.clean || c.addr);
      if (r) { c.lat = r.lat; c.lon = r.lon; c.method = r.type; ok++; }
      await new Promise(res => setTimeout(res, 160));
    }
    vwRun = false; $('#bCustVw').textContent = '🇰🇷 브이월드 정밀 보완';
    renderCust(); fitCust();
    flash(`🇰🇷 브이월드 정밀 보완 완료 · ${ok}/${fails.length}건 성공`);
  };
  let osmRun = false;
  $('#bOsm').onclick = async () => {
    if (osmRun) { osmRun = false; return; }
    const fails = cust.list.filter(c => c.method === '실패' && c.addr);
    if (!fails.length) return alert('보완할 실패 건이 없습니다.');
    if (!confirm(`실패 ${fails.length}건을 OpenStreetMap에서 1초에 1건씩 검색합니다. 진행할까요?`)) return;
    osmRun = true; $('#bOsm').textContent = '■ 중지'; let ok = 0, k = 0;
    for (const c of fails) {
      if (!osmRun) break; k++; flash(`온라인 보완 ${k}/${fails.length} · 성공 ${ok}`);
      try { const r = await osmSearch(c.p.clean || c.addr, 1); if (r[0]) { c.lat = +r[0].lat; c.lon = +r[0].lon; c.method = 'OSM'; ok++; } }
      catch { alert('온라인 검색 실패'); break; }
      await new Promise(r => setTimeout(r, 1100));
    }
    osmRun = false; $('#bOsm').textContent = '🌐 OSM 보완'; renderCust(); flash(`온라인 보완 완료 · ${ok}건 찾음`);
  };

  // Quarter Comparison
  $('#bdrop').onclick = () => $('#baseIn').click();
  $('#baseIn').onchange = () => { const fs = [...$('#baseIn').files]; $('#baseIn').value = ''; loadBaseline(fs); };
  $$('[data-cm]').forEach(btn => btn.onclick = () => setColorMode(btn.dataset.cm));
  $$('[data-sv]').forEach(btn => btn.onclick = () => { const v = btn.dataset.sv; sel.st = v === 'all' ? new Set() : new Set(v.split('').map(Number)); if (colorMode !== 'st' && v !== 'all') colorMode = 'st'; syncCmpButtons(); refilter(); });
  $('#cmpReg').onclick = e => { const tr = e.target.closest('[data-go2]'); if (!tr) return; const [f, k] = tr.dataset.go2.split(':'); const ce = getCentroids(); map.setView([ce[f].y[+k], ce[f].x[+k]], f === 'sgg' ? 13 : 15); };
  $('#bExpNew').onclick = () => { const b = computeFilter('st'), ids = []; for (let k = 0; k < b.length; k++) if (D.codes.st[b[k]] === 1) ids.push(b[k]); if (!ids.length) return alert('신규 개업 업소가 없습니다.'); exportCSV(ids, `신규개업_${CMP.baseYM}-${CMP.curYM}`); };
  $('#bExpClosed').onclick = () => { const b = computeFilter('st'), ids = []; for (let k = 0; k < b.length; k++) if (D.codes.st[b[k]] === 2) ids.push(b[k]); if (!ids.length) return alert('폐업 업소가 없습니다.'); exportCSV(ids, `폐업_${CMP.baseYM}-${CMP.curYM}`); };
  const normName = s => String(s || '').replace(/\(주\)|㈜|주식회사|\(유\)|유한회사|\s|[()\[\]·.,\-_]/g, '').toLowerCase();
  $('#bRisk').onclick = () => {
    const pts = cust.list.filter(c => c.lat != null && c.method.indexOf('동 중심') < 0);
    if (!pts.length) return alert('[고객] 탭에서 고객 파일을 먼저 지오코딩하세요.');
    const closed = []; for (let i = 0; i < D.N; i++) if (D.codes.st[i] === 2) closed.push(i);
    const risk = [];
    for (const c of pts) {
      c.risk = null; const nn = normName(c.name); if (nn.length < 2) continue;
      const near = nearIds(c.lat, c.lon, 20, closed);
      const hit = near.find(i => { const sn = normName(S(i).name); return sn.length >= 2 && (sn.indexOf(nn) >= 0 || nn.indexOf(sn) >= 0); });
      if (hit != null) { c.risk = hit; risk.push(c); }
    }
    renderCust();
    $('#riskList').innerHTML = `<div style="font-weight:700;margin:4px 0">폐업 의심 고객 ${fmt(risk.length)}명 / 정확 위치 ${fmt(pts.length)}명</div>` +
      (risk.length ? `<button id="bRiskExp" style="margin-bottom:6px">⤓ 폐업 의심 고객 CSV</button>` : '') +
      risk.slice(0, 200).map(c => `<div class="li" data-cgo="${c.k}"><span class="bdg bc">폐업</span><div class="t"><div class="a">${esc(c.name)}</div><div class="b">${esc(c.addr)} · 폐업 업소: ${esc(S(c.risk).name)}</div></div></div>`).join('');
    const ex = $('#bRiskExp');
    if (ex) ex.onclick = () => {
      const q = v => { v = v == null ? '' : String(v); return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
      const lines = ['\uFEFF' + [...cust.head, '위도', '경도', '폐업업소명', '폐업업소번호'].map(q).join(',')];
      for (const c of risk) lines.push([...cust.head.map((_, i) => c.row[i]), c.lat, c.lon, S(c.risk).name, S(c.risk).id].map(q).join(','));
      download(lines.join('\r\n') + '\r\n', `고객_폐업의심_${CMP.baseYM}-${CMP.curYM}.csv`);
    };
    flash(`폐업 의심 고객 ${fmt(risk.length)}명`);
  };
  $('#riskList').onclick = e => {
    const it = e.target.closest('[data-cgo]'); if (!it) return;
    const c = cust.list.find(x => x.k === +it.dataset.cgo); if (!c) return;
    map.setView([c.lat, c.lon], 18); L.popup({ maxWidth: 360 }).setLatLng([c.lat, c.lon]).setContent(custPopup(c)).openOn(map);
  };
  $('#bCustNew').onclick = () => {
    if (!cust.list.some(c => c.lat != null)) return alert('[고객] 탭에서 고객 파일을 먼저 지오코딩하세요.');
    sel.st = new Set([1]); colorMode = 'st'; syncCmpButtons(); applyFilter(); renderFilterUI(); $('#bCustRad').click();
  };

  // View List & Export & File Drag/Drop
  $('#vlist').onclick = e => {
    const ck = e.target.closest('[data-ck]'); if (ck) { setSel([+ck.dataset.ck], ck.checked); return; }
    const g = e.target.closest('[data-go]'); if (g) goTo(+g.dataset.go);
  };
  $('#bSelView').onclick = () => {
    const ids = inViewIds();
    if (ids.length > 50000 && !confirm(`${fmt(ids.length)}개를 선택할까요?`)) return;
    setSel(ids, true); flash(`화면 안 ${fmt(ids.length)}개 선택`); renderViewList();
  };
  $('#bExportFilt').onclick = () => {
    if (!filtered.length) return;
    if (filtered.length > 1000000 && !confirm(`${fmt(filtered.length)}건 — 엑셀 행 한도(1,048,576)를 넘습니다. 그래도 저장할까요?`)) return;
    exportCSV(filtered, '필터결과');
  };
  $('#bReset').onclick = () => { if (confirm('불러온 데이터를 모두 비울까요?')) location.reload(); };

  const fileIn = $('#fileIn');
  $('#drop').onclick = () => fileIn.click();
  $('#bOpen2').onclick = () => fileIn.click();
  fileIn.onchange = () => { const fs = [...fileIn.files]; fileIn.value = ''; loadFiles(fs); };
  ['dragenter', 'dragover'].forEach(t => document.addEventListener(t, e => { e.preventDefault(); $('#drop')?.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(t => document.addEventListener(t, e => { e.preventDefault(); if (t === 'drop' || !e.relatedTarget) $('#drop')?.classList.remove('over'); }));
  document.addEventListener('drop', e => {
    if (!$('#lockScreen').hidden) return;
    const fs = e.dataTransfer ? [...e.dataTransfer.files] : []; if (!fs.length) return;
    const cf = fs.filter(f => /\.(xlsx?|xls)$/i.test(f.name));
    const df = fs.filter(f => /\.(csv|zip)$/i.test(f.name));
    if (cf.length || (curTab === 'cust' && df.length === 1 && /\.csv$/i.test(df[0].name))) { readCust(cf[0] || df[0]); switchTab('cust'); return; }
    if (curTab === 'cmp') { loadBaseline(df); return; }
    loadFiles(df);
  });

  syncApiKeyUI();
  window.__D = D; window.__map = map;
  window.__api = { loadVaultSido, runApiHealthCheck, fetchSdscStores, queryNtsStatus, sameBuildingIds, VAULT_SUMMARY: () => VAULT_SUMMARY };
}

/* ==================== Boot Flow & Vault Unlock ==================== */
async function bootWithKey(key) {
  VAULT_KEY = key;
  $('#lockScreen').hidden = true;
  $('#loader').hidden = false;
  const bar = $('#lbar'), txt = $('#ltxt');
  try {
    bar.style.width = '30%';
    txt.textContent = '전국 상권 요약 메타 복호화 중…';
    VAULT_SUMMARY = await fetchDecJson('summary');
    bar.style.width = '75%';
    txt.textContent = '지도 엔진 및 API 연동 준비 중…';

    $('#appShell').hidden = false;
    initAppUI();
    renderVaultSidoGrids();

    const cachedApi = await idb.get('live_api_stores');
    if (Array.isArray(cachedApi) && cachedApi.length) {
      ingestSdscItems(cachedApi, `캐시된 실시간 API (${fmt(cachedApi.length)}건)`, false);
    }

    bar.style.width = '100%';
    setTimeout(() => {
      $('#loader').hidden = true;
      map && map.invalidateSize();
    }, 120);
  } catch (err) {
    console.error(err);
    txt.textContent = '복호화 실패: ' + err.message;
    await idb.delKey();
  }
}

async function initVault() {
  if ('serviceWorker' in navigator && location.protocol !== 'file:') {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }
  let deferredPrompt = null;
  window.addEventListener('beforeinstallprompt', e => {
    e.preventDefault(); deferredPrompt = e;
    const btn = $('#pwaInstallBtn');
    if (btn) {
      btn.hidden = false;
      btn.onclick = async () => {
        if (!deferredPrompt) return;
        deferredPrompt.prompt(); await deferredPrompt.userChoice;
        deferredPrompt = null; btn.hidden = true;
      };
    }
  });

  $('#pwToggle').onclick = () => {
    const inp = $('#pwInput');
    inp.type = inp.type === 'password' ? 'text' : 'password';
  };

  try {
    const res = await fetch('./data/vault.json', { cache: 'no-cache' });
    if (!res.ok) throw new Error('vault.json 로드 실패 (HTTP ' + res.status + ')');
    VAULT_META = await res.json();
  } catch (err) {
    $('#lockErr').textContent = location.protocol === 'file:'
      ? '로컬 서버로 실행해 주세요: python3 -m http.server 8768'
      : 'Vault 메타 정보를 불러올 수 없습니다: ' + err.message;
    return;
  }

  const saved = await idb.getKey();
  if (saved && saved.salt === VAULT_META.salt && saved.key) {
    if (await verifyKey(saved.key, VAULT_META)) {
      await bootWithKey(saved.key);
      return;
    }
    await idb.delKey();
  }

  $('#pwInput').focus();
  $('#lockForm').onsubmit = async e => {
    e.preventDefault();
    const pw = $('#pwInput').value, errEl = $('#lockErr'), btn = $('#pwSubmit');
    if (!pw) return;
    errEl.textContent = ''; btn.disabled = true; btn.textContent = '키 검증 중…';
    try {
      const key = await deriveVaultKey(pw, VAULT_META.salt, VAULT_META.iter);
      if (!(await verifyKey(key, VAULT_META))) {
        errEl.textContent = '비밀번호가 일치하지 않습니다.';
        btn.disabled = false; btn.textContent = '잠금 해제';
        $('#pwInput').select();
        return;
      }
      if ($('#pwRemember').checked) await idb.setKey({ salt: VAULT_META.salt, key });
      $('#pwInput').value = '';
      await bootWithKey(key);
    } catch (err) {
      errEl.textContent = '인증 오류: ' + err.message;
      btn.disabled = false; btn.textContent = '잠금 해제';
    }
  };
}

initVault();
})();
