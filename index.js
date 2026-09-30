#!/usr/bin/env node
'use strict';
/**
 * Node.js 版本（由 Python 版移植，功能对等）
 * 需要 Node.js >= 18（用到全局 fetch 和 fs.statfsSync）
 * 需要系统已安装 openssl（生成/兜底 TLS 证书）与 unzip（解压 Xray-core 官方发行包）
 * 依赖：仅 `ws`（WebSocket 客户端），运行前请先 `npm install`
 */

const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const http = require('http');
const { URL, URLSearchParams } = require('url');
const { execFile, execFileSync, spawn } = require('child_process');
const { promisify } = require('util');
const { pipeline } = require('stream/promises');
// ws 是可选依赖:装不上/没装时不再让整个程序崩溃,自动降级成纯 POST 轮询上报
let WebSocket = null;
let WS_AVAILABLE = false;
try {
  WebSocket = require('ws');
  WS_AVAILABLE = true;
} catch (_) {
  WS_AVAILABLE = false;
}

const execFileP = promisify(execFile);

// =========================== 环境变量 ===========================
const env = process.env;
const NAME = env.NAME || '';
let UUID = env.UUID || '';
const S5_PORT = env.S5_PORT || '';
const HY2_PORT = env.HY2_PORT || '';
const REALITY_PORT = env.REALITY_PORT || '';

const ENABLE_ARGO = !['false', '0', 'no', 'disable'].includes((env.ENABLE_ARGO || 'true').toLowerCase());
const ARGO_DOMAIN = env.ARGO_DOMAIN || '';
const ARGO_AUTH = env.ARGO_AUTH || '';
const ARGO_PORT = parseInt(env.ARGO_PORT || '8001', 10);

const WS_PORT = env.WS_PORT || '';
const CDN_DOMAIN = env.CDN_DOMAIN || '';
const DIRECT_WS_PORT = env.DIRECT_WS_PORT || '443';

const UPLOAD_URL = env.UPLOAD_URL || '';
const PROJECT_URL = env.PROJECT_URL || '';
const AUTO_ACCESS = (env.AUTO_ACCESS || '').toLowerCase() === 'true';
let FILE_PATH_RAW = env.FILE_PATH || '.cache';
const SUB_PATH = env.SUB_PATH || 'sub';
const CFIP = env.CFIP || 'cf.877774.xyz';
const CFPORT = parseInt(env.CFPORT || '443', 10);
const CHAT_ID = env.CHAT_ID || '';
const BOT_TOKEN = env.BOT_TOKEN || '';
const PORT = parseInt(env.PORT || '3000', 10);
const SHOW_LOG = !['false', 'disable', 'no'].includes((env.SHOW_LOG || 'no').toLowerCase());

const CERT_B64 = env.CERT_B64 || '';
const KEY_B64 = env.KEY_B64 || '';
const BOT_VERSION = env.BOT_VERSION || 'latest';
const WEB_VERSION = env.WEB_VERSION || 'latest';

const PROBE_ID = env.PROBE_ID || '';
const PROBE_SECRET = env.PROBE_SECRET || '';
const PROBE_URL = env.PROBE_URL || '';
const PROBE_INTERVAL = parseInt(env.PROBE_INTERVAL || '60', 10);
const PROBE_CT = env.PROBE_CT || 'gd-ct-dualstack.ip.zstaticcdn.com';
const PROBE_CU = env.PROBE_CU || 'gd-cu-dualstack.ip.zstaticcdn.com';
const PROBE_CM = env.PROBE_CM || 'gd-cm-dualstack.ip.zstaticcdn.com';
const PROBE_PING_COUNT = parseInt(env.PROBE_PING_COUNT || '2', 10);
const PROBE_PING_TIMEOUT = parseFloat(env.PROBE_PING_TIMEOUT || '1.0'); // 秒
const PROBE_IP_REFRESH_INTERVAL = parseInt(env.PROBE_IP_REFRESH_INTERVAL || '1800', 10); // 秒
const PROBE_WSS = !['false', '0', 'no', 'disable'].includes((env.PROBE_WSS || 'true').toLowerCase());
const PROBE_PING_CACHE_TTL = parseInt(env.PROBE_PING_CACHE_TTL || '120', 10); // 秒
const PROBE_AGENT_VERSION = env.PROBE_AGENT_VERSION || 'nodejs';

// =========================== 日志 ===========================
function log(msg) { if (SHOW_LOG) console.log(msg); }
function logError(msg) { if (SHOW_LOG) console.error(msg); }
function alwaysLog(msg) { process.stdout.write(msg + '\n'); }

// =========================== 全局变量 / 路径 ===========================
let privateKeyB64 = '';
let publicKeyB64 = '';
let subTxtContent = '';

const FILE_PATH = path.resolve(FILE_PATH_RAW);

function randomName(length = 6) {
  const chars = 'abcdefghijklmnopqrstuvwxyz';
  let out = '';
  for (let i = 0; i < length; i++) out += chars[crypto.randomInt(chars.length)];
  return out;
}

const webName = randomName();
const botName = randomName();

const webPath = path.join(FILE_PATH, webName);
const botPath = path.join(FILE_PATH, botName);
const subPath = path.join(FILE_PATH, 'sub.txt');
const listPath = path.join(FILE_PATH, 'list.txt');
const bootLogPath = path.join(FILE_PATH, 'boot.log');
const configPath = path.join(FILE_PATH, 'config.json');
const certPath = path.join(FILE_PATH, 'cert.pem');
const keyPath = path.join(FILE_PATH, 'private.key');
const keyTxtPath = path.join(FILE_PATH, 'key.txt');

// =========================== 工具函数 ===========================
function isValidPort(port) {
  if (port === null || port === undefined || port === '') return false;
  const n = Number(port);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

function b64(input) {
  return Buffer.from(input).toString('base64');
}
function b64url(buf) {
  return buf.toString('base64url');
}
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function safeUnlink(p) {
  try { await fsp.unlink(p); } catch (_) { /* ignore */ }
}

async function pathExists(p) {
  try { await fsp.access(p); return true; } catch (_) { return false; }
}

// =========================== X25519 密钥对（用于 Reality） ===========================
function generateX25519Keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  // SPKI/PKCS8 DER 里 X25519 的原始 32 字节 key 固定在末尾，直接切片即可
  const rawPub = publicKey.subarray(publicKey.length - 32);
  const rawPriv = privateKey.subarray(privateKey.length - 32);
  return { privateKey: b64url(rawPriv), publicKey: b64url(rawPub) };
}

async function generateOrLoadKeypair() {
  if (await pathExists(keyTxtPath)) {
    const content = await fsp.readFile(keyTxtPath, 'utf-8');
    const priv = content.match(/PrivateKey:\s*(.*)/);
    const pub = content.match(/PublicKey:\s*(.*)/);
    if (priv && pub) {
      privateKeyB64 = priv[1].trim();
      publicKeyB64 = pub[1].trim();
      log(`Private Key: ${privateKeyB64}`);
      log(`Public Key: ${publicKeyB64}`);
      return;
    }
  }
  const kp = generateX25519Keypair();
  privateKeyB64 = kp.privateKey;
  publicKeyB64 = kp.publicKey;
  await fsp.writeFile(keyTxtPath, `PrivateKey: ${privateKeyB64}\nPublicKey: ${publicKeyB64}\n`, 'utf-8');
  log(`Private Key: ${privateKeyB64}`);
  log(`Public Key: ${publicKeyB64}`);
}

// =========================== TLS 证书 ===========================
// 与原 Python 版一致的兜底证书/私钥（极端情况下 openssl 不可用/生成失败时使用）
const FALLBACK_EC_KEY = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49
AwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa
/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==
-----END EC PRIVATE KEY-----
`;
const FALLBACK_CERT = `-----BEGIN CERTIFICATE-----
MIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw
EzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy
MDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h
aD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR
BfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+
eQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==
-----END CERTIFICATE-----
`;

async function ensureTlsCertificates() {
  await fsp.mkdir(path.dirname(certPath), { recursive: true });

  if (CERT_B64 && KEY_B64) {
    try {
      await fsp.writeFile(certPath, Buffer.from(CERT_B64, 'base64'));
      await fsp.writeFile(keyPath, Buffer.from(KEY_B64, 'base64'));
      log('Using custom certificate from CERT_B64/KEY_B64');
      return;
    } catch (e) {
      logError(`Failed to decode CERT_B64/KEY_B64, falling back to self-signed: ${e}`);
    }
  }

  if (await pathExists(certPath) && await pathExists(keyPath)) return;

  try {
    // 走 openssl 生成自签 EC 证书（CN=bing.com，与 Hysteria2/direct-ws 节点里的 SNI 对应）
    execFileSync('openssl', ['ecparam', '-genkey', '-name', 'prime256v1', '-noout', '-out', keyPath], { stdio: 'ignore' });
    execFileSync('openssl', [
      'req', '-new', '-x509', '-key', keyPath, '-out', certPath,
      '-days', '3650', '-subj', '/CN=bing.com',
    ], { stdio: 'ignore' });
  } catch (e) {
    logError(`Failed to generate TLS certificate via openssl: ${e.message}`);
    await fsp.writeFile(keyPath, FALLBACK_EC_KEY, 'utf-8');
    await fsp.writeFile(certPath, FALLBACK_CERT, 'utf-8');
  }
}

function pemToDer(pem) {
  const b64Body = pem.replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s+/g, '');
  return Buffer.from(b64Body, 'base64');
}

async function getCertificateFingerprint(certFile) {
  // 优先纯 JS 实现：对证书 DER 字节做 SHA256，无需依赖 openssl
  try {
    const pem = await fsp.readFile(certFile, 'utf-8');
    const der = pemToDer(pem);
    const digest = crypto.createHash('sha256').update(der).digest();
    return Array.from(digest).map((b) => b.toString(16).toUpperCase().padStart(2, '0')).join(':');
  } catch (e) {
    logError(`Failed to calculate certificate fingerprint: ${e.message}`);
    return '';
  }
}

// =========================== 目录/清理 ===========================
async function createDirectory() {
  if (!SHOW_LOG) process.stdout.write('\x1bc');
  await fsp.mkdir(FILE_PATH, { recursive: true });
}

async function deleteNodes() {
  try {
    if (!UPLOAD_URL) return;
    if (!(await pathExists(subPath))) return;
    const content = await fsp.readFile(subPath, 'utf-8');
    const decoded = Buffer.from(content, 'base64').toString('utf-8');
    const nodes = decoded.split('\n').filter((l) => /^(vless|vmess|trojan|hysteria2|socks):\/\//.test(l));
    if (!nodes.length) return;
    await fetch(`${UPLOAD_URL}/api/delete-nodes`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nodes }), signal: AbortSignal.timeout(10000),
    });
  } catch (_) { /* ignore */ }
}

async function cleanupOldFiles() {
  const preserve = new Set([keyTxtPath, certPath, keyPath]);
  try {
    const items = await fsp.readdir(FILE_PATH);
    for (const name of items) {
      const p = path.join(FILE_PATH, name);
      if (preserve.has(p)) continue;
      try {
        const st = await fsp.lstat(p);
        if (st.isDirectory()) await fsp.rm(p, { recursive: true, force: true });
        else await fsp.unlink(p);
      } catch (_) { /* ignore */ }
    }
  } catch (_) { /* ignore */ }
}

// =========================== 架构判断 ===========================
function getSystemArchitecture() {
  const arch = os.arch(); // 'x64' | 'arm64' | 'arm' ...
  if (arch === 'arm64' || arch === 'arm') return 'arm';
  return 'amd';
}

// =========================== 下载 ===========================
async function downloadFile(fileName, fileUrl) {
  const filePath = path.join(FILE_PATH, fileName);
  try {
    const res = await fetch(fileUrl, { redirect: 'follow', signal: AbortSignal.timeout(180000) });
    if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
    await pipeline(res.body, fs.createWriteStream(filePath));
    log(`Download ${fileName} successfully`);
    return true;
  } catch (e) {
    logError(`Download ${fileName} failed: ${e.message}`);
    await safeUnlink(filePath);
    return false;
  }
}

async function downloadCloudflaredOfficial(archGh) {
  const version = BOT_VERSION || 'latest';
  const url = version === 'latest'
    ? `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${archGh}`
    : `https://github.com/cloudflare/cloudflared/releases/download/${version}/cloudflared-linux-${archGh}`;
  log(`Downloading cloudflared (${version}) from official source: ${url}`);
  return downloadFile(botName, url);
}

async function downloadWebOfficial(archZip) {
  const version = WEB_VERSION || 'latest';
  const url = version === 'latest'
    ? `https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${archZip}.zip`
    : `https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-${archZip}.zip`;
  log(`Downloading Xray-core (${version}) from official source: ${url}`);

  const zipName = `${webName}.zip`;
  if (!(await downloadFile(zipName, url))) return false;

  const zipPath = path.join(FILE_PATH, zipName);
  let fd = null;
  try {
    // 用系统 unzip 把压缩包里的 xray 单文件解出来（等价于原版用 zipfile 模块解包）
    fd = fs.openSync(webPath, 'w');
    execFileSync('unzip', ['-p', zipPath, 'xray'], { stdio: ['ignore', fd, 'ignore'] });
    return true;
  } catch (e) {
    logError(`Failed to extract Xray-core zip: ${e.message}`);
    return false;
  } finally {
    // 关键修复：自己 openSync 出来的 fd 传给子进程后 Node 不会自动关闭,
    // 必须手动 close,否则解压完立刻 spawn 执行这个文件会报 ETXTBSY(文件被占用)
    if (fd !== null) { try { fs.closeSync(fd); } catch (_) { /* ignore */ } }
    await safeUnlink(zipPath);
  }
}

async function downloadAllFiles() {
  const architecture = getSystemArchitecture();
  let baseUrls, archGh, archZip;
  if (architecture === 'arm') {
    baseUrls = ['https://arm64.oooen.com', 'https://arm64.ssss.nyc.mn'];
    archGh = 'arm64'; archZip = 'arm64-v8a';
  } else {
    baseUrls = ['https://amd64.oooen.com', 'https://amd64.ssss.nyc.mn'];
    archGh = 'amd64'; archZip = '64';
  }

  const downloads = [];
  if (!WEB_VERSION) downloads.push({ name: webName, path: 'web' });
  if (ENABLE_ARGO && !BOT_VERSION) downloads.push({ name: botName, path: 'bot' });

  for (const item of downloads) {
    let downloaded = false;
    for (let i = 0; i < baseUrls.length; i++) {
      const url = `${baseUrls[i]}/${item.path}`;
      if (await downloadFile(item.name, url)) { downloaded = true; break; }
      if (i + 1 < baseUrls.length) log(`Retrying ${item.name} from backup source`);
    }
    if (!downloaded) logError(`Error downloading ${item.name}: all sources failed`);
  }

  if (WEB_VERSION) {
    if (!(await downloadWebOfficial(archZip))) {
      logError('Xray-core official download failed, falling back to mirror');
      for (const baseUrl of baseUrls) {
        if (await downloadFile(webName, `${baseUrl}/web`)) break;
      }
    }
  }

  if (ENABLE_ARGO && BOT_VERSION) {
    if (!(await downloadCloudflaredOfficial(archGh))) {
      logError('cloudflared official download failed, falling back to mirror');
      for (const baseUrl of baseUrls) {
        if (await downloadFile(botName, `${baseUrl}/bot`)) break;
      }
    }
  }
}

async function authorizeFiles(fileNames) {
  for (const name of fileNames) {
    const p = path.join(FILE_PATH, name);
    if (await pathExists(p)) {
      try {
        await fsp.chmod(p, 0o775);
        log(`Empowerment success for ${name}: 775`);
      } catch (e) {
        logError(`Empowerment failed for ${name}: ${e.message}`);
      }
    }
  }
}

// =========================== Argo 隧道配置 ===========================
async function argoType() {
  if (!ENABLE_ARGO) { log('ENABLE_ARGO is false, skip Argo tunnel setup'); return; }
  if (!ARGO_AUTH || !ARGO_DOMAIN) { log('ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels'); return; }

  if (ARGO_AUTH.includes('TunnelSecret')) {
    const tunnelJsonPath = path.join(FILE_PATH, 'tunnel.json');
    await fsp.writeFile(tunnelJsonPath, ARGO_AUTH, 'utf-8');
    const tunnelId = ARGO_AUTH.split('"')[11];
    const tunnelYaml = `
tunnel: ${tunnelId}
credentials-file: ${tunnelJsonPath}
protocol: http2

ingress:
  - hostname: ${ARGO_DOMAIN}
    service: http://localhost:${ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
`;
    await fsp.writeFile(path.join(FILE_PATH, 'tunnel.yml'), tunnelYaml, 'utf-8');
  } else {
    log(`Using token connect to tunnel, please set ${ARGO_PORT} in cloudflare`);
  }
}

// =========================== Xray 配置生成 ===========================
async function generateXrayConfig() {
  const config = {
    log: { access: '/dev/null', error: '/dev/null', loglevel: 'none' },
    inbounds: [],
    dns: { servers: ['https+local://8.8.8.8/dns-query'] },
    outbounds: [
      { protocol: 'freedom', tag: 'direct' },
      { protocol: 'blackhole', tag: 'block' },
    ],
  };

  if (ENABLE_ARGO) {
    config.inbounds.push(
      {
        tag: 'vless-fallback-in', listen: '::', port: ARGO_PORT, protocol: 'vless',
        settings: {
          clients: [{ id: UUID, flow: 'xtls-rprx-vision' }], decryption: 'none',
          fallbacks: [
            { dest: 51001 },
            { path: '/vless-argo', dest: 51002 },
            { path: '/vmess-argo', dest: 51003 },
            { path: '/trojan-argo', dest: 51004 },
          ],
        },
        streamSettings: { network: 'tcp' },
      },
      {
        tag: 'vless-tcp-in', port: 51001, listen: '127.0.0.1', protocol: 'vless',
        settings: { clients: [{ id: UUID }], decryption: 'none' },
        streamSettings: { network: 'tcp', security: 'none' },
      },
      {
        tag: 'vless-ws-in', port: 51002, listen: '127.0.0.1', protocol: 'vless',
        settings: { clients: [{ id: UUID, level: 0 }], decryption: 'none' },
        streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/vless-argo' } },
        sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], metadataOnly: false },
      },
      {
        tag: 'vmess-ws-in', port: 51003, listen: '127.0.0.1', protocol: 'vmess',
        settings: { clients: [{ id: UUID, alterId: 0 }] },
        streamSettings: { network: 'ws', wsSettings: { path: '/vmess-argo' } },
        sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], metadataOnly: false },
      },
      {
        tag: 'trojan-ws-in', port: 51004, listen: '127.0.0.1', protocol: 'trojan',
        settings: { clients: [{ password: UUID }] },
        streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/trojan-argo' } },
        sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], metadataOnly: false },
      },
    );
  }

  if (isValidPort(REALITY_PORT)) {
    config.inbounds.push({
      tag: 'vless-reality-in', listen: '::', port: Number(REALITY_PORT), protocol: 'vless',
      settings: { clients: [{ id: UUID, flow: 'xtls-rprx-vision' }], decryption: 'none' },
      streamSettings: {
        network: 'raw', security: 'reality',
        realitySettings: {
          show: false, dest: 'www.iij.ad.jp:443', xver: 0,
          serverNames: ['www.iij.ad.jp'], privateKey: privateKeyB64, shortIds: [''],
        },
      },
    });
  }

  if (isValidPort(HY2_PORT)) {
    config.inbounds.push({
      tag: 'hysteria-in', listen: '::', port: Number(HY2_PORT), protocol: 'hysteria',
      settings: { version: 2, clients: [{ auth: UUID }] },
      streamSettings: {
        network: 'hysteria',
        hysteriaSettings: { version: 2, masquerade: { type: 'proxy', url: 'https://bing.com' } },
        security: 'tls',
        tlsSettings: { alpn: ['h3'], certificates: [{ certificateFile: certPath, keyFile: keyPath }] },
      },
    });
  }

  if (isValidPort(S5_PORT)) {
    config.inbounds.push({
      tag: 's5-in', listen: '::', port: Number(S5_PORT), protocol: 'socks',
      settings: {
        auth: 'password',
        accounts: [{ user: UUID.slice(0, 8), pass: UUID.slice(-12) }],
        udp: true,
      },
    });
  }

  if (isValidPort(WS_PORT)) {
    config.inbounds.push({
      tag: 'vless-ws-plain-in', listen: '::', port: Number(WS_PORT), protocol: 'vless',
      settings: { clients: [{ id: UUID, level: 0 }], decryption: 'none' },
      streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/vless-ws' } },
      sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], metadataOnly: false },
    });
  }

  if (CDN_DOMAIN && isValidPort(DIRECT_WS_PORT)) {
    if (Number(DIRECT_WS_PORT) < 1024) {
      log(`警告: DIRECT_WS_PORT=${DIRECT_WS_PORT} 是特权端口, 非root用户下Xray可能绑定失败`
        + `(且会导致同进程内其它协议一起起不来); 如遇节点无法连接, 请改用>=1024的端口排查`);
    }
    config.inbounds.push({
      tag: 'vless-ws-tls-in', listen: '::', port: Number(DIRECT_WS_PORT), protocol: 'vless',
      settings: { clients: [{ id: UUID, level: 0 }], decryption: 'none' },
      streamSettings: {
        network: 'ws', security: 'tls', wsSettings: { path: '/vless-ws' },
        tlsSettings: { alpn: ['http/1.1'], certificates: [{ certificateFile: certPath, keyFile: keyPath }] },
      },
      sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], metadataOnly: false },
    });
  }

  await fsp.writeFile(configPath, JSON.stringify(config, null, 2), 'utf-8');
}

// =========================== 进程管理 ===========================
// 直接持有子进程句柄来管理生命周期,不依赖 pkill 这类外部二进制
// (非 root/精简容器镜像常常没有装 procps,没有 pkill 命令)
let webProc = null;
let botProc = null;

function spawnTracked(command, args) {
  try {
    const child = spawn(command, args, { detached: true, stdio: 'ignore' });
    child.unref();
    child.on('error', (e) => logError(`Error executing command: ${e.message}`));
    return child;
  } catch (e) {
    logError(`Error executing command: ${e.message}`);
    return null;
  }
}

function killTracked(child) {
  if (!child || child.killed || child.exitCode !== null) return;
  try { process.kill(-child.pid, 'SIGTERM'); } catch (_) {
    // 拿不到进程组(比如非 Linux 或没有 setsid 权限)时,退回只杀这一个 PID
    try { child.kill('SIGTERM'); } catch (_) { /* ignore */ }
  }
}

async function downloadFilesAndRun() {
  await downloadAllFiles();

  const toAuthorize = [webName];
  if (ENABLE_ARGO) toAuthorize.push(botName);
  await authorizeFiles(toAuthorize);

  webProc = spawnTracked(webPath, ['-c', configPath]);
  log(`${webName} is running`);
  await sleep(1000);

  if (ENABLE_ARGO && await pathExists(botPath)) {
    let args;
    if (/^[A-Z0-9a-z=]{120,250}$/.test(ARGO_AUTH)) {
      args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2', 'run', '--token', ARGO_AUTH];
    } else if (ARGO_AUTH.includes('TunnelSecret')) {
      args = ['tunnel', '--edge-ip-version', 'auto', '--config', path.join(FILE_PATH, 'tunnel.yml'), 'run'];
    } else {
      args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2',
        '--logfile', bootLogPath, '--loglevel', 'info', '--url', `http://localhost:${ARGO_PORT}`];
    }
    botProc = spawnTracked(botPath, args);
    log(`${botName} is running`);
    await sleep(2000);
  }

  await sleep(5000);
}

// =========================== 提取隧道域名 ===========================
async function extractDomains(retriesLeft = 5) {
  if (!ENABLE_ARGO) {
    log('ENABLE_ARGO is false, skip Argo domain extraction');
    await generateLinks(null);
    return;
  }

  if (ARGO_AUTH && ARGO_DOMAIN) {
    log(`ARGO_DOMAIN: ${ARGO_DOMAIN}`);
    await generateLinks(ARGO_DOMAIN);
    return;
  }

  try {
    if (await pathExists(bootLogPath)) {
      const fileContent = await fsp.readFile(bootLogPath, 'utf-8');
      const lines = fileContent.split('\n');
      const argoDomains = [];
      for (const line of lines) {
        const m = line.match(/https?:\/\/([^ ]*trycloudflare\.com)\/?/);
        if (m) argoDomains.push(m[1]);
      }
      if (argoDomains.length) {
        log(`ArgoDomain: ${argoDomains[0]}`);
        await generateLinks(argoDomains[0]);
      } else {
        log('ArgoDomain not found, re-running bot to obtain ArgoDomain');
        await safeUnlink(bootLogPath);
        killTracked(botProc);

        if (retriesLeft <= 0) {
          // 与原版不同：这里加了重试上限，避免无限递归；超限后直接按无 Argo 域名生成其余节点
          logError('ArgoDomain still not found after max retries, giving up on Argo domain and generating remaining nodes');
          await generateLinks(null);
          return;
        }

        await sleep(3000);
        const args = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', 'http2',
          '--logfile', bootLogPath, '--loglevel', 'info', '--url', `http://localhost:${ARGO_PORT}`];
        botProc = spawnTracked(botPath, args);
        log(`${botName} is running`);
        await sleep(6000);
        await extractDomains(retriesLeft - 1);
      }
    } else {
      await generateLinks(null);
    }
  } catch (e) {
    logError(`Error reading boot.log: ${e.message}`);
    await generateLinks(null);
  }
}

// =========================== 获取 ISP 信息 ===========================
async function getMetaInfo() {
  try {
    const res = await fetch('https://api.ip.sb/geoip', {
      headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(3000),
    });
    const data = await res.json();
    if (data.country_code && data.isp) return `${data.country_code}-${data.isp}`.replace(/ /g, '_');
  } catch (_) { /* ignore */ }
  try {
    const res = await fetch('http://ip-api.com/json', {
      headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(3000),
    });
    const data = await res.json();
    if (data.status === 'success' && data.countryCode && data.org) {
      return `${data.countryCode}-${data.org}`.replace(/ /g, '_');
    }
  } catch (_) { /* ignore */ }
  return 'Unknown';
}

// =========================== 获取服务器公网 IP ===========================
function looksLikeIp(s) {
  return net.isIP(s) !== 0;
}

async function fetchPublicIpVersion(version = 'v4', timeoutMs = 3000) {
  const host = version === 'v4' ? 'ipv4.ip.sb' : 'ipv6.ip.sb';
  try {
    const res = await fetch(`http://${host}`, { signal: AbortSignal.timeout(timeoutMs) });
    const ip = (await res.text()).trim();
    if (ip && looksLikeIp(ip)) return ip;
  } catch (_) { /* ignore */ }
  try {
    const { stdout } = await execFileP('curl', ['-sm', String(Math.ceil(timeoutMs / 1000) + 2), host], { timeout: timeoutMs + 3000 });
    const ip = stdout.trim();
    if (ip && looksLikeIp(ip)) return ip;
  } catch (_) { /* ignore */ }
  return null;
}

async function getServerIp() {
  const v4 = await fetchPublicIpVersion('v4');
  if (v4) return v4;
  const v6 = await fetchPublicIpVersion('v6');
  if (v6) return `[${v6}]`;
  logError('Failed to get IP address');
  return null; // 调用方需要判空，不要把 null 直接拼进节点链接
}

// =========================== 生成节点链接 ===========================
async function generateLinks(argoDomain) {
  const isp = await getMetaInfo();
  const nodeName = NAME ? `${NAME}-${isp}` : isp;
  const serverIp = await getServerIp();
  const ipForLink = serverIp || '0.0.0.0'; // 拿不到公网 IP 时用占位符，至少不会写出字面 "null"

  await sleep(2000);

  let subTxt = '';

  if (ENABLE_ARGO && argoDomain) {
    subTxt += `\nvless://${UUID}@${CFIP}:${CFPORT}?encryption=none&security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Fvless-argo%3Fed%3D2560#${nodeName}-VLESS-Argo`;

    const vmessObj = {
      v: '2', ps: `${nodeName}-VMess-Argo`, add: CFIP, port: CFPORT,
      id: UUID, aid: '0', scy: 'auto', net: 'ws',
      type: 'none', host: argoDomain, path: '/vmess-argo?ed=2560',
      tls: 'tls', sni: argoDomain, alpn: '', fp: 'firefox',
    };
    subTxt += `\nvmess://${b64(JSON.stringify(vmessObj))}`;
    subTxt += `\ntrojan://${UUID}@${CFIP}:${CFPORT}?security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Ftrojan-argo%3Fed%3D2560#${nodeName}-Trojan-Argo`;
  }

  if (isValidPort(WS_PORT)) {
    subTxt += `\nvless://${UUID}@${ipForLink}:${WS_PORT}?encryption=none&security=none&type=ws&path=%2Fvless-ws#${nodeName}-VLESS-WS`;
  }

  if (CDN_DOMAIN && isValidPort(DIRECT_WS_PORT)) {
    subTxt += `\nvless://${UUID}@${CDN_DOMAIN}:${DIRECT_WS_PORT}?encryption=none&security=tls&sni=${CDN_DOMAIN}&fp=firefox&type=ws&host=${CDN_DOMAIN}&path=%2Fvless-ws#${nodeName}-VLESS-WS-TLS`;
  }

  if (isValidPort(HY2_PORT)) {
    const fingerprint = await getCertificateFingerprint(certPath);
    const fpParam = fingerprint ? `&pinSHA256=${encodeURIComponent(fingerprint)}` : '';
    subTxt += `\nhysteria2://${UUID}@${ipForLink}:${HY2_PORT}/?sni=bing.com&insecure=1&alpn=h3&obfs=none${fpParam}#${nodeName}-HY2`;
  }

  if (isValidPort(REALITY_PORT)) {
    subTxt += `\nvless://${UUID}@${ipForLink}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk=${publicKeyB64}&type=tcp&headerType=none#${nodeName}-Reality`;
  }

  if (isValidPort(S5_PORT)) {
    const s5Auth = b64(`${UUID.slice(0, 8)}:${UUID.slice(-12)}`);
    subTxt += `\nsocks://${s5Auth}@${ipForLink}:${S5_PORT}#${nodeName}-SOCKS5`;
  }

  const subTxtB64 = b64(subTxt);
  if (SHOW_LOG) {
    console.log(`\x1b[32m${subTxtB64}\x1b[0m`);
    console.log('\x1b[35mLogs will be deleted in 90 seconds, you can copy the above nodes\x1b[0m');
  }

  await fsp.writeFile(subPath, subTxtB64, 'utf-8');
  await fsp.writeFile(listPath, subTxt, 'utf-8');
  log(`${FILE_PATH}/sub.txt saved successfully`);

  subTxtContent = subTxtB64;
  return subTxt;
}

// =========================== Telegram 推送 ===========================
async function sendTelegram() {
  if (!BOT_TOKEN || !CHAT_ID) { log('TG variables is empty, Skipping push nodes to TG'); return; }
  try {
    const message = await fsp.readFile(subPath, 'utf-8');
    const escapedName = NAME.replace(/[_*[\]()~`>#+=|{}.!-]/g, '\\$&');
    const params = new URLSearchParams({
      chat_id: CHAT_ID,
      text: `**${escapedName}节点推送通知**\n\`\`\`${message}\`\`\``,
      parse_mode: 'MarkdownV2',
    });
    // 与原版一致：参数放在 URL query 上，以 POST 方式发送
    const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage?${params.toString()}`;
    await fetch(url, { method: 'POST', signal: AbortSignal.timeout(10000) });
    log('Telegram message sent successfully');
  } catch (e) {
    logError(`Failed to send Telegram message: ${e.message}`);
  }
}

// =========================== 上传节点到订阅器 ===========================
async function uploadNodes() {
  if (UPLOAD_URL && PROJECT_URL) {
    const subscriptionUrl = `${PROJECT_URL}/${SUB_PATH}`;
    try {
      const res = await fetch(`${UPLOAD_URL}/api/add-subscriptions`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subscription: [subscriptionUrl] }), signal: AbortSignal.timeout(10000),
      });
      if (res.ok) log('Subscription uploaded successfully');
    } catch (_) { /* ignore */ }
  } else if (UPLOAD_URL) {
    if (!(await pathExists(listPath))) return;
    const content = await fsp.readFile(listPath, 'utf-8');
    const nodes = content.split('\n').filter((l) => /^(vless|vmess|trojan|hysteria2|socks):\/\//.test(l));
    if (!nodes.length) return;
    try {
      const res = await fetch(`${UPLOAD_URL}/api/add-nodes`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nodes }), signal: AbortSignal.timeout(10000),
      });
      if (res.ok) log('Nodes uploaded successfully');
    } catch (_) { /* ignore */ }
  }
}

// =========================== 自动保活 ===========================
async function addVisitTask() {
  if (!AUTO_ACCESS || !PROJECT_URL) { log('Skipping adding automatic access task'); return; }
  try {
    await fetch('https://oooo.serv00.net/add-url', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: PROJECT_URL }), signal: AbortSignal.timeout(10000),
    });
    log('automatic access task added successfully');
  } catch (e) {
    logError(`Add URL failed: ${e.message}`);
  }
}

// =========================== CF-Server-Monitor 上报 ===========================
function probeReadCpuTimes() {
  const line = fs.readFileSync('/proc/stat', 'utf-8').split('\n')[0];
  const nums = line.trim().split(/\s+/).slice(1, 9).map(Number);
  const idle = nums[3] + nums[4];
  const total = nums.reduce((a, b) => a + b, 0);
  return { idle, total };
}

function probeCpuPercent(prevIdle, prevTotal) {
  const { idle, total } = probeReadCpuTimes();
  const dIdle = idle - prevIdle;
  const dTotal = total - prevTotal;
  if (dTotal <= 0) return { cpu: 0.0, idle, total };
  const usage = (1 - dIdle / dTotal) * 100;
  return { cpu: Math.round(Math.max(0, Math.min(100, usage)) * 100) / 100, idle, total };
}

function probeReadHostMeminfo() {
  const text = fs.readFileSync('/proc/meminfo', 'utf-8');
  const info = {};
  for (const line of text.split('\n')) {
    const [k, v] = line.split(':');
    if (!v) continue;
    info[k.trim()] = parseInt(v.trim().split(/\s+/)[0], 10);
  }
  const ramTotal = Math.floor((info.MemTotal || 0) / 1024);
  const ramFree = Math.floor((info.MemAvailable ?? info.MemFree ?? 0) / 1024);
  const ramUsed = Math.max(0, ramTotal - ramFree);
  const swapTotal = Math.floor((info.SwapTotal || 0) / 1024);
  const swapFree = Math.floor((info.SwapFree || 0) / 1024);
  const swapUsed = Math.max(0, swapTotal - swapFree);
  return { ramTotal, ramUsed, swapTotal, swapUsed };
}

function readIntFile(p) {
  return parseInt(fs.readFileSync(p, 'utf-8').trim(), 10);
}

function probeReadCgroupMemory() {
  try {
    const used = readIntFile('/sys/fs/cgroup/memory.current');
    const rawLimit = fs.readFileSync('/sys/fs/cgroup/memory.max', 'utf-8').trim();
    const limit = rawLimit === 'max' ? null : parseInt(rawLimit, 10);
    let swapUsed = 0; let swapTotal = 0;
    try {
      swapUsed = readIntFile('/sys/fs/cgroup/memory.swap.current');
      const rawSw = fs.readFileSync('/sys/fs/cgroup/memory.swap.max', 'utf-8').trim();
      swapTotal = rawSw === 'max' ? null : parseInt(rawSw, 10);
    } catch (_) { /* ignore */ }
    return { used, limit, swapUsed, swapTotal };
  } catch (_) { /* fallthrough to cgroup v1 */ }
  try {
    const used = readIntFile('/sys/fs/cgroup/memory/memory.usage_in_bytes');
    let limit = readIntFile('/sys/fs/cgroup/memory/memory.limit_in_bytes');
    if (limit > Number.MAX_SAFE_INTEGER / 2) limit = null;
    let swapUsed = 0; let swapTotal = 0;
    try {
      const memswUsed = readIntFile('/sys/fs/cgroup/memory/memory.memsw.usage_in_bytes');
      const memswLimit = readIntFile('/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes');
      swapUsed = Math.max(0, memswUsed - used);
      if (memswLimit <= Number.MAX_SAFE_INTEGER / 2 && limit !== null) swapTotal = Math.max(0, memswLimit - limit);
    } catch (_) { /* ignore */ }
    return { used, limit, swapUsed, swapTotal };
  } catch (_) {
    return { used: null, limit: null, swapUsed: null, swapTotal: null };
  }
}

function probeReadMeminfo() {
  const { used, limit, swapUsed, swapTotal } = probeReadCgroupMemory();
  if (used !== null && limit) {
    const ramTotal = Math.floor(limit / (1024 * 1024));
    const ramUsed = Math.min(Math.floor(used / (1024 * 1024)), ramTotal);
    const swapTotalMb = Math.floor((swapTotal || 0) / (1024 * 1024));
    const swapUsedMb = swapTotalMb ? Math.min(Math.floor((swapUsed || 0) / (1024 * 1024)), swapTotalMb) : 0;
    return { ramTotal, ramUsed, swapTotal: swapTotalMb, swapUsed: swapUsedMb };
  }
  return probeReadHostMeminfo();
}

function probeReadDiskUsage(diskPath = '/') {
  try {
    const st = fs.statfsSync(diskPath); // Node >= 18.15
    const total = st.blocks * st.bsize;
    const free = st.bavail * st.bsize;
    const used = total - free;
    return { total: Math.floor(total / (1024 * 1024)), used: Math.floor(used / (1024 * 1024)) };
  } catch (_) {
    // 老版本 Node 没有 fs.statfsSync 时，退回 df 命令
    try {
      const out = execFileSync('df', ['-k', diskPath], { encoding: 'utf-8' });
      const parts = out.trim().split('\n')[1].trim().split(/\s+/);
      const totalKb = parseInt(parts[1], 10);
      const usedKb = parseInt(parts[2], 10);
      return { total: Math.floor(totalKb / 1024), used: Math.floor(usedKb / 1024) };
    } catch (_e) {
      return { total: 0, used: 0 };
    }
  }
}

function probeReadNetBytes() {
  const lines = fs.readFileSync('/proc/net/dev', 'utf-8').split('\n').slice(2);
  let rxTotal = 0; let txTotal = 0;
  for (const line of lines) {
    if (!line.includes(':')) continue;
    const [ifaceRaw, rest] = line.split(':');
    const iface = ifaceRaw.trim();
    if (iface === 'lo') continue;
    const fields = rest.trim().split(/\s+/);
    rxTotal += parseInt(fields[0], 10) || 0;
    txTotal += parseInt(fields[8], 10) || 0;
  }
  return { rx: rxTotal, tx: txTotal };
}

function probeReadOsName() {
  try {
    const text = fs.readFileSync('/etc/os-release', 'utf-8');
    const info = {};
    for (const rawLine of text.split('\n')) {
      const line = rawLine.trim();
      if (!line || !line.includes('=')) continue;
      const idx = line.indexOf('=');
      const key = line.slice(0, idx);
      const val = line.slice(idx + 1).replace(/^"|"$/g, '');
      info[key] = val;
    }
    if (info.PRETTY_NAME) return info.PRETTY_NAME;
    if (info.NAME) {
      const version = info.VERSION || info.VERSION_ID;
      return version ? `${info.NAME} ${version}`.trim() : info.NAME;
    }
  } catch (_) { /* ignore */ }
  return `${os.type()} ${os.release()}`;
}

function probeReadCpuInfo() {
  try {
    const text = fs.readFileSync('/proc/cpuinfo', 'utf-8');
    for (const line of text.split('\n')) {
      if (line.toLowerCase().startsWith('model name')) {
        return line.split(':').slice(1).join(':').trim();
      }
    }
  } catch (_) { /* ignore */ }
  return (os.cpus()[0] && os.cpus()[0].model) || 'unknown';
}

function probeReadProcessCount() {
  try {
    return fs.readdirSync('/proc').filter((p) => /^\d+$/.test(p)).length;
  } catch (_) { return 0; }
}

function probeReadConnCount(proto) {
  try {
    const lines = fs.readFileSync(`/proc/net/${proto}`, 'utf-8').split('\n');
    return Math.max(0, lines.length - 2); // 去掉表头和末尾空行，等价于原版 len-1 的近似
  } catch (_) { return 0; }
}

function probeLoadAvg() {
  const la = os.loadavg();
  return `${la[0].toFixed(2)} ${la[1].toFixed(2)} ${la[2].toFixed(2)}`;
}

const probeIpCache = { v4: '0', v6: '0', ts: 0 };
async function probeGetPublicIps() {
  const now = Date.now() / 1000;
  if (now - probeIpCache.ts < PROBE_IP_REFRESH_INTERVAL && probeIpCache.ts > 0) {
    return { v4: probeIpCache.v4, v6: probeIpCache.v6 };
  }
  const v4 = (await fetchPublicIpVersion('v4')) || '0';
  const v6 = (await fetchPublicIpVersion('v6')) || '0';
  probeIpCache.v4 = v4; probeIpCache.v6 = v6; probeIpCache.ts = now;
  return { v4, v6 };
}

function probeParseHostPort(target, defaultPort = 80) {
  target = (target || '').trim();
  if (!target) return { host: null, port: null };
  if (target.startsWith('[')) {
    const m = target.match(/^\[([^\]]+)\](?::(\d+))?$/);
    if (m) return { host: m[1], port: m[2] ? Number(m[2]) : defaultPort };
    return { host: target.replace(/[[\]]/g, ''), port: defaultPort };
  }
  if (target.includes(':') && target.split(':').length === 2) {
    const [host, portStr] = target.split(':');
    const port = Number(portStr);
    return Number.isFinite(port) ? { host, port } : { host: target, port: defaultPort };
  }
  return { host: target, port: defaultPort };
}

function tcpPingOnce(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(ok ? Date.now() - start : null);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host);
  });
}

async function probeTcpPing(target, count = 4, timeoutSec = 1.5) {
  const { host, port } = probeParseHostPort(target, 443);
  if (!host) return { ping: null, loss: null };
  const timeoutMs = timeoutSec * 1000;
  const times = [];
  let failures = 0;
  for (let i = 0; i < Math.max(1, count); i++) {
    const t = await tcpPingOnce(host, port, timeoutMs);
    if (t === null) failures++; else times.push(t);
  }
  const total = Math.max(1, count);
  const loss = Math.round((failures / total) * 10000) / 100;
  if (!times.length) return { ping: null, loss };
  const avg = times.reduce((a, b) => a + b, 0) / times.length;
  return { ping: Math.round(avg * 100) / 100, loss };
}

const probePingCache = {
  ts: 0, pingCt: null, lossCt: null, pingCu: null, lossCu: null, pingCm: null, lossCm: null,
};

async function probeCollect(prev) {
  const { cpu, idle, total } = probeCpuPercent(prev.idle, prev.total);
  const { ramTotal, ramUsed, swapTotal, swapUsed } = probeReadMeminfo();
  const { total: diskTotal, used: diskUsed } = probeReadDiskUsage('/');
  const { rx, tx } = probeReadNetBytes();

  const now = Date.now() / 1000;
  const dt = Math.max(1e-6, now - prev.ts);
  const rxSpeed = Math.max(0, Math.round((rx - prev.rx) / dt));
  const txSpeed = Math.max(0, Math.round((tx - prev.tx) / dt));

  const metrics = {
    cpu,
    ram_total: ramTotal,
    ram_used: ramUsed,
    swap_total: swapTotal,
    swap_used: swapUsed,
    disk_total: diskTotal,
    disk_used: diskUsed,
    load_avg: probeLoadAvg(),
    boot_time: String(Math.round((Date.now() - os.uptime() * 1000))),
    net_rx: String(rx),
    net_tx: String(tx),
    net_rx_monthly: String(rx),
    net_tx_monthly: String(tx),
    net_in_speed: String(rxSpeed),
    net_out_speed: String(txSpeed),
    os: probeReadOsName(),
    arch: os.arch(),
    kernel_version: os.release(),
    cpu_info: probeReadCpuInfo(),
    cpu_cores: String(os.cpus().length || 1),
    processes: String(probeReadProcessCount()),
    tcp_conn: String(probeReadConnCount('tcp')),
    udp_conn: String(probeReadConnCount('udp')),
    version: PROBE_AGENT_VERSION,
    agent_version: PROBE_AGENT_VERSION,
  };

  const { v4: ipV4, v6: ipV6 } = await probeGetPublicIps();
  metrics.ip_v4 = ipV4;
  metrics.ip_v6 = ipV6;

  if (now - probePingCache.ts >= PROBE_PING_CACHE_TTL) {
    if (PROBE_CT) {
      const r = await probeTcpPing(PROBE_CT, PROBE_PING_COUNT, PROBE_PING_TIMEOUT);
      probePingCache.pingCt = r.ping; probePingCache.lossCt = r.loss;
    }
    if (PROBE_CU) {
      const r = await probeTcpPing(PROBE_CU, PROBE_PING_COUNT, PROBE_PING_TIMEOUT);
      probePingCache.pingCu = r.ping; probePingCache.lossCu = r.loss;
    }
    if (PROBE_CM) {
      const r = await probeTcpPing(PROBE_CM, PROBE_PING_COUNT, PROBE_PING_TIMEOUT);
      probePingCache.pingCm = r.ping; probePingCache.lossCm = r.loss;
    }
    probePingCache.ts = now;
  }
  if (PROBE_CT) { metrics.ping_ct = probePingCache.pingCt; metrics.loss_ct = probePingCache.lossCt; }
  if (PROBE_CU) { metrics.ping_cu = probePingCache.pingCu; metrics.loss_cu = probePingCache.lossCu; }
  if (PROBE_CM) { metrics.ping_cm = probePingCache.pingCm; metrics.loss_cm = probePingCache.lossCm; }

  return { metrics, idle, total, rx, tx, ts: now };
}

async function probeReport(metrics) {
  try {
    const res = await fetch(PROBE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Agent-Version': PROBE_AGENT_VERSION },
      body: JSON.stringify({ id: PROBE_ID, secret: PROBE_SECRET, metrics }),
      signal: AbortSignal.timeout(15000),
    });
    const text = await res.text().catch(() => '');
    log(`[probe] report -> HTTP ${res.status}` + (text ? `: ${text.slice(0, 200)}` : ''));
  } catch (e) {
    logError(`[probe] report failed: ${e.message}`);
  }
}

function startProbeLoop() {
  if (!(PROBE_ID && PROBE_SECRET && PROBE_URL)) { log('PROBE variable is empty, skipping probe'); return; }

  let prev = { ...probeReadCpuTimes(), ...probeReadNetBytes(), ts: Date.now() / 1000 };
  log(`[probe] reporting to ${PROBE_URL} every ${PROBE_INTERVAL}s`);

  const loop = async () => {
    try {
      const result = await probeCollect(prev);
      prev = { idle: result.idle, total: result.total, rx: result.rx, tx: result.tx, ts: result.ts };
      await probeReport(result.metrics);
    } catch (e) {
      logError(`[probe] collection failed: ${e.message}`);
    }
  };

  setInterval(loop, PROBE_INTERVAL * 1000);
}

// =========================== 探针 WSS 实时上报 ===========================
function probeWsUrl() {
  const u = new URL(PROBE_URL);
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
  return u.toString();
}

function startProbeWsLoop() {
  if (!(PROBE_ID && PROBE_SECRET && PROBE_URL)) { log('PROBE variable is empty, skipping probe'); return; }
  if (!PROBE_WSS) { log('[probe] PROBE_WSS is false, using POST polling only'); startProbeLoop(); return; }
  if (!WS_AVAILABLE) {
    log('[probe] "ws" package not installed, falling back to POST polling (run `npm install ws` for real-time WSS reporting)');
    startProbeLoop();
    return;
  }

  const wsUrl = probeWsUrl();
  let prev = { ...probeReadCpuTimes(), ...probeReadNetBytes(), ts: Date.now() / 1000 };
  let backoff = 5000;
  let consecutiveFailures = 0;

  // 请求头与官方 cfsm-agent 协议保持一致（https://github.com/huilang-me/cfsm-agent）
  const headers = {
    'X-Agent-Version': PROBE_AGENT_VERSION,
    'User-Agent': 'cfsm',
    'X-Agent-Config-Schema': '6',
    'X-Agent-Config-Md5': 'none',
    Accept: '*/*',
  };

  log(`[probe] attempting WSS real-time reporting to ${wsUrl}`);

  function connect() {
    const ws = new WebSocket(wsUrl, { headers, handshakeTimeout: 15000 });
    let gotHello = false;
    let reportTimer = null;

    const scheduleNext = (waitMs) => {
      clearTimeout(reportTimer);
      reportTimer = setTimeout(sendOnce, waitMs);
    };

    async function sendOnce() {
      if (ws.readyState !== WebSocket.OPEN) return;
      try {
        const result = await probeCollect(prev);
        prev = { idle: result.idle, total: result.total, rx: result.rx, tx: result.tx, ts: result.ts };
        ws.send(JSON.stringify({ id: PROBE_ID, secret: PROBE_SECRET, metrics: result.metrics }));
        log('[probe] WSS metrics sent, next_wait will be computed from ack');
      } catch (e) {
        logError(`[probe] WSS collect/send failed: ${e.message}`);
        scheduleNext(PROBE_INTERVAL * 1000);
      }
    }

    ws.on('open', () => log('[probe] WSS handshake sent'));

    ws.on('message', (raw) => {
      const text = raw.toString();
      if (!gotHello) {
        // 第一条消息是握手后的 hello 帧
        gotHello = true;
        log('[probe] WSS connected');
        backoff = 5000;
        consecutiveFailures = 0;
        sendOnce();
        return;
      }
      log(`[probe] raw ack: ${text}`);
      let nextWait = PROBE_INTERVAL * 1000;
      try {
        const resp = JSON.parse(text);
        if (resp.type === 'error') {
          logError(`[probe] WSS error: ${resp.error} (code ${resp.code})`);
          ws.close(1000, 'protocol error');
          return;
        }
        const nextMs = resp.nextWssReportAfterMs;
        if (typeof nextMs === 'number' && nextMs > 0) nextWait = Math.max(1000, nextMs);
      } catch (_) { /* ack 解析失败不致命，按默认间隔继续 */ }
      log(`[probe] next report in ${nextWait / 1000}s`);
      scheduleNext(nextWait);
    });

    ws.on('close', (code, reasonBuf) => {
      clearTimeout(reportTimer);
      consecutiveFailures++;
      logError(`[probe] WSS connection issue: closed (code ${code}) ${reasonBuf}`);
      if (consecutiveFailures >= 5) {
        logError('[probe] WSS repeatedly failing, falling back to POST polling for this cycle');
        probeCollect(prev).then((result) => {
          prev = { idle: result.idle, total: result.total, rx: result.rx, tx: result.tx, ts: result.ts };
          return probeReport(result.metrics);
        }).catch((e) => logError(`[probe] fallback POST also failed: ${e.message}`));
        setTimeout(connect, PROBE_INTERVAL * 1000);
      } else {
        setTimeout(connect, backoff);
        backoff = Math.min(backoff * 2, 120000);
      }
    });

    ws.on('error', (e) => {
      logError(`[probe] WSS connection issue: ${e.message}`);
      // 'close' 事件随后也会触发，重连逻辑统一放在 close 处理里
    });
  }

  connect();
}

// =========================== 清理临时文件 ===========================
function cleanFiles() {
  setTimeout(async () => {
    const filesToDelete = [
      bootLogPath, configPath, listPath, webPath, botPath,
      path.join(FILE_PATH, 'tunnel.json'), path.join(FILE_PATH, 'tunnel.yml'),
    ];
    for (const f of filesToDelete) await safeUnlink(f);

    if (SHOW_LOG) {
      try { execFileSync(process.platform === 'win32' ? 'cls' : 'clear', { stdio: 'inherit', shell: true }); } catch (_) { /* ignore */ }
    }
    alwaysLog('App is running');
    log('Thank you for using this script, enjoy!');
  }, 90000).unref();
}

// =========================== HTTP 服务 ===========================
function createRequestHandler() {
  return (req, res) => {
    const parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = parsed.pathname;

    if (pathname === `/${SUB_PATH}`) {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(subTxtContent);
      return;
    }
    if (pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`Hello world!<br><br>You can access /${SUB_PATH}(Default: /sub) get your nodes!`);
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not Found');
  };
}

// =========================== 主流程 ===========================
async function startServer() {
  await deleteNodes();
  await createDirectory();
  await cleanupOldFiles();
  await argoType();

  if (!UUID) {
    UUID = crypto.randomUUID();
    log(`UUID not set, generated a random one for this run: ${UUID}`);
  }

  if (isValidPort(REALITY_PORT)) await generateOrLoadKeypair();
  if (isValidPort(HY2_PORT) || (CDN_DOMAIN && isValidPort(DIRECT_WS_PORT))) await ensureTlsCertificates();

  await generateXrayConfig();
  await downloadFilesAndRun();
  await extractDomains();

  await sendTelegram();
  await uploadNodes();
  await addVisitTask();
  startProbeWsLoop();

  cleanFiles();
}

// =========================== 信号处理 ===========================
function stopAll() {
  log('\nShutting down...');
  killTracked(webProc);
  killTracked(botProc);
  setTimeout(() => process.exit(0), 1000);
}

process.on('SIGINT', stopAll);
process.on('SIGTERM', stopAll);

// =========================== 入口 ===========================
const server = http.createServer(createRequestHandler());
server.listen(PORT, '0.0.0.0', () => {
  alwaysLog(`server is running on ${PORT}!`);
});

// 后台异步跑主流程，不阻塞 HTTP 服务先监听端口（对应原版起一个后台线程）
startServer().catch((e) => logError(`start_server error: ${e && e.stack || e}`));