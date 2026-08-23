const { URL } = require('url');
const { safeInt, safeBigInt, hashBlock, hashTransaction, isBetterChainCandidate } = require('../crypto');
const { log } = require('../config');

function fetchJSON(url, opts = {}) {
  const u = new URL(url);
  const mod = u.protocol === 'https:' ? require('https') : require('http');
  return new Promise((resolve, reject) => {
    const timeout = (opts.timeout || 10) * 1000;
    const req = mod.request(url, {
      method: opts.method || 'GET',
      headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
      timeout,
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    if (opts.body) req.write(JSON.stringify(opts.body));
    req.end();
  });
}

class SyncEngine {
  constructor(db, cfg, chain, peers, challengeMgr, NODE_ID) {
    this.db = db;
    this.cfg = cfg;
    this.chain = chain;
    this.peers = peers;
    this.challengeMgr = challengeMgr;
    this.NODE_ID = NODE_ID;
    this.syncing = false;
    this._lastReorg = 0;
    this._broadcastSeen = new Map();
  }

  _rememberBroadcast(key, ttlMs = 30000) {
    const now = Date.now();
    const expiry = this._broadcastSeen.get(key);
    if (expiry && expiry > now) return false;
    this._broadcastSeen.set(key, now + ttlMs);
    if (this._broadcastSeen.size > 10000) {
      for (const [k, v] of this._broadcastSeen.entries()) {
        if (v <= now) this._broadcastSeen.delete(k);
      }
    }
    return true;
  }

  async discoverPeers() {
    const selfHost = (() => { try { return this.cfg.nodeUrl ? new (require('url').URL)(this.cfg.nodeUrl).hostname : null; } catch { return null; } })();
    const targets = [...new Set([...(this.cfg.seedPeers || []), ...this.peers.active(20).map(p => p.url)])];
    await Promise.allSettled(targets.map(async (url) => {
      try {
        const normalized = new (require('url').URL)(url);
        if (selfHost && normalized.hostname === selfHost) return;
        const data = await fetchJSON(`${url.replace(/\/+$/, '')}/peers`, { timeout: 8 });
        log('info', `[P2P] Discovered peers from ${url}: ${data && Array.isArray(data.peers) ? data.peers.length + ' peers' : data}`);
        if (data && Array.isArray(data.peers) && data.peers.length > 0) {
          for (const p of data.peers) {
            if (p.url) this.peers.add(p.url);
          }
        }
      } catch {
        this.peers.fail(url);
      }
    }));
  }

  async loopSync() {
    if (this.syncing) return;
    this.syncing = true;
    try {
      const peers = this.peers.active(10).filter(p => {
        try { const u = new (require('url').URL)(p.url); if (this.cfg.nodeUrl && u.hostname === new (require('url').URL)(this.cfg.nodeUrl).hostname) return false; } catch {} return true;
      });
      for (const peer of peers) {
        try {
          const remote = await fetchJSON(`${peer.url}/api/stats`, { timeout: 5 });
          if (!remote) continue;
          const remoteHeight = remote.height ?? remote.altura;
          if (typeof remoteHeight !== 'number') continue;
          const remoteWork = safeBigInt(remote.chain_work, 0n);
          const localTip = this.chain.getBlock(this.chain.height);
          const localWork = safeBigInt(localTip ? localTip.chain_work : 0n, 0n);
          if (remoteWork <= localWork && remoteHeight <= this.chain.height) continue;
          log('debug', `loopSync: peer=${peer.url} remoteHeight=${remoteHeight} remoteWork=${remote.chain_work} localHeight=${this.chain.height} localWork=${localTip ? localTip.chain_work : 0}`);
          await this._syncFromPeer(peer.url, remoteHeight);
          break;
        } catch (e) { log('debug', `loopSync: peer=${peer.url} error=${e.message}`); }
      }
    } finally { this.syncing = false; }
  }

  async _findCommonAncestor(peerUrl) {
    let low = 0;
    let high = this.chain.height;
    let best = 0;
    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      const local = this.chain.getBlock(mid);
      if (!local) {
        high = mid - 1;
        continue;
      }
      const remote = await fetchJSON(`${peerUrl}/api/block/${mid}`, { timeout: 5 });
      if (remote && remote.hash && remote.hash === local.hash) {
        best = mid;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    return best;
  }

  async _syncFromPeer(peerUrl, remoteHeight) {
    const commonHeight = await this._findCommonAncestor(peerUrl);
    let from = Math.max(0, commonHeight + 1);
    let inserted = 0;
    const maxBlocks = this.cfg.maxBlocksPerSync || 10000;
    log('info', `Syncing from ${peerUrl} — ancestor=${commonHeight} target=${remoteHeight}`);
    while (from <= remoteHeight && inserted < maxBlocks) {
      try {
        const data = await fetchJSON(`${peerUrl}/api/blocks?from=${from}&limit=50`, { timeout: 15 });
        if (!data || !Array.isArray(data.blocks) || !data.blocks.length) break;
        let advanced = false;
        for (const block of data.blocks) {
          if (block.height < from) continue;
          if (this.db.prepare('SELECT 1 FROM blocks WHERE hash = ?').get(block.hash)) {
            if (block.height >= from) { from = block.height + 1; advanced = true; }
            continue;
          }
          block._from_local_forge = false;
          const insertResult = await this.chain.addBlock(block);
          if (!insertResult.ok) { log('debug', `sync: block insert rejected at #${block.height}: ${insertResult.motivo}`); break; }
          inserted++;
          from = block.height + 1;
          advanced = true;
        }
        if (!advanced) break;
        log('info', `Sync progress: ${inserted} blocks inserted, at #${from - 1}/${remoteHeight}`);
      } catch (e) { log('debug', `sync fetch error: ${e.message}`); break; }
    }
    if (inserted > 0) {
      this.chain._selectTip();
      this.chain._purgeOrphanedBlocks();
      const peerTip = await fetchJSON(`${peerUrl}/api/block/${remoteHeight}`, { timeout: 5 });
      if (peerTip && peerTip.hash) {
        const reorgResult = await this.chain.reorganize(peerTip, false);
        if (reorgResult.ok) {
          log('info', `Synced ${inserted} blocks from ${peerUrl}, reorged to #${reorgResult.height} ${(reorgResult.hash || '').slice(0, 10)}`);
        } else {
          log('debug', `sync: reorg after bulk insert failed: ${reorgResult.motivo}`);
        }
      }
    }
  }

  async mempoolSync() {
    const peers = this.peers.active(5).filter(p => {
      try { const u = new (require('url').URL)(p.url); if (this.cfg.nodeUrl && u.hostname === new (require('url').URL)(this.cfg.nodeUrl).hostname) return false; } catch {} return true;
    });
    for (const peer of peers) {
      try {
        const data = await fetchJSON(`${peer.url}/api/mempool`, { timeout: 5 });
        if (data && Array.isArray(data.transactions)) {
          for (const tx of data.transactions) {
            this.chain.addMempoolTx(tx);
          }
        }
      } catch {}
    }
  }

  async heartbeat() {
    const peers = this.peers.active(20).filter(p => {
      try { const u = new (require('url').URL)(p.url); if (this.cfg.nodeUrl && u.hostname === new (require('url').URL)(this.cfg.nodeUrl).hostname) return false; } catch {} return true;
    });
    await Promise.allSettled(peers.map(async (peer) => {
      try {
        const stats = this.chain.getStats();
        const res = await fetchJSON(`${peer.url}/api/node/announce`, {
          method: 'POST', body: {
            url: this.cfg.nodeUrl, height: this.chain.height, altura: this.chain.height,
            node_id: this.NODE_ID, chain_work: stats.chain_work,
          }, timeout: 5,
        });
        if (res) {
          if (Array.isArray(res.peers)) {
            for (const p of res.peers) if (p.url) this.peers.add(p.url);
            log('info', `[P2P] Heartbeat: ${peer.url} reported ${res.peers.length} peers, seed_height=${res.our_height}, node_id=${res.node_id}`)
          }
        }
      } catch { this.peers.fail(peer.url); }
    }));
  }

  async announce() {
    if (!this.cfg.nodeUrl) return;
    const selfHost = (() => { try { return new (require('url').URL)(this.cfg.nodeUrl).hostname; } catch { return null; } })();
    await Promise.allSettled((this.cfg.seedPeers || []).map(async (seed) => {
      try {
        if (selfHost && new (require('url').URL)(seed).hostname === selfHost) return;
        const stats = this.chain.getStats();
        log('info', `[P2P] Announcing to seed peer ${seed}: height=${this.chain.height}, chain_work=${stats.chain_work}, node_id=${this.NODE_ID}`);
        await fetchJSON(`${seed.replace(/\/+$/, '')}/register`, {
          method: 'POST', body: {
            url: this.cfg.nodeUrl, node_id: this.NODE_ID, height: this.chain.height, altura: this.chain.height,
            chain_work: stats.chain_work, version: this.cfg.version, peers: this.peers.count(),
          }, timeout: 8,
        });
      } catch { this.peers.fail(seed); }
    }));
  }

  async broadcastBlock(block) {
    const key = `block:${block && block.hash ? block.hash : hashBlock(block)}`;
    if (!this._rememberBroadcast(key)) return { accepted: 0, total: 0, noPeers: false, deduped: true };
    const peers = this.peers.active(10);
    if (!peers.length) return { accepted: 0, total: 0, noPeers: true };
    const results = await Promise.allSettled(peers.map(peer => fetchJSON(`${peer.url}/api/node/broadcast/block`, {
      method: 'POST', body: { block }, timeout: 10,
    })));
    const accepted = results.filter(r => r.status === 'fulfilled' && r.value && r.value.ok).length;
    return { accepted, total: peers.length, noPeers: false };
  }

  async broadcastTx(tx) {
    const key = `tx:${tx && tx.hash ? tx.hash : hashTransaction(tx)}`;
    if (!this._rememberBroadcast(key)) return { deduped: true };
    const peers = this.peers.active(10);
    await Promise.allSettled(peers.map(peer => fetchJSON(`${peer.url}/api/node/broadcast/tx`, {
      method: 'POST', body: { tx }, timeout: 5,
    })));
  }

  getStatus() {
    return { syncing: this.syncing, current_height: this.chain.height, last_reorg: this._lastReorg };
  }
}

module.exports = { SyncEngine, fetchJSON };