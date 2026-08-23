const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { safeInt, safeBigInt, sha256hex, hashTransaction, pubkeyToAddress, pubKeyToAddress, calculateMiningReward, hashBlock, signMessage, canonicalTxMessage } = require('./crypto');
const { log, getLogBuffer } = require('./config');
const { createPlotFile, MAX_PLOT_GB } = require('./plot');

const rateLimitStore = new Map();
function rateLimit(options = {}) {
  const { windowMs = 60000, max = 100, keyPrefix = 'rl', message = 'Too many requests' } = options;
  return (req, res, next) => {
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    const key = `${keyPrefix}:${ip}`;
    const now = Date.now();
    const record = rateLimitStore.get(key) || { count: 0, resetTime: now + windowMs };
    if (now > record.resetTime) {
      record.count = 0;
      record.resetTime = now + windowMs;
    }
    record.count++;
    rateLimitStore.set(key, record);
    res.setHeader('X-RateLimit-Limit', max);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, max - record.count));
    res.setHeader('X-RateLimit-Reset', Math.ceil(record.resetTime / 1000));
    if (record.count > max) {
      return res.status(429).json({ error: message, retryAfter: Math.ceil((record.resetTime - now) / 1000) });
    }
    next();
  };
}

function cleanupRateLimit() {
  const now = Date.now();
  for (const [key, record] of rateLimitStore.entries()) {
    if (now > record.resetTime) rateLimitStore.delete(key);
  }
}
setInterval(cleanupRateLimit, 60000);


class Server {
  constructor(cfg, db, chain, peers, sync, miner, challengeMgr, registry, NODE_ID, smartContracts = null, p2pWsServer = null) {
    this.cfg = cfg;
    this.db = db;
    this.chain = chain;
    this.peers = peers;
    this.sync = sync;
    this.miner = miner;
    this.challengeMgr = challengeMgr;
    this.registry = registry;
    this.NODE_ID = NODE_ID;
    this.smartContracts = smartContracts;
    this.p2pWsServer = p2pWsServer;
    this.app = null;
    this.server = null;
    this.discoveryServer = null;
    this._peerStorageCache = { peers: [], local: { plots_count: 0, capacidade_gb: 0 }, fetched_at: 0 };
  }

  async _fetchPeerStorage() {
    try {
      const gossip = this.peers.gossipPeers(50);
      const results = [];
      const fetches = gossip.map(async (p) => {
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 4000);
          const res = await fetch(p.url + '/api/stats', { signal: controller.signal });
          clearTimeout(timer);
          if (!res.ok) return null;
          const d = await res.json();
          return { url: p.url, node_id: p.node_id, plots_count: d.plots_count || 0, capacity_gb: Number(d.capacidade_gb) || 0, height: d.height || 0 };
        } catch { return null; }
      });
      const settled = await Promise.allSettled(fetches);
      for (const r of settled) {
        if (r.status === 'fulfilled' && r.value) results.push(r.value);
      }
      const st = this.chain.getStats();
      this._peerStorageCache = {
        peers: results,
        local: { plots_count: st.plots_count || 0, capacidade_gb: Number(st.capacidade_gb) || 0 },
        fetched_at: Date.now(),
      };
    } catch (e) { /* noop */ }
  }

  start() {
    const express = require('express');
    const helmet = require('helmet');
    const app = express();
    this.app = app;

    const PUBLIC_DIR = path.join(__dirname, 'public');

    app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
    app.use(express.json({ limit: '10mb' }));

    const allowedOrigins = this.cfg.corsOrigins || (this.cfg.nodeUrl ? [this.cfg.nodeUrl] : []);
    app.use((req, res, next) => {
      const origin = req.headers.origin;
      if (origin && allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
      }
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Token');
      res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
      if (req.method === 'OPTIONS') return res.sendStatus(200);
      next();
    });

    app.use(express.static(PUBLIC_DIR, { maxAge: 0 }));

    const apiLimiter = rateLimit({ windowMs: 60000, max: 120, keyPrefix: 'api', message: 'Too many API requests' });
    const mutationLimiter = rateLimit({ windowMs: 60000, max: 30, keyPrefix: 'mut', message: 'Too many mutation requests' });
    const walletLimiter = rateLimit({ windowMs: 60000, max: 10, keyPrefix: 'wlt', message: 'Too many wallet requests' });
    const p2pLimiter = rateLimit({ windowMs: 60000, max: 60, keyPrefix: 'p2p', message: 'Too many P2P requests' });

    const requireAdmin = (req, res, next) => {
      const token = req.headers['x-admin-token'] || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      if (token === this.cfg.adminToken) return next();
      res.status(401).json({ error: 'unauthorized' });
    };

    app.use(apiLimiter);

    const serveDashboard = (req, res) => {
      const html = fs.readFileSync(path.join(PUBLIC_DIR, 'index.html'), 'utf8');
      res.type('html').send(html.replace('__CHOHUB_TOKEN__', this.cfg.adminToken || ''));
    };
    app.get('/dashboard', serveDashboard);
    app.get('/', (req, res) => {
      if (req.accepts('html')) return serveDashboard(req, res);
      res.json({ ok: true, node: 'choco', height: this.chain.height });
    });

    app.get('/api/stats', (req, res) => {
      const stats = this.chain.getStats();
      const tip = this.chain.getBlock(this.chain.height);
      const ns = this.registry.getStats();
      res.json({
        ...stats, chain_id: this.cfg.chainId, chain_name: this.cfg.chainName,
        symbol: this.cfg.symbol, current_reward: calculateMiningReward(this.chain.height + 1, this.cfg).toString(),
        current_reward_cc: Number(calculateMiningReward(this.chain.height + 1, this.cfg)) / 1e18,
        blocks_to_halving: this.cfg.halvingInterval - (this.chain.height % this.cfg.halvingInterval),
        halving_interval: this.cfg.halvingInterval, max_supply: this.cfg.maxSupply,
        seed_version: this.cfg.version, node_url: this.cfg.nodeUrl,
        node_id: this.NODE_ID, peers: { total: this.peers.count(), active: this.peers.active().length, banned: this.peers.banned().length, avg_health: 0 },
        version: this.cfg.version,
      });
    });

app.get('/api/state', (req, res) => {
  const running = !!this.chain;
  const config = this.cfg;
  const wallets = this.db.prepare('SELECT address, balance, nonce FROM users ORDER BY address').all();
  const node = running ? this.chain.getStats() : null;
  res.json({
    running,
    config: {
      port: config.port,
      minerAddress: config.minerAddress,
      miningEnabled: config.miningEnabled,
      chainId: config.chainId,
      chainName: config.chainName,
      symbol: config.symbol
    },
    wallets: wallets.map(w => ({
      address: w.address,
      balance: w.balance,
      nonce: w.nonce
    })),
    miner_unlocked: !!config.minerPrivateKey,
    node: node ? {
      height: node.height,
      hash: node.hash,
      peers: node.blocks ? node.blocks.length : 0
    } : null,
    network_storage: {
      local: { plots_count: node ? node.plots_count : 0, capacidade_gb: node ? Number(node.capacidade_gb || 0) : 0 },
      peers: []
    },
    data_dir: config.dataDir
  });
});

    app.get('/api/blocks', (req, res) => {
      const from = parseInt(req.query.from) || 0;
      const limit = Math.min(parseInt(req.query.limit) || 50, 200);
      let blocks;
      if (req.query.hash) {
        const b = this.chain.getBlock(req.query.hash);
        blocks = b ? [b] : [];
      } else {
        blocks = [];
        for (let h = from; h < from + limit; h++) {
          const b = this.chain.getBlock(h);
          if (b) blocks.push(b); else break;
        }
      }
      res.json({ blocks, total: this.chain.height + 1 });
    });

    app.get('/api/block/:heightOrHash', (req, res) => {
      const b = this.chain.getBlock(req.params.heightOrHash);
      if (!b) return res.status(404).json({ error: 'block not found' });
      res.json(b);
    });

    app.get('/api/plots', (req, res) => {
      const plots = this.db.prepare('SELECT plot_id, miner, merkle_root, size_gb, created_at FROM plot_commitments ORDER BY size_gb DESC').all();
      res.json({ plots });
    });

    app.get('/api/challenge', (req, res) => {
      const ch = this.challengeMgr.getOrCreate();
      if (!ch) return res.status(404).json({ error: 'no active challenge' });
      const now = Math.floor(Date.now() / 1000);
      const deadline = ch.expires_at ? Math.max(0, ch.expires_at - now) : 0;
      const capacityGbRaw = this.db.prepare('SELECT COALESCE(SUM(size_gb), 0) as s FROM (SELECT DISTINCT plot_id, size_gb FROM plot_commitments)').get().s;
      const capacityGb = Number(capacityGbRaw) || 0;
      const plotsCount = this.db.prepare('SELECT COUNT(DISTINCT plot_id) as c FROM plot_commitments').get().c;
      res.json({
        challenge_id: ch.challenge_id,
        block_height: ch.block_height,
        challenge_seed: ch.challenge_seed,
        target_scoop_index: ch.target_scoop_index,
        created_at: ch.created_at,
        expires_at: ch.expires_at,
        deadline,
        base_target: ch.base_target,
        plots: plotsCount,
        capacity_gb: Number(capacityGb.toFixed(2)),
        difficulty: this.chain.height > 0 ? '~' + this.chain.height + ' blocks' : 'genesis',
      });
    });

    app.get('/api/mempool', (req, res) => {
      const txs = this.db.prepare('SELECT * FROM mempool ORDER BY CAST(fee AS INTEGER) DESC LIMIT 200').all().map(r => { try { return JSON.parse(r.raw); } catch { return null; } }).filter(Boolean);
      res.json({ transactions: txs, count: txs.length });
    });

    app.post('/api/mempool', mutationLimiter, async (req, res) => {
      const tx = req.body;
      if (!tx || !tx.from_addr || (!tx.to_addr && !tx.data)) return res.status(400).json({ error: 'invalid transaction' });
      const validation = await this.chain.validateTxForMempool(tx);
      if (!validation.ok) return res.status(400).json({ ok: false, error: validation.motivo });
      if (!tx.hash) tx.hash = hashTransaction(tx);
      const result = this.chain.addMempoolTx(tx);
      if (result.ok) setImmediate(() => this.sync.broadcastTx(tx));
      res.json(result);
    });

    app.post('/api/wallet/prepare-tx', walletLimiter, async (req, res) => {
      try {
        const { from_addr, to_addr, amount, data, gas_limit, gas_price, chain_id, priority_fee } = req.body;
        if (!from_addr || (!to_addr && !data)) return res.status(400).json({ error: 'from_addr and to_addr (or data for contract creation) required' });
        
        const normalizedFrom = from_addr.toLowerCase();
        const user = this.db.prepare('SELECT balance, nonce, public_key_ed25519 FROM users WHERE lower(address) = lower(?)').get(normalizedFrom);
        if (!user || !user.public_key_ed25519) return res.status(400).json({ error: 'address not registered (no public key)' });
        
        const hasData = !!(data && /^0x[0-9a-fA-F]*$/.test(String(data)));
        const amountNum = amount === undefined || amount === null ? 0 : Number(amount);
        if (isNaN(amountNum) || amountNum < 0) return res.status(400).json({ error: 'invalid amount' });
        const valueWei = String(Math.round(amountNum * 1e18));
        
        const nonce = user.nonce || 0;
        const gasPrice = gas_price || this.chain._baseFeeForHeight(this.chain.height + 1);
        const defaultGas = hasData ? 3000000 : 21000;
        const gasLimit = gas_limit || defaultGas;
        const fee = (gasLimit === 21000) ? '21000' : String(gasLimit);
        
        const tx = {
          from_addr: normalizedFrom,
          to_addr: to_addr || '',
          value: valueWei,
          nonce,
          fee,
          gas_limit: gasLimit,
          gas_price: String(gasPrice),
          chain_id: chain_id || this.cfg.chainId || '0',
          priority_fee: priority_fee || '0'
        };
        if (hasData) tx.data = String(data);
        
        const msg = canonicalTxMessage(tx);
        const txHash = hashTransaction(tx);
        
        const estimatedGas = require('./crypto').estimateIntrinsicGas ? require('./crypto').estimateIntrinsicGas(tx) : gasLimit;
        const currentBaseFee = BigInt(this.chain._baseFeeForHeight(this.chain.height + 1));
        const estimatedFee = (BigInt(gasLimit) * currentBaseFee).toString();
        
        res.json({
          ok: true,
          transaction: tx,
          sign_message: msg,
          tx_hash: txHash,
          estimated_gas: estimatedGas,
          estimated_fee: estimatedFee,
          gas_price: String(currentBaseFee),
          balance: user.balance,
          nonce
        });
      } catch (e) { res.status(400).json({ error: e.message }); }
    });

    app.get('/api/wallets', (req, res) => {
      const wallets = this.db.prepare('SELECT address, balance, nonce, created_at, updated_at FROM users ORDER BY CAST(balance AS INTEGER) DESC LIMIT 200').all();
      res.json({ wallets, count: wallets.length });
    });
    app.get('/api/accounts', (req, res) => {
      const address = req.query.address;
      if (!address) return res.status(400).json({ error: 'address query param required' });
      const u = this.db.prepare('SELECT address, balance, nonce, created_at, updated_at FROM users WHERE lower(address) = lower(?)').get(address);
      if (!u) return res.json({ address, balance: '0', nonce: 0 });
      res.json(u);
    });
    app.get('/api/gas/price', (req, res) => {
      const dynamicPrice = this.chain._baseFeeForHeight(this.chain.height + 1);
      res.json({ gas_price: String(dynamicPrice), unit: 'wei' });
    });
    app.get('/api/users/:address', (req, res) => {
      const u = this.db.prepare('SELECT * FROM users WHERE lower(address) = lower(?)').get(req.params.address);
      if (!u) return res.status(404).json({ error: 'user not found' });
      res.json(u);
    });

    app.post('/api/wallet/import', requireAdmin, walletLimiter, (req, res) => {
      const { address, public_key } = req.body;
      if (!address || !public_key) return res.status(400).json({ error: 'address and public_key required (private keys never sent to node)' });
      const normalizedAddress = address.toLowerCase();
      try { if (pubkeyToAddress(public_key).toLowerCase() !== normalizedAddress) return res.status(400).json({ error: 'address does not match public key' }); } catch { return res.status(400).json({ error: 'Invalid public key' }); }
      const now = Math.floor(Date.now() / 1000);
      this.db.prepare('INSERT INTO users (address, public_key_ed25519, balance, nonce, created_at, updated_at) VALUES (?, ?, 0, 0, ?, ?) ON CONFLICT(address) DO UPDATE SET public_key_ed25519 = excluded.public_key_ed25519, updated_at = excluded.updated_at').run(normalizedAddress, public_key, now, now);
      log('info', `Imported wallet: address=${normalizedAddress}, public_key=${public_key}`);
      res.json({ ok: true, address: normalizedAddress });
    });

    app.post('/api/wallet/register', walletLimiter, (req, res) => {
      const { address, public_key } = req.body;
      if (!address || !public_key) return res.status(400).json({ error: 'address and public_key required' });
      const normalizedAddress = address.toLowerCase();
      try { if (pubkeyToAddress(public_key).toLowerCase() !== normalizedAddress) return res.status(400).json({ error: 'address does not match public key' }); } catch { return res.status(400).json({ error: 'Invalid public key' }); }
      const now = Math.floor(Date.now() / 1000);
      const existing = this.db.prepare('SELECT address, public_key_ed25519 FROM users WHERE lower(address) = lower(?)').get(normalizedAddress);
      if (existing && existing.public_key_ed25519) {
        return res.status(409).json({ ok: false, error: 'public key already registered', address: normalizedAddress });
      }
      if (existing) {
        this.db.prepare('UPDATE users SET public_key_ed25519 = ?, updated_at = ? WHERE lower(address) = lower(?)').run(public_key, now, normalizedAddress);
      } else {
        this.db.prepare('INSERT INTO users (address, public_key_ed25519, balance, nonce, created_at, updated_at) VALUES (?, ?, 0, 0, ?, ?)').run(normalizedAddress, public_key, now, now);
      }
      log('info', `Registered wallet: address=${normalizedAddress}, public_key=${public_key}`);
      res.json({ ok: true, address: normalizedAddress, public_key });
    });

    app.get('/api/node/info', (req, res) => {
      const ns = this.registry.getStats();
      res.json({ ...this.chain.getStats(), chain_id: this.cfg.chainId, chain_name: this.cfg.chainName, symbol: this.cfg.symbol, node_url: this.cfg.nodeUrl, node_id: this.NODE_ID, version: this.cfg.version, peers: this.peers.gossipPeers(20) });
    });
    app.get('/api/node/status', (req, res) => res.json({
      height: this.chain.height, hash: this.chain.bestHash,
      chain_work: (this.chain.getBlock(this.chain.height) || {}).chain_work || '0',
      peer_count: this.peers.count(), mining_active: this.miner.active,
      miner_address: this.miner.address, node_url: this.cfg.nodeUrl,
    }));
    app.get('/api/node/peers', (req, res) => res.json({ peers: this.peers.all(100) }));
    app.get('/api/node/peers/gossip', (req, res) => res.json({ peers: this.peers.gossipPeers(50) }));

    app.get('/api/peers', (req, res) => res.json({ peers: this.peers.all(100) }));
    app.post('/api/peers/add', p2pLimiter, (req, res) => {
      const url = require('./config').normalizeUrl(req.body.url);
      if (!url) return res.status(400).json({ error: 'invalid url' });
      this.peers.add(url);
      res.json({ ok: true, url });
    });

    app.get('/api/mining/challenge', (req, res) => {
      const ch = this.challengeMgr.getOrCreate();
      if (!ch) return res.status(404).json({ error: 'no challenge available' });
      res.json(ch);
    });

    app.post('/api/mining/submit-proof', mutationLimiter, (req, res) => {
      const { challenge_id, miner, plot_id, deadline, proof_packet, proof_signature } = req.body;
      if (!challenge_id || !miner || !plot_id || deadline == null) return res.status(400).json({ error: 'challenge_id, miner, plot_id, deadline required' });
      const packet = proof_packet || {};
      if (proof_signature && !packet.proof_signature) packet.proof_signature = proof_signature;
      const result = this.challengeMgr.submitProof(this.chain, challenge_id, miner, plot_id, safeInt(deadline, -1), packet);
      if (!result.ok) return res.status(400).json({ error: result.motivo });
      log('info', `[MINERS] Proof submit: miner=${miner}, plot_id=${plot_id}, deadline=${deadline}, result=${result.ok ? 'accepted' : 'rejected'}, reason=${result.motivo}`);
      if (result.bloco && this.sync) {
        const block = result.bloco;
        setImmediate(() => { this.sync.broadcastBlock(block); });
        if (this.p2pWsServer) this.p2pWsServer.broadcastBlock(block);
      }
      res.json(result);
    });

    app.get('/api/mining/metrics', (req, res) => res.json(this.miner.getMetrics()));
    app.get('/api/mining/status', (req, res) => res.json({ mining: this.miner.active, address: this.miner.address }));
    app.post('/api/mining/start', requireAdmin, (req, res) => { this.miner.start(req.body.address || this.cfg.minerAddress); res.json({ ok: true, mining: this.miner.active, address: this.miner.address }); });
    app.post('/api/mining/stop', requireAdmin, (req, res) => { this.miner.stop(); res.json({ ok: true, mining: false }); });

    app.post('/api/mining/config', requireAdmin, (req, res) => {
      const { address, threads, priority } = req.body;
      if (address) this.miner.address = address;
      res.json({ ok: true, address: this.miner.address });
    });

    app.post('/api/poc/create_plot', requireAdmin, (req, res) => {
      const { miner, plot_id, size_gb, plot_dir } = req.body;
      const address = miner || this.cfg.minerAddress;
      if (!address || !plot_id || !size_gb) return res.status(400).json({ error: 'miner address, plot_id, size_gb required' });
      try {
        const size = parseFloat(size_gb);
        if (size <= 0 || size > MAX_PLOT_GB) return res.status(400).json({ error: `invalid size_gb (1-${MAX_PLOT_GB} GB)` });
        const plotPath = path.join(plot_dir || this.cfg.plotsDir, `${plot_id}.plot`);
        const plotInfo = createPlotFile(plotPath, plot_id, address, size);
        this.db.prepare('INSERT OR IGNORE INTO plot_commitments (plot_id, miner, merkle_root, size_gb, created_at) VALUES (?,?,?,?,?)').run(plot_id, address, plotInfo.merkleRoot, size, Math.floor(Date.now() / 1000));
        log('info', `[MINERS] Created plot: miner=${address}, plot_id=${plot_id}, size_gb=${size}, merkle_root=${plotInfo.merkleRoot}, path=${plotPath}`);
        res.json({ ok: true, plot_id, merkle_root: plotInfo.merkleRoot, size_gb: size, path: plotPath });
      } catch (e) { res.status(500).json({ error: e.message }); }
    });
    
    app.get('/api/poc/plots/:miner', (req, res) => res.json({ plots: this.db.prepare('SELECT * FROM plot_commitments WHERE miner = ?').all(req.params.miner) }));
    app.post('/api/poc/register_plot', requireAdmin, (req, res) => {
      const { miner, plot_id, size_gb, merkle_root = '' } = req.body;
      if (!miner || !plot_id || !size_gb) return res.status(400).json({ error: 'miner, plot_id, size_gb required' });
      console.log(`Registering plot: miner=${miner}, plot_id=${plot_id}, size_gb=${size_gb}, merkle_root=${merkle_root}`);
      this.db.prepare('INSERT OR IGNORE INTO plot_commitments (plot_id, miner, merkle_root, size_gb, created_at) VALUES (?,?,?,?,?)').run(plot_id, miner, merkle_root, parseFloat(size_gb), Math.floor(Date.now() / 1000));
      res.json({ ok: true, plot_id, miner });
    });

    const contractsEnabled = () => !!this.cfg.smartContractsEnabled && this.smartContracts;
    const contractsDisabled = (res) => res.status(503).json({ error: 'smart contracts disabled on this node', enabled: false });

    app.get('/api/contracts', (req, res) => {
      if (!contractsEnabled()) return contractsDisabled(res);
      res.json({ contracts: this.smartContracts.listSmartContracts() });
    });

    app.get('/api/contracts/:address', (req, res) => {
      if (!contractsEnabled()) return contractsDisabled(res);
      const c = this.smartContracts.getSmartContract(req.params.address);
      if (!c) return res.status(404).json({ error: 'contract not found' });
      res.json({ contract: c });
    });

    app.post('/api/contracts/deploy', mutationLimiter, async (req, res) => {
      if (!contractsEnabled()) return contractsDisabled(res);
      const { code, sender, private_key } = req.body || {};
      if (!code || !sender) return res.status(400).json({ error: 'code, sender, and private_key required' });
      if (!private_key) return res.status(401).json({ error: 'private_key required to sign deploy tx' });
      try {
        const result = await this.smartContracts.CreateSmartContract(code, {}, sender, Number(nonce) || 0);
        res.json({ ...result, contractAddress: result.contractAddress });
        log('info', `[SMART CONTRACTS] Deployed contract: sender=${sender}, address=${result.contractAddress}, gasUsed=${result.gasUsed}`);
      } catch (e) {
        res.status(400).json({ error: e.code || 'CREATE_FAILED', message: e.message });
      }
    });

    app.post('/api/contracts/:address/snapshot', async (req, res) => {
      if (!contractsEnabled()) return contractsDisabled(res);
      try {
        const result = await this.smartContracts.SaveSmartContractState(req.params.address);
        res.json({ ok: true, ...result });
        log('info', `[SMART CONTRACTS] Saved snapshot for contract: address=${req.params.address}`);
      } catch (e) {
        res.status(400).json({ error: e.code || 'SNAPSHOT_FAILED', message: e.message });
      }
    });

    app.post('/api/contracts/call', mutationLimiter, async (req, res) => {
      if (!contractsEnabled()) return contractsDisabled(res);
      const { address, sender, data, value } = req.body || {};
      if (!address || !sender) return res.status(400).json({ error: 'address and sender required' });
      try {
        const result = await this.smartContracts.runSmartContract(address, sender, data || '0x', Number(value) || 0);
        res.json({ ok: true, returnValue: result.returnValue, gasUsed: result.gasUsed });
        log('info', `[SMART CONTRACTS] Called contract: address=${address}, sender=${sender}, gasUsed=${result.gasUsed}`);
      } catch (e) {
        log('error', `[SMART CONTRACTS] Failed to call contract: address=${address}, sender=${sender}, error=${e.message}`);
        res.status(400).json({ error: e.code || 'CALL_FAILED', message: e.message });
      }
    });

    app.post('/api/contracts/call-batch', mutationLimiter, async (req, res) => {
      if (!contractsEnabled()) return contractsDisabled(res);
      const { address, sender, calls } = req.body || {};
      if (!address || !sender || !Array.isArray(calls)) return res.status(400).json({ error: 'address, sender, and calls[] required' });
      const results = [];
      for (const call of calls) {
        try {
          const result = await this.smartContracts.runSmartContract(address, sender, call.data || '0x', Number(call.value) || 0);
          results.push({ ok: true, returnValue: result.returnValue, gasUsed: result.gasUsed });
        } catch (e) {
          results.push({ ok: false, error: e.message });
        }
      }
      res.json({ ok: true, results });
    });

    app.post('/api/contracts/execute', mutationLimiter, async (req, res) => {
      if (!contractsEnabled()) return contractsDisabled(res);
      try {
        const { address, sender, data, value, private_key } = req.body || {};
        if (!address) return res.status(400).json({ error: 'address required' });
        const calldata = data || '0x';
        if (!private_key) {
          const execSender = sender || this.cfg.minerAddress;
          const result = await this.smartContracts.runSmartContract(address, execSender, calldata, Number(value) || 0);
          return res.json({ ok: true, mode: 'read', returnValue: result.returnValue, gasUsed: result.gasUsed });
        }
        const pkHex = String(private_key).startsWith('0x') ? String(private_key).slice(2) : String(private_key);
        const key = Buffer.from(pkHex, 'hex');
        const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
        const privKeyObj = crypto.createPrivateKey({ key: Buffer.concat([prefix, key]), format: 'der', type: 'pkcs8' });
        const pubKeyObj = crypto.createPublicKey(privKeyObj);
        const pubB64 = pubKeyObj.export({ type: 'spki', format: 'der' }).subarray(12).toString('base64');
        const from_addr = sender || pubkeyToAddress(pubB64);
        const now = Math.floor(Date.now() / 1000);
        this.db.prepare('INSERT INTO users (address, public_key_ed25519, balance, nonce, created_at, updated_at) VALUES (?, ?, 0, 0, ?, ?) ON CONFLICT(address) DO UPDATE SET public_key_ed25519 = excluded.public_key_ed25519, updated_at = excluded.updated_at').run(from_addr, pubB64, now, now);
        const user = this.db.prepare('SELECT balance, nonce FROM users WHERE lower(address) = lower(?)').get(from_addr);
        const nonce = user ? (user.nonce || 0) : 0;
        const gasPrice = req.body.gas_price || this.chain._baseFeeForHeight(this.chain.height + 1);
        const gasLimit = req.body.gas_limit || 3000000;
        const tx = { from_addr, to_addr: address, value: String(Math.round(Number(value) || 0) * 1e18 || 0), nonce, fee: req.body.fee || String(gasLimit), gas_limit: gasLimit, gas_price: String(gasPrice), chain_id: this.cfg.chainId || '0', priority_fee: req.body.priority_fee || '0', data: calldata };
        const msg = canonicalTxMessage(tx);
        tx.signature = signMessage(msg, pkHex);
        tx.hash = hashTransaction(tx);
const validation = await this.chain.validateTxForMempool(tx);
        if (!validation.ok) return res.status(400).json({ ok: false, error: validation.motivo });
        const result = this.chain.addMempoolTx(tx);
        if (!result.ok) return res.status(400).json({ ok: false, error: result.motivo || 'failed to add transaction' });
        setImmediate(() => this.sync.broadcastTx(tx));
        if (this.p2pWsServer) this.p2pWsServer.broadcastTx(tx);
        res.json({ ok: true, mode: 'tx', hash: tx.hash, from: from_addr });
        log('info', `[SMART CONTRACTS] Executed contract tx: address=${address}, sender=${from_addr}, tx=${tx.hash}`);
      } catch (e) {
        res.status(400).json({ error: e.code || 'EXECUTE_FAILED', message: e.message });
      }
    });

    const p2pExchangeEnabled = () => !!this.cfg.p2pExchangeEnabled;
    const p2pExchangeDisabled = (res) => res.status(503).json({ error: 'P2P exchange disabled on this node', enabled: false });

    let p2pExchange = null;
    if (p2pExchangeEnabled()) {
      try {
        const { P2PExchange } = require('./vm/p2p-exchange');
        p2pExchange = new P2PExchange(this.chain, this.cfg);
        p2pExchange.initSchema();
        log('info', `[P2P-EXCHANGE] P2P exchange enabled`);
      } catch (e) {
        log('warn', `[P2P-EXCHANGE] Failed to initialize: ${e.message}`);
      }
    }

    app.get('/api/p2p/assets', (req, res) => {
      if (!p2pExchangeEnabled()) return p2pExchangeDisabled(res);
      if (!p2pExchange) return res.status(500).json({ error: 'P2P exchange not initialized' });
      res.json({ assets: p2pExchange.listAssets() });
    });

    app.post('/api/p2p/offers', mutationLimiter, async (req, res) => {
      if (!p2pExchangeEnabled()) return p2pExchangeDisabled(res);
      if (!p2pExchange) return res.status(500).json({ error: 'P2P exchange not initialized' });
      try {
        const result = await p2pExchange.createOffer(req.body);
        res.json(result);
      } catch (e) {
        res.status(400).json({ error: e.message });
      }
    });

    app.get('/api/p2p/offers', async (req, res) => {
      if (!p2pExchangeEnabled()) return p2pExchangeDisabled(res);
      if (!p2pExchange) return res.status(500).json({ error: 'P2P exchange not initialized' });
      const { pluginId, asset, status, limit, offset } = req.query;
      const result = await p2pExchange.listOffers({
        pluginId, asset, status, limit: parseInt(limit) || 50, offset: parseInt(offset) || 0
      });
      res.json(result);
    });

    app.get('/api/p2p/offers/:id', async (req, res) => {
      if (!p2pExchangeEnabled()) return p2pExchangeDisabled(res);
      if (!p2pExchange) return res.status(500).json({ error: 'P2P exchange not initialized' });
      const result = await p2pExchange.getOffer(req.params.id);
      res.json(result);
    });

    app.get('/api/p2p/offers/:id/status', async (req, res) => {
      if (!p2pExchangeEnabled()) return p2pExchangeDisabled(res);
      if (!p2pExchange) return res.status(500).json({ error: 'P2P exchange not initialized' });
      const result = await p2pExchange.getOfferStatus(req.params.id);
      res.json(result);
    });

    app.post('/api/p2p/offers/:id/take', requireAdmin, mutationLimiter, async (req, res) => {
      if (!p2pExchangeEnabled()) return p2pExchangeDisabled(res);
      if (!p2pExchange) return res.status(500).json({ error: 'P2P exchange not initialized' });
      try {
        const result = await p2pExchange.takeOffer({ offerId: req.params.id, ...req.body });
        res.json(result);
      } catch (e) {
        res.status(400).json({ error: e.message });
      }
    });

    app.post('/api/p2p/offers/:id/claim', requireAdmin, mutationLimiter, async (req, res) => {
      if (!p2pExchangeEnabled()) return p2pExchangeDisabled(res);
      if (!p2pExchange) return res.status(500).json({ error: 'P2P exchange not initialized' });
      try {
        const result = await p2pExchange.claimOffer({ offerId: req.params.id, ...req.body });
        res.json(result);
      } catch (e) {
        res.status(400).json({ error: e.message });
      }
    });

    app.post('/api/p2p/offers/:id/refund', requireAdmin, mutationLimiter, async (req, res) => {
      if (!p2pExchangeEnabled()) return p2pExchangeDisabled(res);
      if (!p2pExchange) return res.status(500).json({ error: 'P2P exchange not initialized' });
      try {
        const result = await p2pExchange.refundOffer({ offerId: req.params.id, ...req.body });
        res.json(result);
      } catch (e) {
        res.status(400).json({ error: e.message });
      }
    });

    app.post('/api/stake', requireAdmin, (req, res) => {
      const { amount, address } = req.body;
      if (!amount || !address) return res.status(400).json({ error: 'amount and address required' });
      res.json({ ok: true, amount: String(amount), address, stakeId: 'stake_' + Date.now() });
      log('info', `[STAKE] Received stake request: amount=${amount}, address=${address}`);
    });

    app.post('/api/node/settings', requireAdmin, (req, res) => {
      const updates = req.body;
      if (!updates || typeof updates !== 'object') return res.status(400).json({ error: 'settings object required' });
      Object.assign(this.cfg, updates);
      require('./config').saveConfig(this.cfg);
      res.json({ ok: true, config: this.cfg });
    });

    app.get('/api/logs', requireAdmin, (req, res) => res.json({ logs: getLogBuffer() }));

    app.post('/api/node/broadcast/block', p2pLimiter, async (req, res) => {
      const block = req.body.block;
      if (!block) return res.status(400).json({ error: 'block required' });
      const result = await this.chain.addBlock(block, {
        skipPocValidation: false,
        skipSignature: false,
        skipTargetValidation: false,
        skipStateValidation: false,
        skipHashValidation: false,
        forceSync: false,
      });
      log('info', `[P2P] broadcast block h=${block.height} hash=${(block.hash || '').slice(0, 10)} result=${result.motivo} height=${this.chain.height}`);
      res.json(result);
    });

    app.post('/api/node/broadcast/tx', p2pLimiter, async (req, res) => {
      const tx = req.body.tx;
      if (!tx) return res.status(400).json({ error: 'tx required' });
      const validation = await this.chain.validateTxForMempool(tx);
      if (!validation.ok) return res.status(400).json({ ok: false, error: validation.motivo });
      const result = this.chain.addMempoolTx(tx);
      log('info', `[TX] Mempool tx: hash=${tx.hash ? tx.hash.slice(0,10) : 'unknown'}, from=${tx.from_addr}, nonce=${tx.nonce}, result=${result.ok ? 'accepted' : 'rejected'}, reason=${result.motivo}`);
      if (result.ok && result.motivo !== 'Tx already in mempool') {
        const relayHops = safeInt(tx.relay_hops, 0);
        if (relayHops < 2) {
          setImmediate(() => this.sync.broadcastTx({ ...tx, relay_hops: relayHops + 1 }));
          if (this.p2pWsServer) this.p2pWsServer.broadcastTx({ ...tx, relay_hops: relayHops + 1 });
        }
      }
      res.json(result);
    });

    app.post('/api/node/announce', p2pLimiter, (req, res) => {
      const url = require('./config').normalizeUrl(req.body.url);
      if (!url) return res.status(400).json({ error: 'url required' });
      this.peers.add(url);
      this.peers.seen(url, safeInt(req.body.height, 0), req.body.node_id);
      log('info', `[P2P] Node announce: url=${url}, height=${req.body.height}, node_id=${req.body.node_id}`);
      res.json({ ok: true, our_height: this.chain.height, node_id: this.NODE_ID, peers: this.peers.gossipPeers(10) });
    });

    app.get('/peers', (req, res) => res.json({ peers: this.peers.gossipPeers(50), count: this.peers.count() }));
    app.get('/stats', (req, res) => {
      const ns = this.registry.getStats();
      res.json({ ...ns, chain_id: this.cfg.chainId, chain_name: this.cfg.chainName, symbol: this.cfg.symbol, seed_version: this.cfg.version, node_url: this.cfg.nodeUrl, node_id: this.NODE_ID });
    });

    app.post('/register', p2pLimiter, (req, res) => {
      const url = require('./config').normalizeUrl(req.body.url);
      if (!url || !req.body.node_id) return res.status(400).json({ error: 'url and node_id required' });
      this.peers.add(url);
      log('info', `[P2P] Registering peer: url=${url}, height=${req.body.height}, node_id=${req.body.node_id}`);
      this.peers.seen(url, safeInt(req.body.height, 0), req.body.node_id);
      this.registry.registerNode(url, req.body.node_id, { height: safeInt(req.body.height, 0), chain_work: req.body.chain_work, version: req.body.version, peers: safeInt(req.body.peers, 0) });
      res.json({ ok: true, peers: this.peers.gossipPeers(20), stats: this.registry.getStats(), chain_id: this.cfg.chainId });
    });

    app.post('/api/challenge/submit', mutationLimiter, (req, res) => {
      const { challenge_id, miner, plot_id, deadline, proof_packet, proof_signature } = req.body;
      if (!challenge_id || !miner || !plot_id || deadline == null) return res.status(400).json({ error: 'challenge_id, miner, plot_id, deadline required' });
      const packet = proof_packet || {};
      if (proof_signature && !packet.proof_signature) packet.proof_signature = proof_signature;
      const result = this.challengeMgr.submitProof(this.chain, challenge_id, miner, plot_id, safeInt(deadline, -1), packet);
      log('info', `[MINERS] Challenge submit: miner=${miner}, plot_id=${plot_id}, deadline=${deadline}, result=${result.ok ? 'accepted' : 'rejected'}, reason=${result.motivo}`);
      res.json(result);
    });

    app.post('/api/node/vote/request', (req, res) => {
      const { vote_id, proposer } = req.body;
      if (!vote_id || !proposer) return res.status(400).json({ error: 'vote_id and proposer required' });
      log('info', `[P2P] Vote request: vote_id=${vote_id}, proposer=${proposer}`);
      res.json({ vote_id, approve: true, reason: 'accepted', voter_address: this.cfg.minerAddress || '', stake: 0 });
    });

    app.post('/api/plots/add', requireAdmin, (req, res) => {
      const { miner, plot_id, size_gb, merkle_root = '' } = req.body;
      if (!miner || !plot_id || !size_gb) return res.status(400).json({ error: 'miner, plot_id, size_gb required' });
      this.db.prepare('INSERT OR IGNORE INTO plot_commitments (plot_id, miner, merkle_root, size_gb, created_at) VALUES (?,?,?,?,?)').run(plot_id, miner, merkle_root, parseFloat(size_gb), Math.floor(Date.now() / 1000));
      log('info', `[MINERS] Plot added: miner=${miner}, plot_id=${plot_id}, size_gb=${size_gb}`);
      res.json({ ok: true, plot_id, miner });
    });
    app.delete('/api/plots/:id', requireAdmin, (req, res) => { this.db.prepare('DELETE FROM plot_commitments WHERE plot_id = ?').run(req.params.id); res.json({ ok: true }); });

    app.post('/api/node/forge', requireAdmin, async (req, res) => {
      const challenge = this.challengeMgr.getOrCreate();
      if (!challenge) return res.status(400).json({ error: 'no challenge' });
      await this.challengeMgr._forgeBlockForChallenge(this.chain, this.sync, challenge);
      log('info', `[P2P] Forge block request: challenge_id=${challenge.challenge_id}, height=${this.chain.height}`);
      res.json({ ok: true });
    });

    app.get('/api/admin/wallets', requireAdmin, (req, res) => {
      res.json({ wallets: this.db.prepare('SELECT address, balance, nonce, created_at, updated_at FROM users ORDER BY CAST(balance AS INTEGER) DESC LIMIT 200').all() });
    });

    app.get('/api/rewards/:address', (req, res) => {
      const rewards = this.db.prepare('SELECT * FROM block_rewards WHERE miner = ? ORDER BY block_height DESC LIMIT 100').all(req.params.address);
      res.json({ rewards });
    });

    app.get('/api/transactions', (req, res) => {
      const address = req.query.address;
      const limit = Math.min(parseInt(req.query.limit) || 50, 200);
      let rows;
      if (address) rows = this.db.prepare('SELECT * FROM transactions WHERE from_addr = ? OR to_addr = ? ORDER BY block_height DESC LIMIT ?').all(address, address, limit);
      else rows = this.db.prepare('SELECT * FROM transactions ORDER BY block_height DESC LIMIT ?').all(limit);
      res.json({ transactions: rows });
    });

    app.get('/api/transaction/:hash', (req, res) => {
      const tx = this.db.prepare('SELECT * FROM transactions WHERE hash = ?').get(req.params.hash);
      if (!tx) return res.status(404).json({ error: 'not found' });
      res.json(tx);
    });

    app.get('/api/nodes', (req, res) => res.json({ nodes: this.registry.all() }));

    app.get('/api/health', (req, res) => res.json({
      ok: true, status: 'ok', height: this.chain.height, hash: this.chain.bestHash,
      peers: this.peers.count(), mempool: this.db.prepare('SELECT COUNT(*) as c FROM mempool').get().c,
      mining: this.miner.active, uptime: Math.floor((Date.now() - this._startTime) / 1000),
    }));

    app.get('/api/state', (req, res) => {
      const h = { height: this.chain.height, hash: this.chain.bestHash, chain_work: (this.chain.getBlock(this.chain.height) || {}).chain_work || '0', peers: this.peers.count(), uptime: Math.floor((Date.now() - this._startTime) / 1000) };
      const st = this.chain.getStats();
      const mining = { active: this.miner.active, address: this.miner.address, ...this.miner.getMetrics() };
      const mempoolTxs = this.chain.getMempoolForBlock(50);
      const mempoolCount = this.db.prepare('SELECT COUNT(*) as c FROM mempool').get().c;
      res.json({
        running: true, uptime: h.uptime,
        config: { port: this.cfg.port, minerAddress: this.cfg.minerAddress, miningEnabled: this.cfg.miningEnabled, seedPeers: this.cfg.seedPeers, discoveryPort: this.cfg.discoveryPort || 7777, chainId: this.cfg.chainId, chainName: this.cfg.chainName },
        wallets: this.db.prepare('SELECT address FROM users ORDER BY CAST(balance AS INTEGER) DESC LIMIT 50').all().map(w => ({ address: w.address, name: w.address, balance: null, encrypted: false })),
        node: { health: h, stats: st, mining, mempool: mempoolTxs, mempool_count: mempoolCount },
        network_storage: this._peerStorageCache,
        data_dir: this.cfg.dataDir || '',
      });
    });
    app.get('/health', (req, res) => res.json({ ok: true }));
    app.get('/health/liveness', (req, res) => res.json({ ok: true }));
    app.get('/health/readiness', (req, res) => res.json({ ok: true }));

    let port = this.cfg.port;
    this.server = require('http').createServer(app);
    this.server.listen(port, '0.0.0.0', () => {
      log('info', `HTTP server listening on port ${port}`);
    });
    this.server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        port++;
        this.cfg.port = port;
        this.server.listen(port);
        log('info', `Port busy, using ${port}`);
      } else {
        log('error', `Server error: ${err.message}`);
        process.exit(1);
      }
    });
    this._startTime = Date.now();
    this._fetchPeerStorage();
    setInterval(() => this._fetchPeerStorage(), 30000);
  }

  stop() {
    if (this.server) try { this.server.close(); } catch {}
  }
}

module.exports = { Server };