const crypto = require('crypto');
const { load } = require('./modules/index.js');

const pluginRegistry = load();

const SWAP_TIMEOUT = 24 * 60 * 60;

class P2PExchange {
  constructor(dex, cfg = {}) {
    this.dex = dex;
    this.cfg = cfg;
    this.plugins = pluginRegistry;
    this.enabled = cfg.p2pExchangeEnabled !== false;
    this.maxOffersPerUser = cfg.maxP2POffersPerUser || 50;
    this.offerTtlSec = cfg.p2pOfferTtlSec || SWAP_TIMEOUT;
  }

  _normalizeAddr(addr) {
    return addr ? addr.toLowerCase() : '';
  }

  _hashSecret(secretHex) {
    return crypto.createHash('sha256').update(Buffer.from(secretHex, 'hex')).digest('hex');
  }

  _genSecret() {
    return crypto.randomBytes(32).toString('hex');
  }

  _validatePlugin(pluginId) {
    const plugin = this.plugins[pluginId];
    if (!plugin) throw new Error(`Plugin ${pluginId} not loaded`);
    if (plugin.enabled === false) throw new Error(`Plugin ${pluginId} disabled`);
    return plugin;
  }

  async _getClient(pluginId, rpcUrl) {
    const plugin = this._validatePlugin(pluginId);
    return plugin.createClient(rpcUrl || plugin.defaultRpc);
  }

  async _getWallet(pluginId, privateKey) {
    const plugin = this._validatePlugin(pluginId);
    const key = privateKey || plugin.loadKey?.();
    if (!key) throw new Error(`No private key for ${pluginId}`);
    return plugin.createWallet(key);
  }

  listAssets() {
    const assets = {};
    for (const [id, plugin] of Object.entries(this.plugins)) {
      assets[id] = {
        asset: plugin.asset,
        decimals: plugin.decimals,
        chainId: plugin.defaultChainId,
        explorers: plugin.explorers,
        defaultRpc: plugin.defaultRpc,
      };
    }
    return assets;
  }

  async createOffer(opts) {
    if (!this.enabled) return { ok: false, error: 'P2P exchange disabled' };
    const {
      pluginId,
      fromAsset,
      toAsset,
      fromAmount,
      toAmount,
      privateKey,
      rpcUrl,
      timelockSec = 3600,
      memo = '',
    } = opts;

    const plugin = this._validatePlugin(pluginId);
    const wallet = await this._getWallet(pluginId, privateKey);
    const client = await this._getClient(pluginId, rpcUrl);
    const chainId = BigInt(opts.chainId || plugin.defaultChainId);

    const secret = this._genSecret();
    const hashlock = this._hashSecret(secret);
    const timelock = Math.floor(Date.now() / 1000) + timelockSec;

    const deployData = plugin.htlcInit(wallet.address, hashlock, timelock);
    const { hash, receipt, htlc } = await plugin.deployHtlc(client, wallet, {
      receiver: wallet.address,
      hashlock,
      timelock,
      amount: BigInt(fromAmount),
      chainId,
    });

    const offer = {
      id: crypto.createHash('sha256').update(`${htlc}:${Date.now()}`).digest('hex').slice(0, 16),
      pluginId,
      fromAsset: plugin.asset,
      toAsset,
      fromAmount: String(fromAmount),
      toAmount: String(toAmount),
      fromAddress: wallet.address,
      htlc,
      hashlock,
      timelock,
      secret,
      chainId: chainId.toString(),
      txHash: hash,
      createdAt: Math.floor(Date.now() / 1000),
      expiresAt: timelock,
      memo,
      status: 'pending',
      taker: null,
    };

    this.dex.db.prepare(`
      INSERT INTO p2p_offers (id, plugin_id, from_asset, to_asset, from_amount, to_amount, from_address, htlc, hashlock, timelock, secret, chain_id, tx_hash, created_at, expires_at, memo, status, taker)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(
      offer.id, pluginId, offer.fromAsset, offer.toAsset, offer.fromAmount, offer.toAmount,
      offer.fromAddress, htlc, hashlock, timelock, secret, chainId.toString(), hash,
      offer.createdAt, offer.expiresAt, memo, 'pending', ''
    );

    return { ok: true, offer: this._sanitizeOffer(offer) };
  }

  async getOffer(offerId) {
    const row = this.dex.db.prepare('SELECT * FROM p2p_offers WHERE id = ?').get(offerId);
    if (!row) return { ok: false, error: 'Offer not found' };
    return { ok: true, offer: this._sanitizeOffer(row) };
  }

  async listOffers(opts = {}) {
    const { pluginId, asset, status = 'pending', limit = 50, offset = 0 } = opts;
    let query = 'SELECT * FROM p2p_offers WHERE status = ?';
    const params = [status];
    if (pluginId) { query += ' AND plugin_id = ?'; params.push(pluginId); }
    if (asset) { query += ' AND (from_asset = ? OR to_asset = ?)'; params.push(asset, asset); }
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);
    const rows = this.dex.db.prepare(query).all(...params);
    return { ok: true, offers: rows.map(r => this._sanitizeOffer(r)) };
  }

  async takeOffer(opts) {
    const { offerId, takerPrivateKey, takerRpcUrl } = opts;
    const offer = await this.getOffer(offerId);
    if (!offer.ok) return offer;
    const o = offer.offer;

    if (o.status !== 'pending') return { ok: false, error: `Offer not available (${o.status})` };
    if (o.expiresAt < Math.floor(Date.now() / 1000)) return { ok: false, error: 'Offer expired' };

    const takerPlugin = this._validatePlugin(o.pluginId);
    const takerWallet = await this._getWallet(o.pluginId, takerPrivateKey);
    const takerClient = await this._getClient(o.pluginId, takerRpcUrl);
    const chainId = BigInt(o.chainId);

    const txHash = await this._sendToHtlc(takerPlugin, takerClient, takerWallet, {
      htlc: o.htlc,
      amount: BigInt(o.toAmount),
      chainId,
    });

    const takerSecret = this._genSecret();
    const takerHashlock = this._hashSecret(takerSecret);
    const takerTimelock = Math.floor(Date.now() / 1000) + Math.min(3600, o.timelock - Math.floor(Date.now() / 1000) - 60);

    const deployData = takerPlugin.htlcInit(takerWallet.address, takerHashlock, takerTimelock);
    const { hash: takerHtlcTx, htlc: takerHtlc } = await takerPlugin.deployHtlc(takerClient, takerWallet, {
      receiver: takerWallet.address,
      hashlock: takerHashlock,
      timelock: takerTimelock,
      amount: BigInt(o.toAmount),
      chainId,
    });

    this.dex.db.prepare(`
      UPDATE p2p_offers SET status = 'taken', taker = ?, taker_htlc = ?, taker_hashlock = ?, taker_timelock = ?, taker_secret = ?, taker_tx_hash = ?, taken_at = ?
      WHERE id = ?
    `).run(
      takerWallet.address, takerHtlc, takerHashlock, takerTimelock, takerSecret, takerHtlcTx,
      Math.floor(Date.now() / 1000), offerId
    );

    return { ok: true, offerId, takerHtlc, takerHashlock, takerTimelock, takerSecret, takerTxHash: takerHtlcTx };
  }

  async _sendToHtlc(plugin, client, wallet, { htlc, amount, chainId }) {
    const gasPrice = await client.gasPrice();
    const nonce = await client.getNonce(wallet.address);
    const gas = await client.estimateGas({ from: wallet.address, to: htlc, value: amount });
    const raw = wallet.signTx({ nonce, gasPrice, gas, to: htlc, value: amount, data: '0x', chainId });
    const hash = await client.sendRaw(raw);
    const receipt = await client.waitReceipt(hash);
    if (!receipt || receipt.status !== '0x1') throw new Error('Transfer to HTLC failed');
    return hash;
  }

  async claimOffer(opts) {
    const { offerId, claimerPrivateKey, claimerRpcUrl, role } = opts;
    const offer = await this.getOffer(offerId);
    if (!offer.ok) return offer;
    const o = offer.offer;

    if (!['maker', 'taker'].includes(role)) return { ok: false, error: 'Role must be maker or taker' };
    const isMaker = role === 'maker';
    const htlc = isMaker ? o.htlc : o.takerHtlc;
    const secret = isMaker ? o.takerSecret : o.secret;
    const counterSecret = isMaker ? o.secret : o.takerSecret;

    if (!htlc || !secret) return { ok: false, error: `${role} HTLC not yet created` };

    const plugin = this._validatePlugin(o.pluginId);
    const claimerWallet = await this._getWallet(o.pluginId, claimerPrivateKey);
    const claimerClient = await this._getClient(o.pluginId, claimerRpcUrl);
    const chainId = BigInt(o.chainId);

    try {
      const { hash: redeemHash } = await plugin.redeemHtlc(claimerClient, claimerWallet, {
        htlc, secretHex: secret, chainId,
      });

      this.dex.db.prepare(`
        UPDATE p2p_offers SET ${isMaker ? 'maker_redeemed_at' : 'taker_redeemed_at'} = ?, status = 
          CASE 
            WHEN ${isMaker ? 'taker_redeemed_at' : 'maker_redeemed_at'} IS NOT NULL THEN 'completed'
            ELSE 'partially_redeemed'
          END
        WHERE id = ?
      `).run(Math.floor(Date.now() / 1000), offerId);

      if (counterSecret) {
        const counterHtlc = isMaker ? o.takerHtlc : o.htlc;
        if (counterHtlc) {
          try {
            await plugin.redeemHtlc(claimerClient, claimerWallet, {
              htlc: counterHtlc, secretHex: counterSecret, chainId,
            });
            this.dex.db.prepare('UPDATE p2p_offers SET status = ? WHERE id = ?').run('completed', offerId);
          } catch (e) {
            console.warn('[P2P] Counter-party redeem failed:', e.message);
          }
        }
      }

      return { ok: true, offerId, redeemTxHash: redeemHash, role };
    } catch (e) {
      return { ok: false, error: `Claim failed: ${e.message}` };
    }
  }

  async refundOffer(opts) {
    const { offerId, refunderPrivateKey, refunderRpcUrl, role } = opts;
    const offer = await this.getOffer(offerId);
    if (!offer.ok) return offer;
    const o = offer.offer;

    if (!['maker', 'taker'].includes(role)) return { ok: false, error: 'Role must be maker or taker' };
    const isMaker = role === 'maker';
    const htlc = isMaker ? o.htlc : o.takerHtlc;

    if (!htlc) return { ok: false, error: `${role} HTLC not yet created` };
    if (o.expiresAt > Math.floor(Date.now() / 1000)) return { ok: false, error: 'Timelock not expired yet' };

    const plugin = this._validatePlugin(o.pluginId);
    const refunderWallet = await this._getWallet(o.pluginId, refunderPrivateKey);
    const refunderClient = await this._getClient(o.pluginId, refunderRpcUrl);
    const chainId = BigInt(o.chainId);

    try {
      const { hash: refundHash } = await plugin.refundHtlc(refunderClient, refunderWallet, {
        htlc, chainId,
      });

      this.dex.db.prepare(`
        UPDATE p2p_offers SET status = 'refunded', ${isMaker ? 'maker_refunded_at' : 'taker_refunded_at'} = ?, refund_tx_hash = ?
        WHERE id = ?
      `).run(Math.floor(Date.now() / 1000), refundHash, offerId);

      return { ok: true, offerId, refundTxHash: refundHash, role };
    } catch (e) {
      return { ok: false, error: `Refund failed: ${e.message}` };
    }
  }

  async getOfferStatus(offerId) {
    const offer = await this.getOffer(offerId);
    if (!offer.ok) return offer;
    const o = offer.offer;

    const plugin = this._validatePlugin(o.pluginId);
    const client = await this._getClient(o.pluginId);

    let makerHtlcStatus = null, takerHtlcStatus = null;
    try { makerHtlcStatus = await plugin.readHtlc(client, o.htlc); } catch {}
    if (o.takerHtlc) {
      try { takerHtlcStatus = await plugin.readHtlc(client, o.takerHtlc); } catch {}
    }

    return {
      ok: true,
      offer: this._sanitizeOffer(o),
      makerHtlc: makerHtlcStatus ? {
        amount: makerHtlcStatus.amount.toString(),
        redeemed: makerHtlcStatus.redeemed === 1n,
        refunded: makerHtlcStatus.refunded === 1n,
        timelock: makerHtlcStatus.timelock.toString(),
      } : null,
      takerHtlc: takerHtlcStatus ? {
        amount: takerHtlcStatus.amount.toString(),
        redeemed: takerHtlcStatus.redeemed === 1n,
        refunded: takerHtlcStatus.refunded === 1n,
        timelock: takerHtlcStatus.timelock.toString(),
      } : null,
    };
  }

  _sanitizeOffer(o) {
    const { secret, takerSecret, ...safe } = o;
    return {
      ...safe,
      hasSecret: !!secret,
      takerHasSecret: !!takerSecret,
      fromAmount: String(o.fromAmount),
      toAmount: String(o.toAmount),
    };
  }

  initSchema() {
    this.dex.db.exec(`
      CREATE TABLE IF NOT EXISTS p2p_offers (
        id TEXT PRIMARY KEY,
        plugin_id TEXT NOT NULL,
        from_asset TEXT NOT NULL,
        to_asset TEXT NOT NULL,
        from_amount TEXT NOT NULL,
        to_amount TEXT NOT NULL,
        from_address TEXT NOT NULL,
        htlc TEXT NOT NULL,
        hashlock TEXT NOT NULL,
        timelock INTEGER NOT NULL,
        secret TEXT NOT NULL,
        chain_id TEXT NOT NULL,
        tx_hash TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        memo TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        taker TEXT DEFAULT '',
        taker_htlc TEXT DEFAULT '',
        taker_hashlock TEXT DEFAULT '',
        taker_timelock INTEGER DEFAULT 0,
        taker_secret TEXT DEFAULT '',
        taker_tx_hash TEXT DEFAULT '',
        taken_at INTEGER DEFAULT 0,
        maker_redeemed_at INTEGER DEFAULT 0,
        taker_redeemed_at INTEGER DEFAULT 0,
        maker_refunded_at INTEGER DEFAULT 0,
        taker_refunded_at INTEGER DEFAULT 0,
        refund_tx_hash TEXT DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_p2p_status ON p2p_offers(status);
      CREATE INDEX IF NOT EXISTS idx_p2p_plugin ON p2p_offers(plugin_id);
      CREATE INDEX IF NOT EXISTS idx_p2p_from ON p2p_offers(from_address);
      CREATE INDEX IF NOT EXISTS idx_p2p_taker ON p2p_offers(taker);
    `);
  }
}

module.exports = { P2PExchange };