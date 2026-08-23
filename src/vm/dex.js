const { BN } = require('bn.js');
const { createBlock } = require('@ethereumjs/block');
const crypto = require('crypto');
const { AbiCoder, Interface, id } = require('ethers');
const { hashTransaction, ZERO_HASH, calculateMiningReward, computeStateRoot, computeContractStateRoot } = require('../crypto');
const { compileHTLC, compileLPMarket, compileCcPool } = require('./contracts/index.js');
const pluginRegistry = require('./modules/index.js');
const { privateToAddress } = require('@ethereumjs/util');

const WEI = 10n ** 18n;
const FEE = 21000n;
const ABI = AbiCoder.defaultAbiCoder();

function evmAddress(systemAddress) {
  return '0x' + systemAddress.replace(/^0x/i, '').slice(2);
}

function encodeCall(signature, ...args) {
  const name = signature.slice(0, signature.indexOf('('));
  const iface = new Interface([`function ${signature}`]);
  const normalizedArgs = args.map(a => {
    if (typeof a === 'bigint') return a;
    if (a && typeof a.toString === 'function') return a.toString();
    return a;
  });
  return iface.encodeFunctionData(name, normalizedArgs);
}

function selector(name) {
  return id(`${name}()`).slice(0, 10);
}

function pad32(hex) {
  return hex.replace(/^0x/i, '').padStart(64, '0');
}

function last40(returnValue) {
  return '0xcc' + returnValue.replace(/^0x/i, '').slice(-40);
}

function readUint(returnValue, offsetWords) {
  return BigInt('0x' + returnValue.replace(/^0x/i, '').slice(offsetWords * 64, offsetWords * 64 + 64));
}

function decodeWords(returnValue, count) {
  const hex = returnValue.replace(/^0x/i, '');
  const out = [];
  for (let i = 0; i < count; i++) out.push(BigInt('0x' + hex.slice(i * 64, i * 64 + 64)));
  return out;
}

function bn(b) {
  return new BN(b.toString());
}

function blockAt(timestamp) {
  return createBlock({ header: { timestamp: BigInt(timestamp) } });
}

function makeBlock(chain, blk, miner) {
  const parent = chain.getBlock(chain.height);
  const height = chain.height + 1;
  const now = blk.timestamp || Math.floor(Date.now() / 1000);
  return {
    height, parent_hash: parent ? parent.hash : ZERO_HASH,
    timestamp: now, miner: miner || '', challenge_id: '', nonce: '0', difficulty: '0',
    reward_units: '0', reward_cc: String(calculateMiningReward(height, {})),
    tx_root: '', tx_count: (blk.transactions || []).length, signature: '', generation_signature: ZERO_HASH,
    proof_digest: '', plot_id: '', origin: 'genesis', total_fees_units: '0', gas_used: 0, gas_limit: 30000000,
    base_target: String(chain._defaultBaseTarget()),
    transactions: blk.transactions || [], rewards: [], _from_local_forge: true, state_root: '',
    hash: '0x' + 'aa'.repeat(32),
  };
}

function ccTx(chain, from, to, value, nonce, data, ts) {
  const tx = {
    from_addr: from, to_addr: to || '', value: String(value), fee: String(FEE), nonce,
    gas_limit: 3000000, gas_price: '1', timestamp: ts, signature: '0x', data,
  };
  tx.hash = hashTransaction(tx);
  return tx;
}

function htlcInit(receiver, hashlock, timelock) {
  const ctorArgs = ABI.encode(['address', 'bytes32', 'uint256'], [evmAddress(receiver), '0x' + hashlock, BigInt(timelock)]);
  return '0x' + compileHTLC() + ctorArgs.slice(2);
}

function ccFromEthKey(privKeyHex) {
  return '0xcc' + privateToAddress(Buffer.from(String(privKeyHex).replace(/^0x/i, ''), 'hex')).toString('hex');
}

function formatAmount(wei, decimals = 18) {
  const d = Number(decimals);
  const s = wei.toString().padStart(d + 1, '0');
  const whole = s.slice(0, -d) || '0';
  const frac = s.slice(-d).replace(/0+$/, '');
  return whole + (frac ? '.' + frac : '');
}

const DEFAULT_TX_OPTS = {
  skipTxValidation: false, skipPocValidation: false, skipSignature: false,
  skipHashValidation: false, skipTargetValidation: false, skipStateValidation: false,
};

function createDex(opts) {
  const db = opts.db;
  const chain = opts.chain;
  const sc = opts.sc;
  const txOpts = opts.txOpts || DEFAULT_TX_OPTS;
  const miner = opts.miner || '';
  const plugins = opts.plugins || pluginRegistry.load();
  const nonces = new Map();
  for (const row of db.prepare('SELECT address, nonce FROM users').all()) {
    nonces.set(row.address.toLowerCase(), Number(row.nonce) || 0);
  }
  let ts = opts.startTs || Math.floor(Date.now() / 1000);
  let market = (opts.market || '').toLowerCase();
  let reader = (opts.reader || '').toLowerCase();
  let pool = (opts.pool || '').toLowerCase();
  let poolToken = (opts.poolToken || '').toLowerCase();
  const viewSender = () => reader || market || '0xcc' + '0'.repeat(40);
  const balanceOf = (addr) => {
    const row = db.prepare('SELECT balance FROM users WHERE lower(address) = lower(?)').get(addr);
    return row ? BigInt(row.balance) : 0n;
  };

  const dex = {
    chain, sc, db, WEI, FEE,
    plugins,
    plugin(id) { return plugins[id]; },
    nonces,
    reader() { return reader; },
    setReader(addr) { reader = addr.toLowerCase(); },
    market() { return market; },
    setMarket(addr) { market = addr.toLowerCase(); },
    pool() { return pool; },
    setPool(addr) { pool = addr.toLowerCase(); },
    poolToken() { return poolToken; },
    setPoolToken(addr) { poolToken = addr.toLowerCase(); },
    now() { return ts; },
    setNow(t) { ts = Math.max(ts, Math.floor(t)); return ts; },
    nonceOf(addr) { return nonces.get(addr.toLowerCase()) || 0; },
    setNonce(addr, n) { nonces.set(addr.toLowerCase(), Number(n)); },
    nextNonce(addr) {
      const a = addr.toLowerCase();
      const n = nonces.get(a) || 0;
      nonces.set(a, n + 1);
      return n;
    },
    balanceOf,
    payouts() {
      return db.prepare('SELECT to_addr, value FROM block_payouts ORDER BY height').all();
    },

    async add(tx, t) {
      const timestamp = t == null ? ++ts : t;
      if (t == null) ts = timestamp;
      const r = await chain.addBlock(makeBlock(chain, { transactions: [tx], timestamp }, miner), txOpts);
      if (!r.ok) {
        const err = new Error('bloco rejeitado: ' + (r.motivo || JSON.stringify(r)));
        err.result = r;
        throw err;
      }
      if (tx._ccApplied === false) {
        const err = new Error('tx revertida: ' + (tx._ccError || 'contract execution failed'));
        err.revert = tx._ccError;
        err.result = r;
        throw err;
      }
      return r;
    },

    async deployMarket(from) {
      const nonce = dex.nextNonce(from);
      market = sc.deriveContractAddress(from, nonce);
      reader = reader || from.toLowerCase();
      const t = ++ts;
      await dex.add(ccTx(chain, from, '', 0, nonce, '0x' + compileLPMarket(), t), t);
      return market;
    },

    async depositCc(from, amount) {
      const nonce = dex.nextNonce(from);
      const t = ++ts;
      await dex.add(ccTx(chain, from, market, amount, nonce, encodeCall('depositCc()'), t), t);
      return { nonce };
    },

    async withdrawCc(from, amount) {
      const nonce = dex.nextNonce(from);
      const t = ++ts;
      await dex.add(ccTx(chain, from, market, 0, nonce, encodeCall('withdrawCc(uint256)', bn(amount)), t), t);
      return { nonce };
    },

    async postQuote(from, q) {
      const nonce = dex.nextNonce(from);
      const t = ++ts;
      await dex.add(ccTx(chain, from, market, 0, nonce,
        encodeCall('postQuote(uint256,uint256,uint256,uint256,uint256,uint256)',
          bn(q.bid), bn(q.ask), bn(q.maxCc), bn(q.maxQuote), bn(q.feeBps), bn(q.expiresAt)), t), t);
      return { nonce };
    },

    async cancelQuote(from) {
      const nonce = dex.nextNonce(from);
      const t = ++ts;
      await dex.add(ccTx(chain, from, market, 0, nonce, encodeCall('cancelQuote()'), t), t);
      return { nonce };
    },

    async registerIntent(taker, p) {
      const nonce = dex.nextNonce(taker);
      const t = ++ts;
      await dex.add(ccTx(chain, taker, market, 0, nonce,
        encodeCall('registerSwapIntent(bytes32,address,uint256,uint256,uint256)',
          '0x' + p.hashlock, evmAddress(p.lp), bn(p.ccAmount), bn(p.quoteAmount), bn(p.t1)), t), t);
      return { nonce };
    },

    async deployHtlc(from, p) {
      const nonce = dex.nextNonce(from);
      const address = sc.deriveContractAddress(from, nonce);
      const t = ++ts;
      await dex.add(ccTx(chain, from, '', p.amount, nonce, htlcInit(p.receiver, p.hashlock, p.timelock), t), t);
      return { nonce, address };
    },

    async redeemHtlc(from, htlc, secretHex) {
      const nonce = dex.nextNonce(from);
      const t = ++ts;
      await dex.add(ccTx(chain, from, htlc, 0, nonce, encodeCall('redeem(bytes32)', '0x' + secretHex), t), t);
      return { nonce };
    },

    async refundHtlc(from, htlc) {
      const nonce = dex.nextNonce(from);
      const t = ++ts;
      await dex.add(ccTx(chain, from, htlc, 0, nonce, encodeCall('refund()'), t), t);
      return { nonce };
    },

    async settleTrade(lp, p) {
      const nonce = dex.nextNonce(lp);
      const t = ++ts;
      await dex.add(ccTx(chain, lp, market, 0, nonce,
        encodeCall('settleTrade(bytes32,bytes32)', '0x' + p.hashlock, '0x' + p.secret), t), t);
      return { nonce };
    },

    async _view(contract, sig, args, t) {
      const res = await sc.runSmartContract(contract, viewSender(), encodeCall(sig, ...(args || [])), 0, undefined, undefined, blockAt(t == null ? ts : t));
      return res.returnValue;
    },

    async quoteOf(lp, t) {
      const rv = await dex._view(market, 'quoteOf(address)', [evmAddress(lp)], t);
      const w = decodeWords(rv, 10);
      return {
        active: w[0] !== 0n,
        bidRate: w[1], askRate: w[2], maxCc: w[3], maxQuote: w[4],
        feeBps: w[5], updatedAt: w[6], expiresAt: w[7], filledCc: w[8], filledQuote: w[9],
      };
    },

    async isQuoteActive(lp, t) {
      return readUint(await dex._view(market, 'isQuoteActive(address)', [evmAddress(lp)], t), 0) === 1n;
    },

    async liquidityCc(lp, t) {
      return readUint(await dex._view(market, 'liquidityCc(address)', [evmAddress(lp)], t), 0);
    },

    async liquidityQuote(lp, t) {
      return readUint(await dex._view(market, 'liquidityQuote(address)', [evmAddress(lp)], t), 0);
    },

    async intent(hashlock, t) {
      const rv = await dex._view(market, 'intents(bytes32)', ['0x' + hashlock], t);
      const w = decodeWords(rv, 6);
      return {
        active: w[0] !== 0n,
        lp: last40('0x' + pad32(w[1].toString(16))),
        taker: last40('0x' + pad32(w[2].toString(16))),
        ccAmount: w[3], quoteAmount: w[4], t1: w[5],
      };
    },

    async htlc(addr) {
      const read = async (name) => sc.runSmartContract(addr, viewSender(), selector(name));
      const [amount, hashlock, timelock, sender, receiver, redeemed, refunded] = await Promise.all([
        read('amount'), read('hashlock'), read('timelock'), read('sender'), read('receiver'), read('redeemed'), read('refunded'),
      ]);
      return {
        amount: BigInt(amount.returnValue),
        hashlock: '0x' + pad32(hashlock.returnValue),
        timelock: BigInt(timelock.returnValue),
        sender: last40(sender.returnValue),
        receiver: last40(receiver.returnValue),
        redeemed: BigInt(redeemed.returnValue),
        refunded: BigInt(refunded.returnValue),
      };
    },

    async book(t) {
      const bestBid = readUint(await dex._view(market, 'bestBid()', [], t), 0);
      const bestAsk = readUint(await dex._view(market, 'bestAsk()', [], t), 0);
      const mid = readUint(await dex._view(market, 'midPrice()', [], t), 0);
      const lastPrice = readUint(await dex._view(market, 'lastPricePerCc()', [], t), 0);
      const totalTrades = readUint(await dex._view(market, 'totalTrades()', [], t), 0);
      const totalCcVolume = readUint(await dex._view(market, 'totalCcVolume()', [], t), 0);
      const totalQuoteVolume = readUint(await dex._view(market, 'totalQuoteVolume()', [], t), 0);
      const totalIntents = readUint(await dex._view(market, 'totalIntents()', [], t), 0);
      const lastTradeCc = readUint(await dex._view(market, 'lastTradeCc()', [], t), 0);
      const lastTradeQuote = readUint(await dex._view(market, 'lastTradeQuote()', [], t), 0);
      return { bestBid, bestAsk, mid, lastPrice, totalTrades, totalCcVolume, totalQuoteVolume, totalIntents, lastTradeCc, lastTradeQuote };
    },

    async createPool(from, token, feeBps) {
      const nonce = dex.nextNonce(from);
      pool = sc.deriveContractAddress(from, nonce);
      poolToken = String(token).toLowerCase();
      reader = reader || from.toLowerCase();
      const t = ++ts;
      const ctorArgs = ABI.encode(['address', 'uint256'], [evmAddress(poolToken), bn(feeBps == null ? 30 : feeBps)]);
      await dex.add(ccTx(chain, from, '', 0, nonce, '0x' + compileCcPool() + ctorArgs.slice(2), t), t);
      return pool;
    },

    async approveToken(from, token, spender, amount) {
      const nonce = dex.nextNonce(from);
      const t = ++ts;
      await dex.add(ccTx(chain, from, token, 0, nonce, encodeCall('approve(address,uint256)', evmAddress(spender), bn(amount)), t), t);
      return { nonce };
    },

    async addLiquidity(from, tokenAmount, ccAmount) {
      const nonce = dex.nextNonce(from);
      const t = ++ts;
      await dex.add(ccTx(chain, from, pool, ccAmount, nonce, encodeCall('addLiquidity(uint256)', bn(tokenAmount)), t), t);
      return { nonce };
    },

    async removeLiquidity(from, lpAmount) {
      const nonce = dex.nextNonce(from);
      const t = ++ts;
      await dex.add(ccTx(chain, from, pool, 0, nonce, encodeCall('removeLiquidity(uint256)', bn(lpAmount)), t), t);
      return { nonce };
    },

    async swapTokenForCc(from, tokenAmount) {
      const nonce = dex.nextNonce(from);
      const t = ++ts;
      await dex.add(ccTx(chain, from, pool, 0, nonce, encodeCall('swapTokenForCc(uint256)', bn(tokenAmount)), t), t);
      return { nonce };
    },

    async swapCcForToken(from, ccAmount) {
      const nonce = dex.nextNonce(from);
      const t = ++ts;
      await dex.add(ccTx(chain, from, pool, ccAmount, nonce, encodeCall('swapCcForToken()'), t), t);
      return { nonce };
    },

    async poolState(t) {
      const rv = await dex._view(pool, 'poolState()', [], t);
      const w = decodeWords(rv, 5);
      return {
        tokenReserve: w[0], ccReserve: w[1], lpSupply: w[2],
        priceCcPerToken: w[3], priceTokenPerCc: w[4],
      };
    },

    async tokenBalanceOf(addr, t) {
      return readUint(await dex._view(poolToken, 'balanceOf(address)', [evmAddress(addr)], t), 0);
    },

    async poolBalance() {
      return BigInt((await sc.getAccountBalance(market, market)).toString());
    },

    async poolCcBalance() {
      return BigInt((await sc.getAccountBalance(pool, pool)).toString());
    },

    async stateRoots() {
      const tip = chain.getBlock(chain.height);
      return {
        stateRoot: tip.state_root,
        stateRecompute: computeStateRoot(db),
        contractStateRoot: tip.contract_state_root,
        contractStateRecompute: computeContractStateRoot(db),
      };
    },

    newSecret() {
      const secret = crypto.randomBytes(32);
      return { secret, hashlock: crypto.createHash('sha256').update(secret).digest('hex') };
    },

    async swap(p) {
      const { taker, lp, lpCollateral, quote, ccAmount, quoteAmount, t1, t2 } = p;
      const log = p.log || (() => {});
      const toPool = p.toPool !== false;
      const plugin = p.plugin || (p.asset && plugins[p.asset]);
      const secret = Buffer.isBuffer(p.secret) ? p.secret : Buffer.from(String(p.secret || '').replace(/^0x/i, ''), 'hex');
      const secretHex = secret.toString('hex');
      const hashlock = p.hashlock || crypto.createHash('sha256').update(secret).digest('hex');

      log('CC', 'deploy LPMarket');
      await dex.deployMarket(lp);
      log('CC', 'LP trava ' + formatAmount(lpCollateral) + ' CC de colateral');
      await dex.depositCc(lp, lpCollateral);
      log('CC', 'postQuote (bid ' + formatAmount(quote.bid) + ' / ask ' + formatAmount(quote.ask) + ' por CC)');
      await dex.postQuote(lp, quote);
      log('CC', 'registerSwapIntent (' + formatAmount(ccAmount) + ' CC -> ' + formatAmount(quoteAmount) + ', T1=' + t1 + ')');
      await dex.registerIntent(taker, { hashlock, lp, ccAmount, quoteAmount, t1 });
      const htlcCC = (await dex.deployHtlc(taker, { receiver: lp, hashlock, timelock: t1, amount: ccAmount })).address;
      log('CC', 'HTLC-CC em ' + htlcCC + ' (trava ' + formatAmount(ccAmount) + ' CC)');

      let counter = { mode: 'skipped' };
      if (plugin) {
        const sym = plugin.asset || plugin.id;
        const client = plugin.createClient(p.rpc);
        const wallet = p.wallet || (plugin.loadKey && plugin.createWallet(plugin.loadKey()));
        if (!wallet || !wallet.address) throw new Error('sem carteira para o plugin ' + plugin.id + ' (defina ' + plugin.id + '_PRIVATE_KEY)');
        const receiver = (p.receiver || wallet.address).toLowerCase();
        const chainId = p.chainId !== undefined ? BigInt(p.chainId) : await client.chainId();
        const netChainId = await client.chainId();
        if (netChainId !== chainId) throw new Error('RPC chainId ' + netChainId + ' != ' + plugin.id + '_CHAIN_ID ' + chainId + ' (use RPC/CHAIN_ID consistentes)');
        const info = plugin.explorerFor ? plugin.explorerFor(chainId) : { name: '', explorer: '' };
        log(sym, 'rede ' + chainId + (info.name ? ' (' + info.name + ')' : '') + ' | wallet ' + wallet.address + ' | receiver ' + receiver);
        const bal = await client.getBalance(wallet.address);
        const gasPrice = await client.gasPrice();
        let estDeploy = 400000n;
        if (plugin.estimateDeployGas) {
          try {
            estDeploy = await plugin.estimateDeployGas(client, wallet, { receiver, hashlock, timelock: t2, amount: quoteAmount });
          } catch { estDeploy = 400000n; }
        }
        const gasFund = p.gasFund || (plugin.gasFund ? plugin.gasFund() : 0n);
        const need = quoteAmount + gasFund + (estDeploy + 120000n) * gasPrice;
        const fmt = plugin.weiToAsset || ((w) => w.toString());
        if (bal < need) {
          throw new Error(sym + ' insuficiente na wallet ' + wallet.address + ': precisa ~' + fmt(need) + ' ' + sym + ', tem ' + fmt(bal));
        }
        if (!plugin.deployHtlc) throw new Error('plugin ' + plugin.id + ' sem deployHtlc');
        log(sym, 'deploy HTLC-' + sym + ' (trava ' + fmt(quoteAmount) + ' ' + sym + ', T2=' + t2 + ')');
        const deploy = await plugin.deployHtlc(client, wallet, { receiver, hashlock, timelock: t2, amount: quoteAmount, chainId });
        const htlcX = deploy.htlc || (deploy.receipt && deploy.receipt.contractAddress);
        if (!htlcX) throw new Error('deploy HTLC-' + sym + ' sem endereço');
        if (plugin.readHtlc) {
          const g1 = await plugin.readHtlc(client, htlcX);
          if (g1.amount !== quoteAmount || String(g1.sender).toLowerCase() !== wallet.address.toLowerCase() || String(g1.receiver).toLowerCase() !== receiver) {
            throw new Error('HTLC-' + sym + ' com estado inesperado');
          }
        }
        if (p.redeemerWallet) {
          const redeemer = p.redeemerWallet;
          if (redeemer.address.toLowerCase() !== wallet.address.toLowerCase()) {
            log(sym, 'funda gas do receiver (' + fmt(gasFund) + ' ' + sym + ')');
            if (!plugin.fundGas) throw new Error('plugin ' + plugin.id + ' sem fundGas');
            await plugin.fundGas(client, wallet, redeemer.address, { amount: gasFund, chainId });
          }
          log(sym, 'redeem HTLC-' + sym + ' revelando S');
          if (!plugin.redeemHtlc) throw new Error('plugin ' + plugin.id + ' sem redeemHtlc');
          const redeem = await plugin.redeemHtlc(client, redeemer, { htlc: htlcX, secretHex, chainId });
          if (plugin.readHtlc) {
            const g2 = await plugin.readHtlc(client, htlcX);
            if (g2.redeemed !== 1n) throw new Error('HTLC-' + sym + ' não redeemado');
          }
          counter = { mode: 'live', asset: sym, chainId, htlc: htlcX, receiver, deployHash: deploy.hash, redeemHash: redeem.hash };
        } else {
          counter = { mode: 'live-manual', asset: sym, chainId, htlc: htlcX, receiver, deployHash: deploy.hash, secret: '0x' + secretHex };
        }
      }

      log('CC', 'LP resgata HTLC-CC com S (antes de T1)');
      await dex.redeemHtlc(lp, htlcCC, secretHex);
      log('CC', 'settleTrade (prova de S + debita liquidez + feed)');
      await dex.settleTrade(lp, { hashlock, secret: secretHex });
      if (toPool) {
        log('CC', 'CC da troca entra no pool e sai via withdraw');
        await dex.depositCc(lp, ccAmount);
        await dex.withdrawCc(lp, ccAmount);
      }

      const summary = {
        market, htlcCC, secret: '0x' + secretHex, hashlock: '0x' + hashlock,
        counter,
        quote: await dex.quoteOf(lp),
        book: await dex.book(),
        liquidityCc: await dex.liquidityCc(lp),
        liquidityQuote: await dex.liquidityQuote(lp),
        pool: await dex.poolBalance(),
        balanceTaker: balanceOf(taker),
        balanceLp: balanceOf(lp),
        payouts: dex.payouts(),
        roots: await dex.stateRoots(),
      };
      return summary;
    },
  };

  return dex;
}

module.exports = {
  createDex, WEI, FEE, evmAddress, encodeCall, blockAt, readUint, decodeWords, htlcInit, ccTx, makeBlock,
  ccFromEthKey, formatAmount, bn, DEFAULT_TX_OPTS,
};