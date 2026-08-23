const fs = require('fs');
const os = require('os');
const path = require('path');

const { initDB } = require('../Blockchain/db');
const { Chain } = require('../Blockchain/chain');
const SC = require('./smartcontracts');
const { createDex, WEI, ccFromEthKey, formatAmount } = require('./dex');
const { load } = require('./modules/index.js');

const plugins = load();
const ASSET = process.env.SWAP_ASSET || 'POL';
const P = plugins[ASSET];
if (!P) throw new Error('Plugin ' + ASSET + ' not found (available: ' + Object.keys(plugins).join(', ') + ')');
const SYM = P.asset || P.id;

const SWAP_CC = BigInt(Math.round(Number(process.env.SWAP_CC || '0.2') * 1e18));
const RATE = BigInt(process.env.RATE || '1950000000000000000');
const ASK_RATE = BigInt(process.env.ASK_RATE || String(RATE + 10n ** 17n));
const QUOTE_AMOUNT = (SWAP_CC * RATE) / WEI;
const LP_COLLATERAL = BigInt(Math.round(Number(process.env.LP_COLLATERAL || '100') * 1e18));
const LP_QUOTE_LIQUIDITY = BigInt(Math.round(Number(process.env.LP_QUOTE_LIQUIDITY || String(Number(QUOTE_AMOUNT) * 2)) * 1e18));
const FEE_BPS = Number(process.env.FEE_BPS || '250');
const T1_SEC = Number(process.env.T1_SEC || '3600');
const T2_SEC = Number(process.env.T2_SEC || '1800');
const LIVE_GAS_FUND = BigInt(process.env.LIVE_GAS_FUND || '10000000000000000');
const FEE = 21000n;

const KEY_ENV = ASSET + '_PRIVATE_KEY';
const RPC_ENV = ASSET + '_RPC';
const CHAIN_ID_ENV = ASSET + '_CHAIN_ID';
const RECEIVER_ENV = ASSET + '_RECEIVER';
const REDEEMER_ENV = ASSET + '_REDEEMER_KEY';

async function runSwap() {
  const key = process.env[KEY_ENV] || P.loadKey();
  if (!key) throw new Error('Missing private key: ' + KEY_ENV + ' or plugin key');
  const lpCc = ccFromEthKey(key);
  const lpWallet = P.createWallet(key);
  const receiver = (process.env[RECEIVER_ENV] || lpWallet.address).toLowerCase();
  let redeemerWallet;
  if (process.env[REDEEMER_ENV]) redeemerWallet = P.createWallet(process.env[REDEEMER_ENV]);
  else if (receiver === lpWallet.address.toLowerCase()) redeemerWallet = lpWallet;

  const chainId = BigInt(process.env[CHAIN_ID_ENV] || P.defaultChainId.toString());
  const info = P.explorerFor(chainId);
  const mainnet = !!info.mainnet;
  if (mainnet) {
    if (process.env.SWAP_CC === undefined) throw new Error('Mainnet: SWAP_CC must be set');
    if (QUOTE_AMOUNT > 2n * WEI) throw new Error('Mainnet: SWAP_CC too large (>2 ' + SYM + ')');
  }

  const taker = process.env.MINER_ADDRESS;
  if (!taker) throw new Error('MINER_ADDRESS not set');
  const realDb = initDB(path.join(__dirname, '..', '..', 'db', 'choco-node.db'), {});
  const user = realDb.prepare('SELECT address, balance, nonce FROM users WHERE lower(address) = lower(?)').get(taker);
  realDb.close();
  if (!user) throw new Error('Wallet ' + taker + ' not found in db');
  const takerBal = BigInt(user.balance);
  const takerNonce = Number(user.nonce);
  if (takerBal < SWAP_CC + 2n * FEE) throw new Error('Insufficient CC balance: need ' + formatAmount(SWAP_CC + 2n * FEE));

  console.log('=== CC -> ' + SYM + ' SWAP (LPMarket + dual HTLC) — plugin ' + P.id + ' ===');
  console.log('Seller (CC)  : ' + taker + '  balance ' + formatAmount(takerBal) + ' CC, nonce ' + takerNonce);
  console.log('LP (CC)      : ' + lpCc);
  console.log('LP (' + SYM + ') : ' + lpWallet.address);
  console.log('Receiver     : ' + receiver + (redeemerWallet ? ' (auto-redeem)' : ' (manual)'));
  console.log('Swap         : ' + formatAmount(SWAP_CC) + ' CC -> ' + formatAmount(QUOTE_AMOUNT) + ' ' + SYM + ' (rate ' + formatAmount(RATE) + ')');
  console.log('Network      : ' + (info.name || chainId) + (chainId === P.defaultChainId ? '' : ' (chainId ' + chainId + ')'));
  console.log('Note         : CC chain is local sandbox; ' + SYM + ' side is live.\n');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cc-swap-'));
  const ccDb = initDB(path.join(tmpDir, 'cc.db'), {});
  const chain = new Chain(ccDb, { maxFutureBlockSec: 60, minGasPrice: 10 ** 9, expectedTimePerBlock: 240 });
  SC.setDatabase(ccDb);
  chain.setContractExecutor(SC);
  const now = Math.floor(Date.now() / 1000);
  const seed = (addr, bal, nonce) =>
    ccDb.prepare('INSERT OR IGNORE INTO users (address, balance, nonce, created_at, updated_at) VALUES (?,?,?,?,?)')
      .run(addr, String(bal), nonce || 0, now, now);
  seed(taker, takerBal, takerNonce);
  seed(lpCc, LP_COLLATERAL + 1n * WEI, 0);

  const dex = createDex({ db: ccDb, chain, sc: SC, miner: taker, plugins });
  const t1 = now + T1_SEC;
  const t2 = now + T2_SEC;
  const log = (side, msg) => console.log('  [' + side + '] ' + msg);

  const summary = await dex.swap({
    taker,
    lp: lpCc,
    lpCollateral: LP_COLLATERAL,
    quote: { bid: RATE, ask: ASK_RATE, maxCc: LP_COLLATERAL, maxQuote: LP_QUOTE_LIQUIDITY, feeBps: FEE_BPS, expiresAt: now + 7200 },
    ccAmount: SWAP_CC,
    quoteAmount: QUOTE_AMOUNT,
    t1, t2,
    plugin: P,
    rpc: process.env[RPC_ENV],
    chainId,
    wallet: lpWallet,
    receiver,
    redeemerWallet,
    gasFund: LIVE_GAS_FUND,
    log,
  });

  console.log('\n--- Summary ---');
  console.log('Market LPMarket : ' + summary.market);
  console.log('HTLC-CC         : ' + summary.htlcCC + '  (lock ' + formatAmount(SWAP_CC) + ' CC)');
  console.log('Secret S        : ' + summary.secret);
  console.log('Hashlock H      : ' + summary.hashlock);
  const q = summary.quote;
  console.log('LP Quote        : bid ' + formatAmount(q.bidRate) + ' / ask ' + formatAmount(q.askRate) + ' ' + SYM + '/CC, filled ' + formatAmount(q.filledCc) + ' CC / ' + formatAmount(q.filledQuote) + ' ' + SYM);
  const b = summary.book;
  console.log('Book            : bestBid ' + formatAmount(b.bestBid) + ', bestAsk ' + formatAmount(b.bestAsk) + ', lastPrice ' + formatAmount(b.lastPrice) + ', ' + b.totalTrades + ' trade(s)');
  console.log('Liquidity       : CC ' + formatAmount(summary.liquidityCc) + ' (collateral) | ' + SYM + ' ' + formatAmount(summary.liquidityQuote) + ' (after debit)');
  console.log('Pool (contract) : ' + formatAmount(summary.pool) + ' CC');
  console.log('Final seller    : ' + formatAmount(summary.balanceTaker) + ' CC');
  console.log('Final LP        : ' + formatAmount(summary.balanceLp) + ' CC');

  if (summary.counter.mode === 'live') {
    console.log(SYM + ' side       : LIVE — HTLC-' + SYM + ' ' + summary.counter.htlc);
    console.log('                  deploy ' + info.explorer + '/tx/' + summary.counter.deployHash);
    console.log('                  redeem ' + info.explorer + '/tx/' + summary.counter.redeemHash);
  } else if (summary.counter.mode === 'live-manual') {
    console.log(SYM + ' side       : HTLC-' + SYM + ' ' + summary.counter.htlc + ' (network ' + summary.counter.chainId + ')');
    console.log('                  deploy ' + info.explorer + '/tx/' + summary.counter.deployHash);
    console.log('                  WAITING MANUAL REDEEM from ' + summary.counter.receiver);
    console.log('                  redeem(bytes32) with secret: ' + summary.counter.secret);
  } else {
    console.log(SYM + ' side       : not executed');
  }

  console.log('\n--- Verification ---');
  let fails = 0;
  const expect = (cond, msg) => {
    console.log('  [' + (cond ? 'OK' : 'FAIL') + '] ' + msg);
    if (!cond) fails++;
  };
  const htlc = await dex.htlc(summary.htlcCC);
  expect(htlc.redeemed === 1n, 'HTLC-CC redeemed');
  expect(htlc.hashlock === summary.hashlock, 'hashlock matches');
  expect(q.filledCc === SWAP_CC && q.filledQuote === QUOTE_AMOUNT, 'quote fully filled');
  expect(b.totalTrades === 1n && b.lastPrice === RATE, 'lastPrice = ' + formatAmount(RATE));
  expect(summary.liquidityQuote === LP_QUOTE_LIQUIDITY - QUOTE_AMOUNT, SYM + ' liquidity debited');
  expect(summary.balanceTaker === takerBal - SWAP_CC - 2n * FEE, 'seller balance correct');
  expect(summary.balanceLp === 1n * WEI + SWAP_CC - 7n * FEE, 'LP balance correct');
  expect(summary.roots.stateRoot === summary.roots.stateRecompute, 'state_root matches');
  expect(summary.roots.contractStateRoot === summary.roots.contractStateRecompute, 'contract_state_root matches');

  ccDb.close();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}

  console.log('\n=== RESULT ===');
  if (fails) console.log('Some checks failed.');
  else if (summary.counter.mode === 'live-manual') console.log('HTLC-' + SYM + ' locked for ' + receiver + '. Manual redeem pending with secret above.');
  else if (summary.counter.mode === 'live') console.log('CC -> ' + SYM + ' live swap completed: ' + formatAmount(SWAP_CC) + ' CC sold, ' + formatAmount(QUOTE_AMOUNT) + ' ' + SYM + ' delivered.');
  else console.log('CC -> ' + SYM + ' swap (side not executed).');
  process.exitCode = fails ? 1 : 0;
}

if (require.main === module) {
  runSwap().catch(e => {
    console.error('SWAP ERROR:', e.code || '', e.message);
    process.exitCode = 1;
  });
}