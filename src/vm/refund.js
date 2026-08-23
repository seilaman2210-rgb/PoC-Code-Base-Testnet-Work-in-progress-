const crypto = require('crypto');
const { load } = require('./modules/index.js');

const ASSET = process.env.REFUND_ASSET || 'POL';
const plugins = load();
const plugin = plugins[ASSET];
if (!plugin) throw new Error('plugin ' + ASSET + ' not found in src/vm/modules');

const SYM = plugin.asset || plugin.id;

let fails = 0;
function expect(cond, label) {
  console.log('  [' + (cond ? 'OK  ' : 'FAIL') + '] ' + label);
  if (!cond) fails++;
}

function gasCost(receipt) {
  return BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPrice);
}

async function refundExistingHtlc({ client, lp, submit, target, explorer }) {
  const now = Math.floor(Date.now() / 1000);
  const g = await plugin.readHtlc(client, target);
  console.log('HTLC ' + target + ': amount=' + plugin.weiToAsset(g.amount) + ' ' + SYM +
    ', sender=' + g.sender + ', receiver=' + g.receiver + ', timelock=' + g.timelock);

  expect(g.refunded === 0n && g.redeemed === 0n, 'contract not yet settled');
  expect(BigInt(now) > g.timelock, 'timelock expired (' + now + ' > ' + g.timelock + ')');
  if (g.refunded !== 0n || g.redeemed !== 0n || BigInt(now) <= g.timelock) return;

  const before = await client.getBalance(lp.address);
  const refund = await submit(lp, { to: target, data: plugin.encodeCall('refund()') }, 'refund executed');
  const after = await client.getBalance(lp.address);
  const g2 = await plugin.readHtlc(client, target);

  expect(g2.refunded === 1n, 'refunded = true on-chain');
  expect(await client.getBalance(target) === 0n, 'contract balance zeroed');
  expect(after - before === g.amount - gasCost(refund.receipt), 'LP recovered ' + plugin.weiToAsset(g.amount) + ' ' + SYM + ' (net of gas)');

  console.log('\nRefund complete: ' + SYM + ' returned to ' + lp.address + ' (' + explorer + '/tx/' + refund.hash + ')');
}

async function deployAndRefund({ client, lp, chainId, explorer }) {
  const now = Math.floor(Date.now() / 1000);
  const amount = BigInt(process.env.REFUND_AMOUNT || '5000000000000000');
  const receiver = process.env.REFUND_RECEIVER || lp.address;
  const timelock = now - 60;
  const hashlock = crypto.createHash('sha256').update(crypto.randomBytes(32)).digest('hex');

  console.log('[1] Locking ' + plugin.weiToAsset(amount) + ' ' + SYM + ' in an HTLC with an expired timelock (T=' + timelock + ', receiver=' + receiver + ')');
  const deploy = await plugin.deployHtlc(client, lp, { receiver, hashlock, timelock, amount, chainId });
  expect(deploy.receipt && deploy.receipt.status === '0x1', 'HTLC deploy succeeded');
  const htlc = deploy.htlc;
  expect(!!htlc, 'HTLC deployed at ' + htlc);

  let g = await plugin.readHtlc(client, htlc);
  expect(g.amount === amount, 'amount = ' + plugin.weiToAsset(amount) + ' ' + SYM);
  expect(await client.getBalance(htlc) === amount, SYM + ' locked in contract');

  console.log('\n[2] Immediate refund (timelock already expired)');
  const before = await client.getBalance(lp.address);
  const refund = await plugin.refundHtlc(client, lp, { htlc, chainId });
  expect(refund.receipt && refund.receipt.status === '0x1', 'refund tx succeeded');
  const after = await client.getBalance(lp.address);
  g = await plugin.readHtlc(client, htlc);

  expect(g.refunded === 1n, 'refunded = true on-chain');
  expect(g.redeemed === 0n, 'not redeemed');
  expect(await client.getBalance(htlc) === 0n, 'contract balance zeroed (' + SYM + ' returned to LP)');
  expect(after - before === amount - gasCost(refund.receipt), 'LP recovered ' + plugin.weiToAsset(amount) + ' ' + SYM + ' (net of gas)');

  console.log('\n=== Live refund validated ===');
  console.log('  deploy:   ' + explorer + '/tx/' + deploy.hash);
  console.log('  refund:   ' + explorer + '/tx/' + refund.hash);
  console.log('  contract: ' + explorer + '/address/' + htlc);
}

async function runRefund() {
  const chainId = BigInt(process.env[plugin.id + '_CHAIN_ID'] || plugin.defaultChainId.toString());
  const info = plugin.explorerFor(chainId);
  const explorer = info.explorer;
  const privKey = plugin.loadKey();
  if (!privKey) throw new Error('missing key for plugin ' + plugin.id + ' (' + plugin.id + '_PRIVATE_KEY)');

  const client = plugin.createClient(process.env[plugin.id + '_RPC']);
  const lp = plugin.createWallet(privKey);
  const target = process.env.REFUND_HTLC;

  console.log('=== LIVE REFUND (' + (info.name || chainId) + ') — plugin ' + plugin.id + ' ===');
  console.log('LP wallet: ' + lp.address + '\n');

  const submit = async (wallet, params, label) => {
    const { hash, receipt } = await plugin.walletSend(client, wallet, { ...params, chainId });
    expect(receipt && receipt.status === '0x1', label + ' (tx ' + hash.slice(0, 10) + '... ' + explorer + '/tx/' + hash + ')');
    return { hash, receipt };
  };

  if (target) {
    await refundExistingHtlc({ client, lp, submit, target, explorer });
  } else {
    await deployAndRefund({ client, lp, chainId, explorer });
  }

  console.log('\n=== RESULT ===');
  console.log(fails ? 'Some checks failed.' : 'HTLC refund validated (' + info.name + ').');
  process.exitCode = fails ? 1 : 0;
}

if (require.main === module) {
  runRefund().catch((e) => {
    console.error('Refund error:', e.code || '', e.message);
    process.exitCode = 1;
  });
}

module.exports = { runRefund };