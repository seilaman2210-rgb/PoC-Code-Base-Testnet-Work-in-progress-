const axios = require('axios');
const crypto = require('crypto');
const { privateToAddress, setLengthLeft } = require('@ethereumjs/util');
const { secp256k1 } = require('@noble/curves/secp256k1.js');
const rlp = require('@ethereumjs/rlp');
const { AbiCoder, Interface, keccak256 } = require('ethers');
const { compileHTLC: compileHTLCImpl } = require('./contracts/index.js');

const ABI = AbiCoder.defaultAbiCoder();

function ecsign(msgHash, privateKey) {
  const raw = secp256k1.sign(new Uint8Array(msgHash), new Uint8Array(privateKey), { format: 'recovered' });
  return {
    r: Buffer.from(raw.slice(1, 33)),
    s: Buffer.from(raw.slice(33, 65)),
    v: raw[0] + 27,
  };
}

function hexBuf(hex) {
  let h = String(hex).replace(/^0x/i, '');
  if (h.length % 2) h = '0' + h;
  return Buffer.from(h, 'hex');
}

function bigBuf(b) {
  if (b === 0n) return Buffer.alloc(0);
  const hex = b.toString(16);
  const buf = Buffer.from((hex.length % 2 ? '0' + hex : hex), 'hex');
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0) i++;
  return buf.slice(i);
}

function hexify(buf) {
  return '0x' + buf.toString('hex');
}

function encodeCall(signature, ...args) {
  const name = signature.slice(0, signature.indexOf('('));
  const iface = new Interface([`function ${signature}`]);
  return iface.encodeFunctionData(name, args);
}

function weiToDec(wei, decimals = 18) {
  const d = Number(decimals);
  const s = wei.toString().padStart(d + 1, '0');
  const whole = s.slice(0, -d) || '0';
  const frac = s.slice(-d).replace(/0+$/, '');
  return whole + (frac ? '.' + frac : '');
}

function htlcDeployData(receiver, hashlockHex, timelock, bytecode) {
  const ctorArgs = ABI.encode(['address', 'bytes32', 'uint256'], [receiver, '0x' + hashlockHex, BigInt(timelock)]);
  return '0x' + bytecode + ctorArgs.slice(2);
}

function createClient(url, timeoutMs = 20000) {
  async function _call(method, params) {
    const body = JSON.stringify({ jsonrpc: '2.0', id: Date.now() % 1000000000, method, params: params || [] }, (k, v) =>
      typeof v === 'bigint' ? '0x' + v.toString(16) : v);
    const res = await axios.post(url, body, { timeout: timeoutMs, headers: { 'Content-Type': 'application/json' } });
    if (res.data.error) {
      const e = new Error('RPC ' + method + ': ' + res.data.error.message);
      e.code = res.data.error.code;
      throw e;
    }
    return res.data.result;
  }
  return {
    _call,
    url,
    chainId: async () => BigInt(await _call('eth_chainId')),
    blockNumber: async () => BigInt(await _call('eth_blockNumber')),
    gasPrice: async () => BigInt(await _call('eth_gasPrice')),
    getBalance: async (addr) => BigInt(await _call('eth_getBalance', [addr, 'latest'])),
    getNonce: async (addr) => BigInt(await _call('eth_getTransactionCount', [addr, 'pending'])),
    call: async ({ to, data, from }) => await _call('eth_call', [{ to, data, from }, 'latest']),
    estimateGas: async ({ from, to, value, data }) => BigInt(await _call('eth_estimateGas', [{ from, to, value, data }])),
    sendRaw: async (raw) => await _call('eth_sendRawTransaction', [raw]),
    getReceipt: async (hash) => await _call('eth_getTransactionReceipt', [hash]),
    async waitReceipt(hash, { tries = 45, delayMs = 2000 } = {}) {
      for (let i = 0; i < tries; i++) {
        const r = await _call('eth_getTransactionReceipt', [hash]);
        if (r) return r;
        await new Promise((res) => setTimeout(res, delayMs));
      }
      throw new Error('timeout waiting for receipt ' + hash);
    },
  };
}

function createWallet(privKeyHex) {
  const pk = Buffer.from(String(privKeyHex).replace(/^0x/i, ''), 'hex');
  const address = hexify(privateToAddress(pk));
  function signTx({ nonce, gasPrice, gas, to, value, data, chainId }) {
    const toBuf = to ? hexBuf(to) : Buffer.alloc(0);
    const dataBuf = data ? hexBuf(data) : Buffer.alloc(0);
    const pre = [bigBuf(nonce), bigBuf(gasPrice), bigBuf(gas), toBuf, bigBuf(value), dataBuf, bigBuf(chainId), bigBuf(0n), bigBuf(0n)];
    const hash = keccak256(rlp.encode(pre));
    const sig = ecsign(hash, pk);
    const v = chainId * 2n + 35n + BigInt(sig.v) - 27n;
    const signed = [
      bigBuf(nonce), bigBuf(gasPrice), bigBuf(gas), toBuf, bigBuf(value), dataBuf,
      bigBuf(v), setLengthLeft(sig.r, 32), setLengthLeft(sig.s, 32),
    ];
    return '0x' + rlp.encode(signed).toString('hex');
  }
  return { address, privKey: privKeyHex, signTx };
}

async function walletSend(client, wallet, { to, value, data, chainId, gasPrice, gas }) {
  const valueB = value ?? 0n;
  const nonce = await client.getNonce(wallet.address);
  const gp = gasPrice || (await client.gasPrice());
  const g = gas || (await client.estimateGas({ from: wallet.address, to, value: valueB, data }));
  const raw = wallet.signTx({ nonce, gasPrice: gp, gas: g, to, value: valueB, data, chainId });
  const hash = await client.sendRaw(raw);
  const receipt = await client.waitReceipt(hash);
  return { hash, receipt, nonce, gasPrice: gp, gas: g };
}

async function readHTLC(client, contract) {
  const read = async (sig, args) => client.call({ to: contract, data: encodeCall(sig, ...(args || [])) });
  const [amount, hashlock, timelock, sender, receiver, redeemed, refunded] = await Promise.all([
    read('amount()'), read('hashlock()'), read('timelock()'), read('sender()'), read('receiver()'), read('redeemed()'), read('refunded()'),
  ]);
  const w = (hex, off) => BigInt('0x' + hex.replace(/^0x/i, '').slice((off || 0) * 64, (off || 0) * 64 + 64));
  return {
    amount: w(amount),
    hashlock: '0x' + hashlock.replace(/^0x/i, '').padStart(64, '0'),
    timelock: w(timelock),
    sender: '0x' + sender.replace(/^0x/i, '').slice(-40),
    receiver: '0x' + receiver.replace(/^0x/i, '').slice(-40),
    redeemed: w(redeemed),
    refunded: w(refunded),
  };
}

function compileHTLC() {
  return compileHTLCImpl();
}

function makeEVMPlugin({
  id, asset, decimals = 18, defaultRpc, defaultChainId,
  explorers = {}, loadKey, gasFund = 10000000000000000n, deployGasFallback = 400000n,
}) {
  const clientOf = (url) => createClient(url || defaultRpc);
  const plugin = {
    id,
    asset,
    decimals,
    defaultRpc,
    defaultChainId,
    explorers,
    createClient: clientOf,
    createWallet,
    loadKey,
    encodeCall,
    walletSend,
    weiToAsset: (wei) => weiToDec(wei, decimals),
    htlcInit(receiver, hashlockHex, timelock) {
      return htlcDeployData(receiver, hashlockHex, timelock, compileHTLC());
    },
    readHtlc: (client, contract) => readHTLC(client || clientOf(), contract),
    async estimateDeployGas(client, wallet, { receiver, hashlock, timelock, amount, data }) {
      const c = client || clientOf();
      const d = data || htlcDeployData(receiver, hashlock, timelock, compileHTLC());
      return c.estimateGas({ from: wallet.address, data: d, value: amount || 0n });
    },
    gasFund: () => gasFund,
    async deployHtlc(client, wallet, { receiver, hashlock, timelock, amount, chainId, data }) {
      const c = client || clientOf();
      const d = data || htlcDeployData(receiver, hashlock, timelock, compileHTLC());
      const { hash, receipt } = await walletSend(c, wallet, { data: d, value: amount || 0n, chainId });
      return { hash, receipt, htlc: receipt.contractAddress, data: d };
    },
    async redeemHtlc(client, wallet, { htlc, secretHex, chainId }) {
      return walletSend(client || clientOf(), wallet, { to: htlc, data: encodeCall('redeem(bytes32)', '0x' + secretHex), chainId });
    },
    async refundHtlc(client, wallet, { htlc, chainId }) {
      return walletSend(client || clientOf(), wallet, { to: htlc, data: encodeCall('refund()'), chainId });
    },
    async fundGas(client, fromWallet, to, { amount, chainId }) {
      return walletSend(client || clientOf(), fromWallet, { to, value: amount, chainId });
    },
    explorerFor(chainId) {
      const id_ = BigInt(chainId);
      return explorers[id_] || { name: 'chain ' + id_, explorer: '' };
    },
  };
  return plugin;
}

module.exports = {
  hexBuf, bigBuf, hexify, encodeCall, weiToDec, htlcDeployData,
  createClient, createWallet, walletSend, readHTLC, compileHTLC, makeEVMPlugin,
};