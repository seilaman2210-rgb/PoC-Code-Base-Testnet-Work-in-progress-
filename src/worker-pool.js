const { Worker } = require('worker_threads');
const path = require('path');

// Đường dẫn tuyệt đối đến crypto.js (cùng thư mục)
const cryptoPath = path.join(__dirname, 'crypto.js');

// Mã nguồn worker (CommonJS) sẽ chạy trong thread riêng
const workerCode = `
  const { parentPort } = require('worker_threads');
  const { hashBlock, verifySignature, canonicalTxMessage } = require(${JSON.stringify(cryptoPath)});

  parentPort.on('message', (msg) => {
    let result;
    try {
      switch (msg.type) {
        case 'hashBlock': result = hashBlock(msg.block); break;
        case 'verifySignature': result = verifySignature(msg.message, msg.signature, msg.pubkey); break;
        case 'canonicalTxMessage': result = canonicalTxMessage(msg.tx); break;
        default: result = undefined;
      }
      parentPort.postMessage({ id: msg.id, result });
    } catch (error) {
      parentPort.postMessage({ id: msg.id, error: error.message });
    }
  });
`;

let worker = null;
let nextId = 0;
const pending = new Map();

function getWorker() {
  if (!worker) {
    worker = new Worker(workerCode, { eval: true });
    worker.on('message', (data) => {
      const p = pending.get(data.id);
      if (p) {
        pending.delete(data.id);
        if (data.error) p.reject(new Error(data.error));
        else p.resolve(data.result);
      }
    });
    worker.on('error', (err) => {
      for (const p of pending.values()) p.reject(err);
      pending.clear();
      worker = null;
    });
    worker.on('exit', () => {
      for (const p of pending.values()) p.reject(new Error('Worker exited'));
      pending.clear();
      worker = null;
    });
  }
  return worker;
}

function schedule(type, payload) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    getWorker().postMessage({ id, type, ...payload });
  });
}

async function hashBlockAsync(block) {
  return schedule('hashBlock', { block });
}

async function verifySignatureAsync(message, signature, pubkey) {
  return schedule('verifySignature', { message, signature, pubkey });
}

async function canonicalTxMessageAsync(tx) {
  return schedule('canonicalTxMessage', { tx });
}

async function hashBlocksAsync(blocks) {
  return Promise.all(blocks.map(b => hashBlockAsync(b)));
}

async function verifySignaturesAsync(items) {
  return Promise.all(items.map(i => verifySignatureAsync(i.message, i.signature, i.pubkey)));
}

function terminateWorkerPool() {
  if (worker) {
    worker.terminate();
    worker = null;
  }
}

module.exports = {
  hashBlockAsync,
  verifySignatureAsync,
  canonicalTxMessageAsync,
  hashBlocksAsync,
  verifySignaturesAsync,
  terminateWorkerPool,
};