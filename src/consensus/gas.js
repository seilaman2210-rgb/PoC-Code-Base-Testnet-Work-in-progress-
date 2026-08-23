const GAS_PARAMS = {
  simpleTransferGas: 21000,
  gasPerByteZero: 4,
  gasPerByteNonZero: 16,
  initialBaseFee: 10 ** 9,
  blockGasLimit: 10500000,
};

function estimateIntrinsicGas(tx) {
  let gas = GAS_PARAMS.simpleTransferGas;
  let dataHex = '';
  if (tx.data) {
    dataHex = tx.data.startsWith('0x') ? tx.data.slice(2) : tx.data;
  }
  const data = dataHex ? Buffer.from(dataHex, 'hex') : Buffer.alloc(0);
  for (const byte of data) {
    gas += byte === 0 ? GAS_PARAMS.gasPerByteZero : GAS_PARAMS.gasPerByteNonZero;
  }
  return gas;
}

function nextBaseFee(parentBaseFee, parentGasUsed, targetGas, minGasPrice, mempoolPendingCount = 0) {
  if (parentGasUsed === targetGas) return parentBaseFee;
  const delta = parentGasUsed > targetGas
    ? (parentBaseFee * BigInt(parentGasUsed - targetGas)) / BigInt(targetGas) / 8n
    : -(parentBaseFee * BigInt(targetGas - parentGasUsed)) / BigInt(targetGas) / 8n;
  let next = parentBaseFee + delta;

  if (mempoolPendingCount < targetGas / GAS_PARAMS.simpleTransferGas / 4) {
    next = (next * 95n) / 100n;
  }

  if (next < BigInt(minGasPrice)) next = BigInt(minGasPrice);
  return next;
}

module.exports = {
  GAS_PARAMS,
  estimateIntrinsicGas,
  nextBaseFee,
};