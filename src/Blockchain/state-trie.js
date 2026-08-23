const crypto = require('crypto');

const ZERO_HASH = '0'.repeat(64);
const EMPTY_ROOT = ZERO_HASH;

function sha256hex(data) {
  return crypto.createHash('sha256').update(typeof data === 'string' ? data : data).digest('hex');
}

function hashPair(left, right) {
  return sha256hex(left + right);
}

class SparseMerkleTrie {
  constructor() {
    this.leaves = new Map();
    this.cache = new Map();
    this.root = EMPTY_ROOT;
    this._dirty = false;
  }

  _getPath(key) {
    if (typeof key !== 'string' || key.length !== 64) {
      key = key.toString(16).padStart(64, '0');
    }
    return key;
  }

  _computeRoot() {
    if (this.leaves.size === 0) return EMPTY_ROOT;
    
    const paths = Array.from(this.leaves.keys()).sort();
    const values = paths.map(p => this.leaves.get(p));
    
    let level = values;
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        const left = level[i];
        const right = i + 1 < level.length ? level[i + 1] : left;
        next.push(hashPair(left, right));
      }
      level = next;
    }
    return level[0] || EMPTY_ROOT;
  }

  _setLeaf(path, value) {
    if (value === EMPTY_ROOT || value === '' || value === '0'.repeat(64)) {
      this.leaves.delete(path);
    } else {
      this.leaves.set(path, value);
    }
  }

  get(key) {
    return this.leaves.get(this._getPath(key)) || EMPTY_ROOT;
  }

  set(key, value) {
    const path = this._getPath(key);
    this._setLeaf(path, value);
    this._dirty = true;
  }

  delete(key) {
    this.set(key, EMPTY_ROOT);
  }

  getRoot() {
    if (this._dirty) {
      this.root = this._computeRoot();
      this._dirty = false;
    }
    return this.root;
  }

  batchUpdate(updates) {
    for (const [key, value] of updates) {
      const path = this._getPath(key);
      this._setLeaf(path, value);
    }
    this._dirty = true;
    return this.getRoot();
  }

  getProof(key) {
    const path = this._getPath(key);
    const paths = Array.from(this.leaves.keys()).sort();
    const idx = paths.indexOf(path);
    if (idx === -1) { const empty = []; empty.leafIndex = -1; return empty; }
    
    const proof = [];
    let levelPaths = paths;
    let levelIdx = idx;
    
    while (levelPaths.length > 1) {
      const siblingIdx = levelIdx % 2 === 0 ? levelIdx + 1 : levelIdx - 1;
      const siblingPath = siblingIdx < levelPaths.length ? levelPaths[siblingIdx] : levelPaths[levelIdx];
      proof.push(this.leaves.get(siblingPath) || EMPTY_ROOT);
      
      const nextPaths = [];
      for (let i = 0; i < levelPaths.length; i += 2) {
        nextPaths.push(levelPaths[i].slice(0, -1));
      }
      levelPaths = nextPaths;
      levelIdx = Math.floor(levelIdx / 2);
    }
    
    proof.leafIndex = idx;
    return proof;
  }

  static verifyProof(root, key, value, proof, leafIndex) {
    let proofArray = proof;
    let idx = leafIndex;
    
    if (Array.isArray(proof)) {
      idx = proof.leafIndex;
    } else if (proof && typeof proof === 'object' && proof.proof) {
      proofArray = proof.proof;
      idx = proof.leafIndex;
    } else if (typeof leafIndex !== 'number') {
      const path = (typeof key !== 'string' || key.length !== 64) 
        ? key.toString(16).padStart(64, '0') 
        : key;
      console.warn('SparseMerkleTrie.verifyProof: legacy bit-based verification used; may not match getProof()');
      let current = value;
      for (let i = 0; i < proofArray.length; i++) {
        const sibling = proofArray[i];
        const bit = path[path.length - 1 - i];
        if (bit === '0') {
          current = hashPair(current, sibling);
        } else {
          current = hashPair(sibling, current);
        }
      }
      return current === root;
    }
    
    let current = value;
    for (let i = 0; i < proofArray.length; i++) {
      const sibling = proofArray[i];
      if (idx % 2 === 0) {
        current = hashPair(current, sibling);
      } else {
        current = hashPair(sibling, current);
      }
      idx = Math.floor(idx / 2);
    }
    return current === root;
  }

  clone() {
    const newTrie = new SparseMerkleTrie();
    newTrie.leaves = new Map(this.leaves);
    newTrie.root = this.root;
    newTrie._dirty = false; // root is up-to-date at clone time
    return newTrie;
  }
}

class IncrementalStateRoot {
  constructor() {
    this.userTrie = new SparseMerkleTrie();
    this.contractStorageTrie = new SparseMerkleTrie();
    this.contractAccountTrie = new SparseMerkleTrie();
    this.contractCodeTrie = new SparseMerkleTrie();
  }

  _normalizeAddr(address) {
    return address.toLowerCase().replace(/^0x/, '').padStart(40, '0');
  }

  updateUser(address, balance, nonce) {
    const key = this._normalizeAddr(address);
    const leaf = sha256hex(`${key}:${balance}:${nonce}`);
    this.userTrie.set(key, leaf);
  }

  deleteUser(address) {
    const key = this._normalizeAddr(address);
    this.userTrie.delete(key);
  }

  batchUpdateUsers(updates) {
    for (const u of updates) {
      const key = this._normalizeAddr(u.address);
      const leaf = sha256hex(`${key}:${u.balance}:${u.nonce}`);
      this.userTrie.set(key, leaf);
    }
    // force root recomputation once after all updates
    this.userTrie.getRoot();
  }

  updateContractStorage(contractAddress, slot, value) {
    const addr = this._normalizeAddr(contractAddress);
    const slotKey = BigInt(slot).toString(16).padStart(64, '0');
    const key = `${addr}:${slotKey}`;
    const leaf = sha256hex(`storage:${key}:${value}`);
    this.contractStorageTrie.set(key, leaf);
  }

  deleteContractStorage(contractAddress, slot) {
    const addr = this._normalizeAddr(contractAddress);
    const slotKey = BigInt(slot).toString(16).padStart(64, '0');
    const key = `${addr}:${slotKey}`;
    this.contractStorageTrie.delete(key);
  }

  updateContractAccount(address, balance) {
    const addr = this._normalizeAddr(address);
    const leaf = sha256hex(`account:${addr}:${balance}`);
    this.contractAccountTrie.set(addr, leaf);
  }

  deleteContractAccount(address) {
    const addr = this._normalizeAddr(address);
    this.contractAccountTrie.delete(addr);
  }

  batchUpdateContracts(updates) {
    for (const c of updates) {
      const addr = this._normalizeAddr(c.address);
      const leaf = sha256hex(`account:${addr}:${c.balance}`);
      this.contractAccountTrie.set(addr, leaf);
    }
    this.contractAccountTrie.getRoot();
  }

  updateContractCode(address, codeHash) {
    const addr = this._normalizeAddr(address);
    const leaf = sha256hex(`code:${addr}:${codeHash}`);
    this.contractCodeTrie.set(addr, leaf);
  }

  deleteContractCode(address) {
    const addr = this._normalizeAddr(address);
    this.contractCodeTrie.delete(addr);
  }

  getStateRoot() {
    const userRoot = this.userTrie.getRoot();
    const storageRoot = this.contractStorageTrie.getRoot();
    const accountRoot = this.contractAccountTrie.getRoot();
    const codeRoot = this.contractCodeTrie.getRoot();
    
    const leaves = [userRoot, storageRoot, accountRoot, codeRoot].filter(r => r !== EMPTY_ROOT);
    if (leaves.length === 0) return ZERO_HASH;
    
    let nodes = [...leaves];
    while (nodes.length > 1) {
      const next = [];
      for (let i = 0; i < nodes.length; i += 2) {
        const left = nodes[i];
        const right = i + 1 < nodes.length ? nodes[i + 1] : left;
        next.push(sha256hex(left + right));
      }
      nodes = next;
    }
    return nodes[0];
  }

  getComponentRoots() {
    return {
      userRoot: this.userTrie.getRoot(),
      storageRoot: this.contractStorageTrie.getRoot(),
      accountRoot: this.contractAccountTrie.getRoot(),
      codeRoot: this.contractCodeTrie.getRoot(),
    };
  }

  snapshot() {
    return {
      userTrie: this.userTrie.clone(),
      contractStorageTrie: this.contractStorageTrie.clone(),
      contractAccountTrie: this.contractAccountTrie.clone(),
      contractCodeTrie: this.contractCodeTrie.clone(),
    };
  }

  restore(snapshot) {
    this.userTrie = snapshot.userTrie;
    this.contractStorageTrie = snapshot.contractStorageTrie;
    this.contractAccountTrie = snapshot.contractAccountTrie;
    this.contractCodeTrie = snapshot.contractCodeTrie;
  }

  async loadFromDB(db) {
    const users = db.prepare('SELECT address, balance, nonce FROM users ORDER BY address').all();
    for (const u of users) {
      this.updateUser(u.address, u.balance, u.nonce);
    }

    const storage = db.prepare('SELECT contract_address, slot, value FROM smart_contract_storage ORDER BY lower(contract_address), slot').all();
    for (const s of storage) {
      this.updateContractStorage(s.contract_address, s.slot, s.value);
    }

    const accounts = db.prepare('SELECT address, balance FROM smart_contract_accounts ORDER BY lower(address)').all();
    for (const a of accounts) {
      this.updateContractAccount(a.address, a.balance);
    }

    const contracts = db.prepare('SELECT address, code FROM smart_contracts ORDER BY lower(address)').all();
    for (const c of contracts) {
      const codeHash = crypto.createHash('sha256').update(String(c.code || '')).digest('hex');
      this.updateContractCode(c.address, codeHash);
    }

    return this.getStateRoot();
  }
}

module.exports = { SparseMerkleTrie, IncrementalStateRoot, ZERO_HASH, sha256hex };