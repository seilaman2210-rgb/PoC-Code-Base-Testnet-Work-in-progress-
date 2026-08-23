const crypto = require('crypto');
const { ZERO_HASH, sha256hex, sha256buf, safeInt, safeBigInt, hashBlock, hashTransaction, merkleRoot, computeStateRootAfterTxs, calculateMiningReward, verifyMerkleProofBuf, computeDeadline, plotScoopCount, getTier, computeEffectiveCapacityGb, computeBaseTargetWithTier, TIERS, SCOOPS_PER_NONCE, MINING_SCOOP_MODULUS, verifySignature, canonicalTxMessage, proofMessage } = require('../crypto');
const { log } = require('../config');
const { runHook } = require('../optional');


const TIER_REWARD_PCT = { tier_1: 8, tier_2: 12, tier_3: 20, tier_4: 25, tier_5: 35 };

class ChallengeManager {
  constructor(db, chain, cfg, optionalModules = null) {
    this.db = db;
    this.cfg = cfg || {};
    this.chain = chain;
    this.optionalModules = optionalModules;
  }

  getOrCreate() {
    const now = Math.floor(Date.now() / 1000);
    const tip = this.chain.getBlock(this.chain.height);
    const genSig = (tip && tip.generation_signature) || ZERO_HASH;
    const tipHash = tip ? tip.hash : ZERO_HASH;
    const challengeId = sha256hex(`${genSig}:${tipHash}`);
    const targetIdx = parseInt(sha256hex(genSig).slice(0, 8), 16) % MINING_SCOOP_MODULUS;
    const challengeGrace = Math.max(15, Math.floor((this.cfg.expectedTimePerBlock || 240) / 2));
    // Grace period before a dead challenge can be replaced by a fresh one.
    const challengeExpiredGraceSec = Math.max(this.cfg.challengeExpiredGraceSec || 300, (this.cfg.expectedTimePerBlock || 240) * 2);
    const baseTarget = this.chain._baseTargetForHeight(this.chain.height);

    const existing = this.db.prepare('SELECT * FROM mining_challenges WHERE challenge_id = ? AND forged_block_height IS NULL AND expires_at > ?').get(challengeId, now);
    if (existing) return { ...existing, base_target: baseTarget };

    const expired = this.db.prepare('SELECT * FROM mining_challenges WHERE challenge_id = ? AND forged_block_height IS NULL AND expires_at <= ? AND challenge_id IN (SELECT DISTINCT challenge_id FROM challenge_submissions)').get(challengeId, now);
    // If the expired challenge is still within the grace window, keep waiting for a possible late forge.
    // If it has been expired too long, continue below to delete & recreate the challenge.
    if (expired && (now - expired.expires_at) <= challengeExpiredGraceSec) {
      return { ...expired, base_target: baseTarget };
    }

    const minTtl = Math.max(this.cfg.challengeTtlSec || 300, (this.cfg.expectedTimePerBlock || 240) * 5);
    const ttl = Math.min(Math.max(minTtl, 60), 86400);
    this.db.prepare('DELETE FROM mining_challenges WHERE forged_block_height IS NULL AND (challenge_id != ? OR expires_at + ? < ?) AND challenge_id NOT IN (SELECT DISTINCT challenge_id FROM challenge_submissions)').run(challengeId, challengeGrace, now);
    // This delete now also removes the dead expired challenge because expires_at < now - challengeGrace
    this.db.prepare('DELETE FROM mining_challenges WHERE challenge_id = ? AND (forged_block_height IS NOT NULL OR expires_at < ?)').run(challengeId, now - challengeGrace);
    const nonce = crypto.randomBytes(4).toString('hex');
    try {
      this.db.prepare('INSERT INTO mining_challenges (challenge_id, challenge_seed, nonce, target_scoop_index, created_at, expires_at, block_height) VALUES (?,?,?,?,?,?,?)').run(challengeId, genSig, nonce, targetIdx, now, now + ttl, this.chain.height);
      log('info', `New challenge ${challengeId.slice(0, 12)}  scoop=${targetIdx}  expires in ${ttl}s`);
    } catch {
      const r = this.db.prepare('SELECT * FROM mining_challenges WHERE challenge_id = ?').get(challengeId);
      return r || null;
    }
    return { ...this.db.prepare('SELECT * FROM mining_challenges WHERE challenge_id = ?').get(challengeId), base_target: baseTarget };
  }


  submitProof(chain, challengeId, miner, plotId, deadline, proofPacket = null) {
    const now = Math.floor(Date.now() / 1000);
    const submitGrace = Math.max(15, Math.floor((this.cfg.expectedTimePerBlock || 240) / 2));
    const ch = this.db.prepare('SELECT * FROM mining_challenges WHERE challenge_id = ? AND forged_block_height IS NULL AND expires_at + ? >= ?').get(challengeId, submitGrace, now);
    if (!ch) return { ok: false, motivo: 'challenge not found or expired' };
    if (ch.forged_block_height != null) return { ok: false, motivo: 'challenge already finalized' };
    const maxDl = chain.computeMaxDeadline();
    deadline = safeInt(deadline, -1);
    if (deadline < 0 || deadline > maxDl) return { ok: false, motivo: `invalid deadline (must be 0–${maxDl}s)` };
    let sizeGb = 0;
    const plot = this.db.prepare('SELECT * FROM plot_commitments WHERE plot_id = ? AND miner = ?').get(plotId, miner);
    if (plot) sizeGb = plot.size_gb;
    else {
      const peerPlot = this.db.prepare('SELECT * FROM peer_plot_commitments WHERE plot_id = ? AND miner = ?').get(plotId, miner);
      sizeGb = peerPlot ? peerPlot.size_gb : 1;
    }
    if (!proofPacket || !proofPacket.scoop_data) return { ok: false, motivo: 'proof_packet with scoop_data required for PoC verification' };
    const genSig = ch.challenge_seed || ZERO_HASH;
    const networkBaseTarget = chain._baseTargetForHeight(ch.block_height || chain.height);
    const computedDeadline = Math.min(computeDeadline(proofPacket.scoop_data, genSig, sizeGb, networkBaseTarget), maxDl);
    if (Math.abs(computedDeadline - deadline) > 1) return { ok: false, motivo: `PoC verification failed: computed ${computedDeadline}s, submitted ${deadline}s` };
    const expectedDigest = sha256hex(Buffer.concat([Buffer.from(proofPacket.scoop_data, 'hex'), Buffer.from(String(deadline))]));
    if (proofPacket.proof_digest && proofPacket.proof_digest !== expectedDigest) return { ok: false, motivo: 'proof digest mismatch' };
    if (!plot || !plot.merkle_root) return { ok: false, motivo: 'plot has no merkle_root commitment' };
    const totalScoops = safeInt(proofPacket.total_scoops, 0) || plotScoopCount(sizeGb);
    const scoopIndex = safeInt(proofPacket.scoop_index, -1);
    if (scoopIndex < 0 || scoopIndex >= totalScoops) return { ok: false, motivo: `invalid scoop_index ${scoopIndex} for ${totalScoops} scoops` };
    const merkleProof = proofPacket.merkle_proof || [];
    const leafHash = Buffer.from(proofPacket.scoop_data, 'hex');
    if (!verifyMerkleProofBuf(leafHash, scoopIndex, totalScoops, merkleProof, plot.merkle_root)) return { ok: false, motivo: 'Merkle proof does not match committed plot root' };

    const proofSig = (proofPacket && proofPacket.proof_signature) || '';
    if (proofSig) {
      const pkRow = this.db.prepare('SELECT public_key_ed25519 FROM users WHERE lower(address) = lower(?)').get(miner);
      if (pkRow && pkRow.public_key_ed25519) {
        const msg = proofMessage(challengeId, miner, deadline, plotId);
        if (!verifySignature(msg, proofSig, pkRow.public_key_ed25519)) {
          return { ok: false, motivo: 'proof signature does not match miner address' };
        }
      }
    }

    this.db.prepare('INSERT OR IGNORE INTO challenge_submissions (challenge_id, miner, plot_id, size_gb, deadline, proof_digest, proof_signature, submitted_at) VALUES (?,?,?,?,?,?,?,?)').run(challengeId, miner, plotId, sizeGb, deadline, expectedDigest, proofSig, now);
    const updated = this.db.prepare('UPDATE mining_challenges SET winner_miner = ?, winner_deadline = ?, winner_plot_id = ?, finalized_at = ? WHERE challenge_id = ? AND (winner_deadline IS NULL OR ? < winner_deadline)').run(miner, deadline, plotId, now, challengeId, deadline);
    const subCount = this.db.prepare('SELECT COUNT(*) as cnt FROM challenge_submissions WHERE challenge_id = ?').get(challengeId).cnt;
    const result = { ok: true, submitted: true, challenge_id: challengeId, total_submissions: subCount };
    log('info', `PoC proof from ${(miner || '').slice(0, 10)}… d=${deadline}s plot=${(plotId || '').slice(0, 10)}… for challenge ${challengeId.slice(0, 12)}`);
    if (updated.changes > 0) {
      log('info', `Best deadline updated! d=${deadline}s for challenge ${challengeId.slice(0, 12)}`);
      const waitSec = deadline;
      log('info', `Waiting ${waitSec}s for deadline to elapse on challenge ${challengeId.slice(0, 12)}`);
    }
    return result;
  }

  _selectValidMempoolTxs(chain, maxCount) {
    const candidates = chain.getMempoolForBlock(maxCount);
    log('info', `[TX] mempool candidates: ${candidates.length}`);
    const good = [];
    const projectedNonce = {};
    const projectedBalance = {};
    for (const tx of candidates) {
      const sender = tx.from_addr;
      let reason = null;
      if (!sender) reason = 'invalid tx sender';
      if (!reason) {
        if (!(sender in projectedNonce)) {
          const user = this.db.prepare('SELECT nonce, balance FROM users WHERE address = ?').get(sender);
          projectedNonce[sender] = user ? safeInt(user.nonce, 0) : 0;
          projectedBalance[sender] = user ? safeBigInt(user.balance, 0n) : 0n;
        }
        if (safeInt(tx.nonce, -1) < 0 || safeInt(tx.value, -1) < 0) reason = `invalid tx values for ${sender}`;
        else if (safeInt(tx.nonce, 0) !== projectedNonce[sender]) reason = `nonce mismatch (tx=${tx.nonce}, expected=${projectedNonce[sender]})`;
        else if (projectedBalance[sender] < safeBigInt(tx.value, 0n) + safeBigInt(tx.fee, 0n)) reason = `insufficient balance for ${sender}`;
        else {
          const sig = tx.signature || '';
          if (!sig) reason = `missing signature from ${sender}`;
          else {
            const pubkey = this.db.prepare('SELECT public_key_ed25519 FROM users WHERE address = ?').get(sender);
            if (!pubkey || !pubkey.public_key_ed25519) reason = `sender ${sender} has no public key`;
            else if (!verifySignature(canonicalTxMessage(tx), sig, pubkey.public_key_ed25519)) reason = `invalid tx signature from ${sender}`;
          }
        }
      }
      if (reason) {
        log('warn', `[TX] Dropping mempool tx ${(tx.hash || '').slice(0, 12)}: ${reason}`);
        this.db.prepare('DELETE FROM mempool WHERE hash = ?').run(tx.hash || hashTransaction(tx));
        continue;
      }
      log('info', `[TX] Accepting tx ${(tx.hash || '').slice(0, 12)} from ${sender.slice(0, 14)}... nonce=${tx.nonce}`);
      projectedBalance[sender] -= safeBigInt(tx.value, 0n) + safeBigInt(tx.fee, 0n);
      projectedNonce[sender]++;
      good.push(tx);
    }
    log('info', `[TX] selected ${good.length} txs for block`);
    return good;
  }

  _forgeBlock(chain, challenge, miner, deadline, rewardDistribution = [], plotId = '', proofDigest = '', winnerProof = null) {
    try {
      miner = typeof miner === 'string' ? miner.toLowerCase() : miner;
      const newHeight = chain.height + 1;
      let now = Math.floor(Date.now() / 1000);
      const parent = chain.getBlock(chain.height);
      if (parent && now <= parent.timestamp) now = parent.timestamp + 1;
      log('info', `[TX] _forgeBlock called for height ${newHeight}, chain.height=${chain.height}`);
      const mempoolTxs = this._selectValidMempoolTxs(chain, 100);
      log('info', `[TX] _forgeBlock: ${mempoolTxs.length} txs selected for block #${newHeight}`);
      const txHashes = mempoolTxs.map(t => t.hash || hashTransaction(t));
      const txRoot = merkleRoot(txHashes);
      const totalReward = calculateMiningReward(newHeight, this.cfg);
      const rewardCc = String(totalReward);
      const targetValue = chain._targetForHeight(newHeight);
      const genSig = parent ? sha256hex((parent.generation_signature || ZERO_HASH) + parent.hash) : ZERO_HASH;
      const block = {
        height: newHeight, parent_hash: parent ? parent.hash : ZERO_HASH, generation_signature: genSig,
        timestamp: now, miner, tx_count: mempoolTxs.length, tx_root: txRoot,
        challenge_id: challenge.challenge_id, nonce: String(Math.floor(deadline)),
        difficulty: '0', target: String(targetValue), reward_units: '0', reward_cc: String(rewardCc),
        proof_digest: proofDigest, plot_id: plotId, base_target: chain._baseTargetForHeight(newHeight),
        state_root: computeStateRootAfterTxs(this.db, mempoolTxs, rewardDistribution),
        transactions: mempoolTxs, signature: '', gas_used: mempoolTxs.length * 21000, gas_limit: 30000000,
        base_fee: String(chain._baseFeeForHeight(newHeight)),
        _from_local_forge: true, rewards: rewardDistribution,
        winner_proof: winnerProof || null,
      };
      if (this.cfg.minerPrivateKey) {
        const { signMessage, blockMessage } = require('../crypto');
        block.signature = signMessage(blockMessage(block), this.cfg.minerPrivateKey);
      }
      block.hash = hashBlock(block);
      return block;
    } catch (e) { log('error', `forge block error: ${e.message}`); return null; }
  }

  async finalizeExpiredChallenges(chain, syncEngine) {
    const now = Math.floor(Date.now() / 1000);
    const nextHeight = chain.height + 1;
    const existingBlock = this.db.prepare('SELECT hash, challenge_id FROM blocks WHERE height = ? ORDER BY LENGTH(chain_work) DESC, chain_work DESC LIMIT 1').get(nextHeight);

    const stale = this.db.prepare(`SELECT challenge_id, block_height FROM mining_challenges
      WHERE forged_block_height IS NULL AND winner_deadline IS NOT NULL AND winner_miner IS NOT NULL
      AND (finalized_at + winner_deadline) <= ? AND block_height < ?`).all(now, chain.height);
    for (const s of stale) {
      log('warn', `Abandoning stale challenge ${s.challenge_id.slice(0, 12)} (created at height ${s.block_height}, chain now at ${chain.height})`);
      this.db.prepare('UPDATE mining_challenges SET forged_block_height = ? WHERE challenge_id = ? AND forged_block_height IS NULL').run(-1, s.challenge_id);
    }

    const localMiner = String(this.cfg.minerAddress || '').toLowerCase();
    const readyToForge = this.db.prepare(`SELECT * FROM mining_challenges WHERE forged_block_height IS NULL
      AND winner_deadline IS NOT NULL AND winner_miner IS NOT NULL
      AND lower(winner_miner) = lower(?)
      AND (finalized_at + winner_deadline) <= ? AND block_height >= ?
      ORDER BY created_at ASC LIMIT 1`).get(localMiner, now, chain.height);
    if (readyToForge) {
      const ch = readyToForge;
      if (existingBlock) {
        this.db.prepare('UPDATE mining_challenges SET forged_block_height = ? WHERE challenge_id = ? AND forged_block_height IS NULL').run(nextHeight, ch.challenge_id);
      } else if (chain.height >= nextHeight) {
        this.db.prepare('UPDATE mining_challenges SET forged_block_height = ? WHERE challenge_id = ? AND forged_block_height IS NULL').run(chain.height, ch.challenge_id);
      } else {
        log('info', `Deadline elapsed — forging block for challenge ${ch.challenge_id.slice(0, 12)} (d=${ch.winner_deadline}s)`);
        await this._forgeBlockForChallenge(chain, syncEngine, ch);
        return;
      }
    }

    const expired = this.db.prepare(`SELECT * FROM mining_challenges WHERE forged_block_height IS NULL
      AND winner_deadline IS NOT NULL AND winner_miner IS NOT NULL
      AND lower(winner_miner) = lower(?)
      AND (finalized_at + winner_deadline) <= ? AND block_height >= ?
      AND challenge_id NOT IN (SELECT DISTINCT challenge_id FROM blocks WHERE blocks.challenge_id = mining_challenges.challenge_id AND blocks.challenge_id != '')
      AND challenge_id IN (SELECT DISTINCT challenge_id FROM challenge_submissions)
      ORDER BY created_at ASC LIMIT 1`).get(localMiner, now, chain.height);
    if (expired) {
      const ch = expired;
      const chId = ch.challenge_id;
      if (existingBlock) {
        this.db.prepare('UPDATE mining_challenges SET forged_block_height = ? WHERE challenge_id = ? AND forged_block_height IS NULL').run(nextHeight, chId);
      } else if (chain.height >= nextHeight) {
        this.db.prepare('UPDATE mining_challenges SET forged_block_height = ? WHERE challenge_id = ? AND forged_block_height IS NULL').run(chain.height, chId);
      } else {
        await this._forgeBlockForChallenge(chain, syncEngine, ch);
      }
    }
  }

  async _forgeBlockForChallenge(chain, syncEngine, challenge) {
    try {
      const nextHeight = chain.height + 1;
      const existing = this.db.prepare('SELECT hash, challenge_id FROM blocks WHERE height = ? LIMIT 1').get(nextHeight);
      if (existing) return null;
      const submissions = this.db.prepare('SELECT * FROM challenge_submissions WHERE challenge_id = ?').all(challenge.challenge_id);
      if (!submissions.length) return null;
      const maxDl = chain.computeMaxDeadline();
      const seenSub = new Set();
      const validSubs = submissions
        .filter(s => safeInt(s.deadline, maxDl + 1) <= maxDl)
        .filter(s => {
          const k = `${(s.miner || '').toLowerCase()}:${s.plot_id || ''}:${safeInt(s.deadline, -1)}`;
          if (seenSub.has(k)) return false;
          seenSub.add(k);
          return true;
        })
        .sort((a, b) => {
          const da = safeInt(a.deadline, Number.MAX_SAFE_INTEGER);
          const dbd = safeInt(b.deadline, Number.MAX_SAFE_INTEGER);
          if (da !== dbd) return da - dbd;
          const ma = String(a.miner || '').toLowerCase();
          const mb = String(b.miner || '').toLowerCase();
          if (ma !== mb) return ma < mb ? -1 : 1;
          const pa = String(a.plot_id || '');
          const pb = String(b.plot_id || '');
          if (pa !== pb) return pa < pb ? -1 : 1;
          const sa = String(a.proof_digest || '');
          const sb = String(b.proof_digest || '');
          return sa < sb ? -1 : sa > sb ? 1 : 0;
        });
      if (!validSubs.length) return null;
      const winner = validSubs[0];
      const localMiner = String(this.cfg.minerAddress || '').toLowerCase();
      if (!this.cfg.minerPrivateKey || !localMiner || (winner.miner || '').toLowerCase() !== localMiner) {
        return null;
      }
      const totalReward = calculateMiningReward(chain.height + 1, this.cfg);
      const winnerSharePct = this.cfg.winnerSharePct || 70;
      const poolSharePct = 100 - winnerSharePct;
      const scores = [];
      let totalScore = 0;
      for (const s of validSubs) {
        const eff = computeEffectiveCapacityGb(s.size_gb);
        const score = eff / Math.max(1, s.deadline);
        scores.push({ sub: s, score });
        totalScore += score;
      }
      const distribution = [];
      let allocated = 0n;
      for (const { sub, score } of scores) {
        const poolPct = totalScore > 0 ? (score / totalScore) * poolSharePct : 0;
        const isWinner = String(sub.miner || '').toLowerCase() === String(winner.miner || '').toLowerCase() && safeInt(sub.deadline, -1) === safeInt(winner.deadline, -1) && String(sub.plot_id || '') === String(winner.plot_id || '');
        const finalPct = isWinner ? (poolPct + winnerSharePct) : poolPct;
        const permille = BigInt(Math.round(finalPct * 1000));
        const reward = (totalReward * permille) / 100000n;
        if (reward > 0n) {
          distribution.push({
            miner: (sub.miner || '').toLowerCase(), plot_id: sub.plot_id || '', size_gb: sub.size_gb,
            deadline: sub.deadline, share_pct: finalPct, reward_cc: String(reward),
            type: 'poc',
          });
          allocated += reward;
        }
      }
      if (allocated < totalReward && distribution.length > 0) {
        distribution[0].reward_cc = String(BigInt(distribution[0].reward_cc) + (totalReward - allocated));
      }
      const winnerProof = {
        miner: (winner.miner || '').toLowerCase(),
        deadline: winner.deadline,
        plot_id: winner.plot_id || '',
        proof_signature: winner.proof_signature || '',
      };
      const block = this._forgeBlock(chain, challenge, winner.miner, winner.deadline, distribution, winner.plot_id || '', winner.proof_digest || '', winnerProof);
      if (!block) return null;
      const result = await chain.addBlock(block, { skipStateValidation: true, skipPocValidation: true });
      if (!result.ok) {
        log('error', `Block forge rejected for challenge ${challenge.challenge_id.slice(0, 12)}: ${result.motivo}`);
        return null;
      }
      this.db.prepare('UPDATE mining_challenges SET forged_block_height = ? WHERE challenge_id = ? AND forged_block_height IS NULL').run(block.height, challenge.challenge_id);
      log('info', `Block #${block.height} forged — challenge ${challenge.challenge_id.slice(0, 12)} (${distribution.length} miners, reward ${totalReward} CC)`);
      runHook(this.optionalModules, 'notifyNewBlock', block, this.cfg);
      if (syncEngine) setImmediate(() => { syncEngine.broadcastBlock(block); });
      return block;
    } catch (e) { log('error', `forge error: ${e.message}`); return null; }
  }
}

module.exports = { ChallengeManager, TIERS, getTier, computeBaseTargetWithTier };
