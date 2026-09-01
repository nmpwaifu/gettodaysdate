import fs from 'node:fs';
import path from 'node:path';

// Provides a strictly-increasing WebAuthn signature counter per credential.
// WebAuthn's counter is a uint32; relying parties only require new > stored.
// We use Unix epoch seconds as the counter source (fits uint32 until 2106),
// and persist the last value so same-second calls still strictly increase.
const MAX_UINT32 = 0xffffffff;

export function counterStatePath(keyDir) {
  return path.join(keyDir, 'signcount-state.json');
}

function readState(statePath) {
  try {
    return JSON.parse(fs.readFileSync(statePath, 'utf8'));
  } catch {
    return {};
  }
}

// Returns the next counter for `credentialId` and persists it.
// Value = max(epochSeconds, lastStored + 1), guaranteeing strict increase.
export function nextSignCount(keyDir, credentialId) {
  const statePath = counterStatePath(keyDir);
  const state = readState(statePath);
  const last = Number.isInteger(state[credentialId]) ? state[credentialId] : 0;
  const epochSeconds = Math.floor(Date.now() / 1000);
  const next = Math.max(epochSeconds, last + 1);
  if (next > MAX_UINT32) {
    throw new Error(`Signature counter for ${credentialId} exceeded uint32 range (year 2106).`);
  }
  state[credentialId] = next;
  fs.writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`);
  return next;
}
