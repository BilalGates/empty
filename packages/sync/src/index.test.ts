import { describe, expect, it } from 'vitest';
import type { SyncMutation } from '@space/protocol';
import { applyMutations, emptySyncState, pullSince, reconcile } from './index.js';

const mutation = (id: string, deviceId: string, itemId: string, baseItemVersion: number, encryptedItem: string | null): SyncMutation => ({
  mutationId: id, deviceId, itemId, baseItemVersion, encryptedItem, occurredAt: `2026-01-01T00:00:0${id.length}.000Z`
});

describe('sync engine', () => {
  it('is idempotent', () => {
    const first = applyMutations(emptySyncState(), 'vault-1', [mutation('m1', 'a', 'item', 0, 'cipher-a')]);
    const replay = applyMutations(first.state, 'vault-1', [mutation('m1', 'a', 'item', 0, 'cipher-a')]);
    expect(replay.state.revision).toBe(1); expect(replay.receipts[0]).toEqual(first.receipts[0]);
  });

  it('reports offline concurrent changes instead of overwriting', () => {
    const first = applyMutations(emptySyncState(), 'vault-1', [mutation('m1', 'a', 'item', 0, 'cipher-a')]);
    const second = applyMutations(first.state, 'vault-1', [mutation('m2', 'b', 'item', 0, 'cipher-b')]);
    expect(second.receipts[0]?.status).toBe('conflict');
    expect(second.state.records.get('item')?.encryptedItem).toBe('cipher-a');
  });

  it('syncs create, update, and tombstone incrementally', () => {
    let state = applyMutations(emptySyncState(), 'vault-1', [mutation('m1', 'a', 'item', 0, 'v1')]).state;
    state = applyMutations(state, 'vault-1', [mutation('m2', 'a', 'item', 1, 'v2')]).state;
    state = applyMutations(state, 'vault-1', [mutation('m3', 'a', 'item', 2, null)]).state;
    expect(pullSince(state, 0).records).toEqual([expect.objectContaining({ itemVersion: 3, encryptedItem: null })]);
  });

  it('keeps a local conflict for explicit resolution', () => {
    const remote = [{ vaultId: 'v', itemId: 'x', itemVersion: 2, serverRevision: 2, encryptedItem: 'remote', updatedAt: '2026-01-01T00:00:00Z' }];
    expect(reconcile([{ itemId: 'x', baseVersion: 1, value: 'local' }], remote).conflicts).toHaveLength(1);
  });
});

