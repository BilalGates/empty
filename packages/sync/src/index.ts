import type { SyncConflict, SyncMutation, SyncRecord } from '@space/protocol';

export interface SyncState {
  revision: number;
  records: Map<string, SyncRecord>;
  appliedMutations: Map<string, MutationReceipt>;
}

export interface MutationReceipt {
  mutationId: string;
  status: 'applied' | 'conflict';
  serverRevision: number;
  record?: SyncRecord;
  conflict?: SyncConflict;
}

export interface PushResult { state: SyncState; receipts: MutationReceipt[] }

export function emptySyncState(): SyncState {
  return { revision: 0, records: new Map(), appliedMutations: new Map() };
}

export function applyMutations(input: SyncState, vaultId: string, mutations: readonly SyncMutation[]): PushResult {
  const state: SyncState = {
    revision: input.revision,
    records: new Map(input.records),
    appliedMutations: new Map(input.appliedMutations)
  };
  const receipts: MutationReceipt[] = [];
  for (const mutation of mutations) {
    const existingReceipt = state.appliedMutations.get(mutation.mutationId);
    if (existingReceipt) { receipts.push(existingReceipt); continue; }
    const current = state.records.get(mutation.itemId);
    const currentVersion = current?.itemVersion ?? 0;
    state.revision++;
    let receipt: MutationReceipt;
    if (mutation.baseItemVersion !== currentVersion && current) {
      receipt = {
        mutationId: mutation.mutationId,
        status: 'conflict',
        serverRevision: state.revision,
        conflict: { mutation, current }
      };
    } else {
      const record: SyncRecord = {
        vaultId,
        itemId: mutation.itemId,
        itemVersion: currentVersion + 1,
        serverRevision: state.revision,
        encryptedItem: mutation.encryptedItem,
        updatedAt: mutation.occurredAt
      };
      state.records.set(mutation.itemId, record);
      receipt = { mutationId: mutation.mutationId, status: 'applied', serverRevision: state.revision, record };
    }
    state.appliedMutations.set(mutation.mutationId, receipt);
    receipts.push(receipt);
  }
  return { state, receipts };
}

export function pullSince(state: SyncState, cursor: number, limit = 500): { records: SyncRecord[]; cursor: number; hasMore: boolean } {
  if (!Number.isSafeInteger(cursor) || cursor < 0 || cursor > state.revision) throw new Error('Invalid sync cursor');
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new Error('Invalid page limit');
  const records = [...state.records.values()]
    .filter(record => record.serverRevision > cursor)
    .sort((a, b) => a.serverRevision - b.serverRevision)
    .slice(0, limit);
  const nextCursor = records.at(-1)?.serverRevision ?? cursor;
  return { records, cursor: nextCursor, hasMore: [...state.records.values()].some(record => record.serverRevision > nextCursor) };
}

export interface LocalChange<T> { itemId: string; baseVersion: number; value: T | null }
export interface Reconciliation<T> { accepted: LocalChange<T>[]; conflicts: Array<{ local: LocalChange<T>; remote: SyncRecord }> }

export function reconcile<T>(changes: readonly LocalChange<T>[], remote: readonly SyncRecord[]): Reconciliation<T> {
  const latest = new Map(remote.map(record => [record.itemId, record]));
  const accepted: LocalChange<T>[] = [], conflicts: Array<{ local: LocalChange<T>; remote: SyncRecord }> = [];
  for (const local of changes) {
    const record = latest.get(local.itemId);
    if (record && record.itemVersion !== local.baseVersion) conflicts.push({ local, remote: record });
    else accepted.push(local);
  }
  return { accepted, conflicts };
}

