import type { GetSignaturesForAddressApi, Rpc } from '@solana/kit';
import type { Commitment, Signature } from '@solana/kit';

import type { Reference } from './types.js';

/**
 * A machine-readable reason for a {@link FindReferenceError}.
 *
 * `'not found'` means the RPC returned no signatures for the reference, which is
 * inconclusive: the customer may never have paid, the transaction may not be
 * indexed by this node yet, or it may have aged out of a non-archival node's
 * history. `'aborted'` means the subscription was cancelled before any
 * transaction was seen.
 */
export type FindReferenceErrorCode = 'aborted' | 'not found';

/**
 * Thrown when no transaction signature can be found referencing a given address.
 */
export class FindReferenceError extends Error {
    name = 'FindReferenceError';

    /** Machine-readable reason, so callers can branch without string-matching {@link Error.message}. */
    readonly code: FindReferenceErrorCode;

    constructor(message: FindReferenceErrorCode) {
        super(message);
        this.code = message;
    }
}

/** Options for {@link findReference}. */
export interface FindReferenceOptions {
    /** Limit the number of signatures returned. */
    limit?: number;
    /** Start searching backwards from this signature. */
    before?: Signature;
    /** Search until this signature is reached. */
    until?: Signature;
    /** Commitment level to use for the query. */
    commitment?: Exclude<Commitment, 'processed'>;
}

/** A confirmed signature info entry returned by the RPC. */
export interface ConfirmedSignatureInfo {
    signature: Signature;
    slot: bigint | number;
    err: unknown | null;
    memo: string | null;
    blockTime: bigint | number | null;
    confirmationStatus: Commitment | null;
}

/**
 * Find the oldest transaction signature referencing a given address.
 *
 * @param rpc - An RPC client supporting `getSignaturesForAddress`.
 * @param reference - `reference` in the [Solana Pay spec](https://github.com/solana-foundation/pay/blob/main/typescript/packages/solana-pay/spec/SPEC.md#reference).
 * @param options - Options for `getSignaturesForAddress`.
 *
 * @throws {FindReferenceError}
 */
export async function findReference(
    rpc: Rpc<GetSignaturesForAddressApi>,
    reference: Reference,
    { commitment, ...options }: FindReferenceOptions = {},
): Promise<ConfirmedSignatureInfo> {
    const signatures = await rpc
        .getSignaturesForAddress(reference, { ...options, ...(commitment ? { commitment } : {}) })
        .send();

    const length = signatures.length;
    if (!length) throw new FindReferenceError('not found');

    // If one or more transaction signatures are found under the limit, return the oldest one.
    const oldest = signatures[length - 1];
    if (length < (options?.limit || 1000)) return oldest;

    try {
        // In the unlikely event that signatures up to the limit are found, recursively find the oldest one.
        return await findReference(rpc, reference, {
            commitment,
            ...options,
            before: oldest.signature,
        });
    } catch (error) {
        // If the signatures found were exactly at the limit, there won't be more to find, so return the oldest one.
        if (error instanceof FindReferenceError) return oldest;
        throw error;
    }
}
