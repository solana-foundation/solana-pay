import type { Signature } from '@solana/kit';
import type { LogsNotificationsApi } from '@solana/rpc-subscriptions-api';
import type { RpcSubscriptions } from '@solana/rpc-subscriptions-spec';

import { FindReferenceError } from './findReference.js';
import type { Finality, Reference } from './types.js';

/** Options for {@link watchReference}. */
export interface WatchReferenceOptions {
    /** Commitment level for the subscription. Defaults to `confirmed`. */
    commitment?: Finality;
    /** Abort signal to cancel the subscription. */
    abortSignal?: AbortSignal;
}

/** Result returned by {@link watchReference}. */
export interface WatchReferenceResult {
    /** The transaction signature. */
    signature: Signature;
    /** Error if the transaction failed, null if it succeeded. */
    err: unknown | null;
}

/**
 * Watch for a transaction referencing a given address using WebSocket subscriptions.
 *
 * Unlike {@link findReference}, which polls via HTTP, this function subscribes
 * to `logsNotifications` filtered by `{ mentions: [reference] }` and resolves
 * as soon as a matching transaction lands.
 *
 * @param rpcSubscriptions - An RPC subscriptions client supporting `logsNotifications`.
 * @param reference - `reference` in the [Solana Pay spec](https://github.com/solana-foundation/pay/blob/main/typescript/packages/solana-pay/spec/SPEC.md#reference).
 * @param options - Options for the subscription.
 *
 * @throws {FindReferenceError} If the subscription is aborted before a transaction is found.
 */
export async function watchReference(
    rpcSubscriptions: RpcSubscriptions<LogsNotificationsApi>,
    reference: Reference,
    options?: WatchReferenceOptions,
): Promise<WatchReferenceResult> {
    const { commitment = 'confirmed', abortSignal: externalSignal } = options ?? {};

    if (externalSignal?.aborted) {
        throw new FindReferenceError('aborted');
    }

    const abortController = new AbortController();
    if (externalSignal) {
        externalSignal.addEventListener('abort', () => abortController.abort(externalSignal.reason), { once: true });
    }

    try {
        const subscription = await rpcSubscriptions
            .logsNotifications({ mentions: [reference] }, { commitment })
            .subscribe({ abortSignal: abortController.signal });

        for await (const notification of subscription) {
            return {
                signature: notification.value.signature,
                err: notification.value.err,
            };
        }
    } catch (error) {
        if (abortController.signal.aborted) {
            throw new FindReferenceError('aborted');
        }
        throw error;
    } finally {
        abortController.abort();
    }

    throw new FindReferenceError('not found');
}
