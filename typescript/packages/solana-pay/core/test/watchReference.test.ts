import { address } from '@solana/kit';
import { describe, expect, it } from 'vitest';

import { FindReferenceError, watchReference } from '../src/index.js';

const reference = address('9aE476sH92Vz7DMPyq5WLPkrKWivxeuTKEFKd2sZZcde');

function createMockRpcSubscriptions(notifications: Array<{ signature: string; err: unknown | null }>) {
    return {
        logsNotifications(filter: unknown, _config?: unknown) {
            return {
                async subscribe(_options: { abortSignal: AbortSignal }) {
                    return {
                        async *[Symbol.asyncIterator]() {
                            for (const n of notifications) {
                                yield { value: { signature: n.signature, err: n.err, logs: [] } };
                            }
                        },
                    };
                },
            };
        },
    } as any;
}

describe('watchReference', () => {
    it('should resolve with the first matching notification', async () => {
        const rpcSubscriptions = createMockRpcSubscriptions([{ signature: 'sig123', err: null }]);

        const result = await watchReference(rpcSubscriptions, reference);

        expect(result).toEqual({ signature: 'sig123', err: null });
    });

    it('should return only the first notification when multiple exist', async () => {
        const rpcSubscriptions = createMockRpcSubscriptions([
            { signature: 'first', err: null },
            { signature: 'second', err: null },
        ]);

        const result = await watchReference(rpcSubscriptions, reference);

        expect(result).toEqual({ signature: 'first', err: null });
    });

    it('should include the error when a transaction fails', async () => {
        const txError = { InstructionError: [0, 'Custom'] };
        const rpcSubscriptions = createMockRpcSubscriptions([{ signature: 'failSig', err: txError }]);

        const result = await watchReference(rpcSubscriptions, reference);

        expect(result).toEqual({ signature: 'failSig', err: txError });
    });

    it('should pass commitment through to the subscription', async () => {
        let capturedConfig: unknown;
        const rpcSubscriptions = {
            logsNotifications(_filter: unknown, config?: unknown) {
                capturedConfig = config;
                return {
                    async subscribe() {
                        return {
                            async *[Symbol.asyncIterator]() {
                                yield { value: { signature: 'sig', err: null, logs: [] } };
                            },
                        };
                    },
                };
            },
        } as any;

        await watchReference(rpcSubscriptions, reference, { commitment: 'finalized' });

        expect(capturedConfig).toEqual({ commitment: 'finalized' });
    });

    it('should default commitment to confirmed', async () => {
        let capturedConfig: unknown;
        const rpcSubscriptions = {
            logsNotifications(_filter: unknown, config?: unknown) {
                capturedConfig = config;
                return {
                    async subscribe() {
                        return {
                            async *[Symbol.asyncIterator]() {
                                yield { value: { signature: 'sig', err: null, logs: [] } };
                            },
                        };
                    },
                };
            },
        } as any;

        await watchReference(rpcSubscriptions, reference);

        expect(capturedConfig).toEqual({ commitment: 'confirmed' });
    });

    it('should pass the reference as mentions filter', async () => {
        let capturedFilter: unknown;
        const rpcSubscriptions = {
            logsNotifications(filter: unknown, _config?: unknown) {
                capturedFilter = filter;
                return {
                    async subscribe() {
                        return {
                            async *[Symbol.asyncIterator]() {
                                yield { value: { signature: 'sig', err: null, logs: [] } };
                            },
                        };
                    },
                };
            },
        } as any;

        await watchReference(rpcSubscriptions, reference);

        expect(capturedFilter).toEqual({ mentions: [reference] });
    });

    it('should throw FindReferenceError when aborted', async () => {
        const abortController = new AbortController();
        const rpcSubscriptions = {
            logsNotifications() {
                return {
                    async subscribe({ abortSignal }: { abortSignal: AbortSignal }) {
                        return new Promise((_resolve, reject) => {
                            abortSignal.addEventListener('abort', () => reject(abortSignal.reason));
                        });
                    },
                };
            },
        } as any;

        const promise = watchReference(rpcSubscriptions, reference, { abortSignal: abortController.signal });
        abortController.abort();

        await expect(promise).rejects.toThrow(FindReferenceError);
    });

    it('should throw immediately when given a pre-aborted signal', async () => {
        const abortController = new AbortController();
        abortController.abort();

        await expect(watchReference({} as any, reference, { abortSignal: abortController.signal })).rejects.toThrow(
            FindReferenceError,
        );
    });

    it('should set code to "aborted" when the subscription is aborted', async () => {
        expect.assertions(2);

        const abortController = new AbortController();
        const rpcSubscriptions = {
            logsNotifications() {
                return {
                    async subscribe({ abortSignal }: { abortSignal: AbortSignal }) {
                        return new Promise((_resolve, reject) => {
                            abortSignal.addEventListener('abort', () => reject(abortSignal.reason));
                        });
                    },
                };
            },
        } as any;

        const promise = watchReference(rpcSubscriptions, reference, { abortSignal: abortController.signal });
        abortController.abort();

        const error = await promise.catch((thrown: unknown) => thrown);

        expect(error).toBeInstanceOf(FindReferenceError);
        // An abort is a caller action, not an inconclusive read; it must not read as 'not found'.
        expect((error as FindReferenceError).code).toBe('aborted');
    });

    it('should set code to "not found" when the subscription ends without a notification', async () => {
        expect.assertions(2);

        const rpcSubscriptions = createMockRpcSubscriptions([]);

        const error = await watchReference(rpcSubscriptions, reference).catch((thrown: unknown) => thrown);

        expect(error).toBeInstanceOf(FindReferenceError);
        // A subscription that ends normally saw no transaction; it is the same inconclusive read as
        // an empty getSignaturesForAddress response, not a caller abort.
        expect((error as FindReferenceError).code).toBe('not found');
    });
});
