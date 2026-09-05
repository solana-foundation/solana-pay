import { address } from '@solana/kit';
import { describe, expect, it } from 'vitest';

import { FindReferenceError, findReference } from '../src/index.js';

const reference = address('9aE476sH92Vz7DMPyq5WLPkrKWivxeuTKEFKd2sZZcde');

// Mock RPC that returns signatures for the known reference address
const rpc = {
    getSignaturesForAddress(addr: string, _config?: unknown) {
        return {
            async send() {
                if (addr === reference) {
                    return [{ signature: 'signature' }];
                }
                return [];
            },
        };
    },
} as any;

describe('findReference', () => {
    it('should return the last signature', async () => {
        expect.assertions(1);

        const found = await findReference(rpc, reference);

        expect(found).toEqual({ signature: 'signature' });
    });

    it('throws an error on signature not found', async () => {
        expect.assertions(1);

        const unknownRef = address('2jDmYQMRCBnXUQeFRvQABcU6hLcvjVTdG7AoHravxWJX');

        await expect(findReference(rpc, unknownRef)).rejects.toThrow('not found');
    });

    it('should set code to "not found" when the RPC returns no signatures', async () => {
        expect.assertions(2);

        const unknownRef = address('2jDmYQMRCBnXUQeFRvQABcU6hLcvjVTdG7AoHravxWJX');

        const error = await findReference(rpc, unknownRef).catch((thrown: unknown) => thrown);

        expect(error).toBeInstanceOf(FindReferenceError);
        // An empty result is inconclusive, but it is reported as 'not found', never as 'aborted'.
        expect((error as FindReferenceError).code).toBe('not found');
    });
});
