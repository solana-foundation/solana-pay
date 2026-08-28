import type { Address, Signature, TransactionVersion, V1TransactionConfig } from '@solana/kit';
import {
    address,
    appendTransactionMessageInstructions,
    blockhash,
    compileTransaction,
    createNoopSigner,
    createTransactionMessage,
    decompileTransactionMessage,
    getBase64EncodedWireTransaction,
    getCompiledTransactionMessageDecoder,
    pipe,
    setTransactionMessageConfig,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
} from '@solana/kit';
import { getTransferSolInstruction } from '@solana-program/system';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { fetchTransaction, validateTransfer } from '../src/index.js';

const SIGNATURE = '5UfDuX7hXbDBZpHnSEFMwBN6JdANTF54fGVz9Kp1fZBNTmRmEiGP' as Signature;
const SENDER = address('FnHyam9w4NZoWR6mKN1CuGBritdsEWZQa4Z4oawLZGxa');
const RECIPIENT = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
const BLOCKHASH = blockhash('4NpjLLnFBqFzwFkRFBauGFYVnijcQhLBSPo9UhbZgqRf');
const LINK = 'https://example.com/pay';

const originalFetch = globalThis.fetch;

/** Build a base64 wire-format SOL transfer transaction of the given version. */
function buildSolTransferTx(version: TransactionVersion, config?: V1TransactionConfig): string {
    const instructions = [
        getTransferSolInstruction({
            source: createNoopSigner(SENDER),
            destination: RECIPIENT,
            amount: 1_000_000_000n,
        }),
    ];
    const lifetime = { blockhash: BLOCKHASH, lastValidBlockHeight: 100n };
    if (version === 1) {
        const msg = pipe(
            createTransactionMessage({ version: 1 }),
            m => setTransactionMessageFeePayerSigner(createNoopSigner(SENDER), m),
            m => setTransactionMessageLifetimeUsingBlockhash(lifetime, m),
            m => appendTransactionMessageInstructions(instructions, m),
            m => (config ? setTransactionMessageConfig(config, m) : m),
        );
        return getBase64EncodedWireTransaction(compileTransaction(msg));
    }
    const msg = pipe(
        createTransactionMessage({ version }),
        m => setTransactionMessageFeePayerSigner(createNoopSigner(SENDER), m),
        m => setTransactionMessageLifetimeUsingBlockhash(lifetime, m),
        m => appendTransactionMessageInstructions(instructions, m),
    );
    return getBase64EncodedWireTransaction(compileTransaction(msg));
}

function createGetTransactionMockRpc(base64Tx: string) {
    const getTransaction = vi.fn().mockReturnValue({
        send: vi.fn().mockResolvedValue({
            meta: {
                err: null,
                // Account order: [sender(0), recipient(1), systemProgram(2)]
                preBalances: [10_000_000_000n, 0n, 1n],
                postBalances: [9_000_000_000n, 1_000_000_000n, 1n],
            },
            transaction: [base64Tx, 'base64'],
        }),
    });
    return { rpc: { getTransaction } as any, getTransaction };
}

function createBlockhashMockRpc() {
    return {
        getLatestBlockhash: () => ({
            send: vi.fn().mockResolvedValue({
                value: { blockhash: BLOCKHASH, lastValidBlockHeight: 100n },
            }),
        }),
    } as any;
}

function mockMerchantResponse(base64Tx: string) {
    globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({ transaction: base64Tx }),
    });
}

describe('validateTransfer across transaction versions', () => {
    const fields = { recipient: RECIPIENT, amount: 1 };

    it.each([['legacy'], [0], [1]] as [TransactionVersion][])(
        'should validate a version %s SOL transfer',
        async version => {
            const { rpc } = createGetTransactionMockRpc(buildSolTransferTx(version));
            await expect(validateTransfer(rpc, SIGNATURE, fields)).resolves.toBeDefined();
        },
    );

    it('should validate a v1 transfer carrying a transaction config', async () => {
        const tx = buildSolTransferTx(1, { computeUnitLimit: 200_000, priorityFeeLamports: 10_000n });
        const { rpc } = createGetTransactionMockRpc(tx);
        await expect(validateTransfer(rpc, SIGNATURE, fields)).resolves.toBeDefined();
    });

    it('should request transactions up to version 1 from the RPC', async () => {
        const { rpc, getTransaction } = createGetTransactionMockRpc(buildSolTransferTx(1));
        await validateTransfer(rpc, SIGNATURE, fields);
        expect(getTransaction).toHaveBeenCalledWith(
            SIGNATURE,
            expect.objectContaining({ maxSupportedTransactionVersion: 1 }),
        );
    });
});

describe('fetchTransaction across transaction versions', () => {
    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    it.each([['legacy'], [0], [1]] as [TransactionVersion][])(
        'should return an unsigned version %s transaction with the account as fee payer',
        async version => {
            mockMerchantResponse(buildSolTransferTx(version));
            const account = address('82ZJ7nbGpixjeDCmEhUcmwXYfvurzAgGdtSMuHnUgyny');

            const transaction = await fetchTransaction(createBlockhashMockRpc(), account, LINK);

            const compiledMessage = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
            expect(compiledMessage.version).toBe(version === 'legacy' ? 'legacy' : version);
            expect(compiledMessage.staticAccounts[0]).toBe(account);
        },
    );

    it('should preserve the v1 transaction config through the fee payer swap', async () => {
        const config = { computeUnitLimit: 300_000, priorityFeeLamports: 5_000n };
        mockMerchantResponse(buildSolTransferTx(1, config));
        const account = address('82ZJ7nbGpixjeDCmEhUcmwXYfvurzAgGdtSMuHnUgyny');

        const transaction = await fetchTransaction(createBlockhashMockRpc(), account, LINK);

        const compiledMessage = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
        if (compiledMessage.version !== 1) throw new Error('expected a v1 transaction');
        const message = decompileTransactionMessage(compiledMessage);
        if (message.version !== 1) throw new Error('expected a v1 message');
        expect(message.config).toEqual(config);
    });
});
