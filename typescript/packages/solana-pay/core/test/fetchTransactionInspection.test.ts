import type { Instruction, TransactionVersion, V1TransactionConfig } from '@solana/kit';
import {
    AccountRole,
    address,
    appendTransactionMessageInstructions,
    blockhash,
    compileTransaction,
    createNoopSigner,
    createTransactionMessage,
    getBase64EncodedWireTransaction,
    pipe,
    setTransactionMessageComputeUnitLimit,
    setTransactionMessageComputeUnitPrice,
    setTransactionMessageConfig,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
} from '@solana/kit';
import { getAssignInstruction, getTransferSolInstruction } from '@solana-program/system';
import { AuthorityType, getSetAuthorityInstruction, getTransferCheckedInstruction } from '@solana-program/token';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { fetchTransaction, FetchTransactionError } from '../src/index.js';

const SENDER = address('FnHyam9w4NZoWR6mKN1CuGBritdsEWZQa4Z4oawLZGxa');
const RECIPIENT = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
const BLOCKHASH = blockhash('4NpjLLnFBqFzwFkRFBauGFYVnijcQhLBSPo9UhbZgqRf');
const LINK = 'https://example.com/pay';

const originalFetch = globalThis.fetch;

function transferInstruction(): Instruction {
    return getTransferSolInstruction({
        source: createNoopSigner(SENDER),
        destination: RECIPIENT,
        amount: 1_000_000_000n,
    });
}

/** Build a base64 unsigned wire transaction for the given version, instructions, and fee settings. */
function buildTx({
    computeUnitLimit,
    computeUnitPriceMicroLamports,
    config,
    instructions = [transferInstruction()],
    version = 0,
}: {
    computeUnitLimit?: number;
    computeUnitPriceMicroLamports?: bigint;
    config?: V1TransactionConfig;
    instructions?: Instruction[];
    version?: TransactionVersion;
} = {}): string {
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
        m =>
            computeUnitPriceMicroLamports != null
                ? setTransactionMessageComputeUnitPrice(computeUnitPriceMicroLamports, m)
                : m,
        m => (computeUnitLimit != null ? setTransactionMessageComputeUnitLimit(computeUnitLimit, m) : m),
    );
    return getBase64EncodedWireTransaction(compileTransaction(msg));
}

function mockMerchantResponse(base64Tx: string) {
    globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: vi.fn().mockResolvedValue({ transaction: base64Tx }),
    });
}

function createMockRpc() {
    return {
        getLatestBlockhash: () => ({
            send: vi.fn().mockResolvedValue({
                value: { blockhash: BLOCKHASH, lastValidBlockHeight: 100n },
            }),
        }),
    } as any;
}

describe('fetchTransaction inspection', () => {
    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    describe('priority fee ceilings', () => {
        it('should reject a v0 transaction whose priority fee exceeds the default ceiling', async () => {
            // 10,000,000 micro-lamports/CU × 200,000 CU = 2,000,000 lamports > 1,000,000 default
            mockMerchantResponse(buildTx({ computeUnitPriceMicroLamports: 10_000_000n, computeUnitLimit: 200_000 }));

            await expect(fetchTransaction(createMockRpc(), SENDER, LINK)).rejects.toThrow(
                /priority fee of 2000000 lamports exceeds maximum of 1000000 lamports/,
            );
        });

        it('should reject a v1 transaction whose priority fee exceeds the default ceiling', async () => {
            mockMerchantResponse(
                buildTx({ version: 1, config: { computeUnitLimit: 200_000, priorityFeeLamports: 2_000_000n } }),
            );

            await expect(fetchTransaction(createMockRpc(), SENDER, LINK)).rejects.toThrow(
                /priority fee of 2000000 lamports exceeds maximum of 1000000 lamports/,
            );
        });

        it('should apply the default compute unit limit when a v0 transaction sets a price but no limit', async () => {
            // 10,000,000 micro-lamports/CU × 200,000 defaulted CU (1 budgeted instruction) = 2,000,000 lamports
            mockMerchantResponse(buildTx({ computeUnitPriceMicroLamports: 10_000_000n }));

            await expect(fetchTransaction(createMockRpc(), SENDER, LINK)).rejects.toThrow(
                /priority fee of 2000000 lamports/,
            );
        });

        it('should accept a transaction whose priority fee is within a raised ceiling', async () => {
            mockMerchantResponse(buildTx({ computeUnitPriceMicroLamports: 10_000_000n, computeUnitLimit: 200_000 }));

            const transaction = await fetchTransaction(createMockRpc(), SENDER, LINK, {
                maxPriorityFeeLamports: 2_000_000n,
            });
            expect(transaction.inspection.maxPriorityFeeLamports).toBe(2_000_000n);
        });

        it('should reject a transaction whose compute unit limit exceeds a configured ceiling', async () => {
            mockMerchantResponse(buildTx({ computeUnitLimit: 1_000_000 }));

            await expect(
                fetchTransaction(createMockRpc(), SENDER, LINK, { maxComputeUnitLimit: 400_000 }),
            ).rejects.toThrow(/compute unit limit of 1000000 exceeds maximum of 400000/);
        });

        it('should accept a fee-less transfer under the default ceilings', async () => {
            mockMerchantResponse(buildTx());

            const transaction = await fetchTransaction(createMockRpc(), SENDER, LINK);
            expect(transaction.inspection.maxPriorityFeeLamports).toBe(0n);
        });
    });

    describe('unexpected account signatures', () => {
        it('should reject when the account signs an instruction of an unexpected program', async () => {
            const maliciousInstruction: Instruction = {
                programAddress: address('82ZJ7nbGpixjeDCmEhUcmwXYfvurzAgGdtSMuHnUgyny'),
                accounts: [{ address: SENDER, role: AccountRole.WRITABLE_SIGNER }],
                data: new Uint8Array([1, 2, 3]),
            };
            mockMerchantResponse(buildTx({ instructions: [transferInstruction(), maliciousInstruction] }));

            await expect(fetchTransaction(createMockRpc(), SENDER, LINK)).rejects.toThrow(
                /account is a signer on an unexpected instruction/,
            );
        });

        it('should reject when an unexpected program references the account even without a signer role', async () => {
            // Signer privileges are transaction-global, so a readonly reference still gains the
            // account's signature at runtime once the account signs the transaction.
            const readonlyInstruction: Instruction = {
                programAddress: address('82ZJ7nbGpixjeDCmEhUcmwXYfvurzAgGdtSMuHnUgyny'),
                accounts: [{ address: SENDER, role: AccountRole.READONLY }],
                data: new Uint8Array([1, 2, 3]),
            };
            mockMerchantResponse(buildTx({ instructions: [transferInstruction(), readonlyInstruction] }));

            await expect(fetchTransaction(createMockRpc(), SENDER, LINK)).rejects.toThrow(
                /account is a signer on an unexpected instruction/,
            );
        });

        it('should reject a System Assign instruction that changes the account owner', async () => {
            const assignInstruction = getAssignInstruction({
                account: createNoopSigner(SENDER),
                programAddress: address('82ZJ7nbGpixjeDCmEhUcmwXYfvurzAgGdtSMuHnUgyny'),
            });
            mockMerchantResponse(buildTx({ instructions: [transferInstruction(), assignInstruction] }));

            await expect(fetchTransaction(createMockRpc(), SENDER, LINK)).rejects.toThrow(
                /account is a signer on an unexpected instruction/,
            );
        });

        it('should reject a token SetAuthority instruction referencing the account', async () => {
            const setAuthorityInstruction = getSetAuthorityInstruction({
                owned: RECIPIENT,
                owner: createNoopSigner(SENDER),
                authorityType: AuthorityType.AccountOwner,
                newAuthority: address('82ZJ7nbGpixjeDCmEhUcmwXYfvurzAgGdtSMuHnUgyny'),
            });
            mockMerchantResponse(buildTx({ instructions: [setAuthorityInstruction] }));

            await expect(fetchTransaction(createMockRpc(), SENDER, LINK)).rejects.toThrow(
                /account is a signer on an unexpected instruction/,
            );
        });

        it('should accept a token TransferChecked instruction with the account as authority', async () => {
            const transferChecked = getTransferCheckedInstruction({
                source: address('7dHbWXmci3dT1h5tC8S1ZLw6KcDk4chx6Y6bx4dM3f1h'),
                mint: address('So11111111111111111111111111111111111111112'),
                destination: address('GfC73miMwXBoRYDn7gvEZVbhM7n6SUHxJb4LdBz2Mfp6'),
                authority: createNoopSigner(SENDER),
                amount: 1_000_000n,
                decimals: 6,
            });
            mockMerchantResponse(buildTx({ instructions: [transferChecked] }));

            await expect(fetchTransaction(createMockRpc(), SENDER, LINK)).resolves.toBeDefined();
        });

        it('should accept instructions of unexpected programs that do not reference the account', async () => {
            const unrelatedInstruction: Instruction = {
                programAddress: address('82ZJ7nbGpixjeDCmEhUcmwXYfvurzAgGdtSMuHnUgyny'),
                accounts: [{ address: RECIPIENT, role: AccountRole.READONLY }],
                data: new Uint8Array([1, 2, 3]),
            };
            mockMerchantResponse(buildTx({ instructions: [transferInstruction(), unrelatedInstruction] }));

            await expect(fetchTransaction(createMockRpc(), SENDER, LINK)).resolves.toBeDefined();
        });
    });

    describe('inspection results', () => {
        it('should surface instructions, version, and fee details for a v0 transaction', async () => {
            // 1,000 micro-lamports/CU × 300,000 CU = 300 lamports
            mockMerchantResponse(buildTx({ computeUnitPriceMicroLamports: 1_000n, computeUnitLimit: 300_000 }));

            const { inspection } = await fetchTransaction(createMockRpc(), SENDER, LINK);

            expect(inspection.version).toBe(0);
            expect(inspection.computeUnitLimit).toBe(300_000);
            expect(inspection.maxPriorityFeeLamports).toBe(300n);
            // Transfer + SetComputeUnitPrice + SetComputeUnitLimit
            expect(inspection.instructions).toHaveLength(3);
        });

        it('should surface config-based fee details for a v1 transaction', async () => {
            mockMerchantResponse(
                buildTx({ version: 1, config: { computeUnitLimit: 250_000, priorityFeeLamports: 5_000n } }),
            );

            const { inspection } = await fetchTransaction(createMockRpc(), SENDER, LINK);

            expect(inspection.version).toBe(1);
            expect(inspection.computeUnitLimit).toBe(250_000);
            expect(inspection.maxPriorityFeeLamports).toBe(5_000n);
            expect(inspection.instructions).toHaveLength(1);
        });
    });

    describe('unsupported transaction versions', () => {
        it('should reject wire bytes with an unknown version discriminator', async () => {
            const validTx = buildTx();
            const bytes = Uint8Array.from(atob(validTx), c => c.charCodeAt(0));
            // Unsigned v0 wire layout: [sig count (1)][64-byte zeroed signature][message]. The
            // message's first byte is the version discriminator: 0x80 | version. 0x82 (v2) is
            // beyond what the package supports.
            expect(bytes[65]).toBe(0x80);
            bytes[65] = 0x82;
            mockMerchantResponse(btoa(String.fromCharCode(...bytes)));

            await expect(fetchTransaction(createMockRpc(), SENDER, LINK)).rejects.toThrow(FetchTransactionError);
        });
    });
});
