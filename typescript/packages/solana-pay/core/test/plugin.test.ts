import {
    type Address,
    type Instruction,
    address,
    type TransactionSigner,
    decompileTransactionMessage,
    getBase64Encoder,
    getTransactionDecoder,
    getCompiledTransactionMessageDecoder,
} from '@solana/kit';
import { describe, expect, it, vi } from 'vitest';

import { solanaPayMerchant } from '../src/plugins/merchant.js';
import { solanaPayWallet } from '../src/plugins/wallet.js';

function createMockSigner(addr: Address): TransactionSigner {
    return {
        address: addr,
        signTransactions: vi.fn(),
    } as unknown as TransactionSigner;
}

function createMockClient(payer?: TransactionSigner) {
    return {
        rpc: {} as any,
        ...(payer ? { payer } : {}),
    };
}

describe('solanaPayMerchant plugin', () => {
    describe('installation', () => {
        it('should add pay namespace with merchant methods', () => {
            const client = createMockClient();
            const extended = solanaPayMerchant()(client);

            expect(extended.pay).toBeDefined();
            expect(typeof extended.pay.encodeURL).toBe('function');
            expect(typeof extended.pay.createQR).toBe('function');
            expect(typeof extended.pay.createQROptions).toBe('function');
            expect(typeof extended.pay.findReference).toBe('function');
            expect(typeof extended.pay.validateTransfer).toBe('function');
            expect(typeof extended.pay.buildTransaction).toBe('function');
        });

        it('should not include wallet methods', () => {
            const client = createMockClient();
            const extended = solanaPayMerchant()(client) as any;

            expect(extended.pay.parseURL).toBeUndefined();
            expect(extended.pay.createTransfer).toBeUndefined();
            expect(extended.pay.fetchTransaction).toBeUndefined();
        });

        it('should preserve existing client properties', () => {
            const client = { rpc: {} as any, customProp: 'hello' };
            const extended = solanaPayMerchant()(client);

            expect(extended.customProp).toBe('hello');
            expect(extended.rpc).toBe(client.rpc);
        });

        it('should return a frozen object', () => {
            const client = createMockClient();
            const extended = solanaPayMerchant()(client);

            expect(Object.isFrozen(extended)).toBe(true);
        });
    });

    describe('encodeURL', () => {
        it('should encode a transfer request URL', () => {
            const extended = solanaPayMerchant()(createMockClient());
            const recipient = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');

            const url = extended.pay.encodeURL({ recipient, amount: 1 });

            expect(url).toBeInstanceOf(URL);
            expect(url.protocol).toBe('solana:');
            expect(url.pathname).toBe(recipient);
        });

        it('should encode a transaction request URL', () => {
            const extended = solanaPayMerchant()(createMockClient());

            const url = extended.pay.encodeURL({ link: new URL('https://example.com/pay') });

            expect(url).toBeInstanceOf(URL);
            expect(url.protocol).toBe('solana:');
        });
    });

    describe('buildTransaction', () => {
        const feePayer = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
        const programAddress = address('11111111111111111111111111111111');

        function createMockInstruction(data?: Uint8Array): Instruction {
            return {
                programAddress,
                accounts: [{ address: feePayer, role: 3 /* WRITABLE_SIGNER */ }],
                data: data ?? new Uint8Array([2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]),
            };
        }

        it('should return a base64 string', () => {
            const extended = solanaPayMerchant()(createMockClient());
            const result = extended.pay.buildTransaction(feePayer, [createMockInstruction()]);

            expect(typeof result).toBe('string');
            expect(result.length).toBeGreaterThan(0);
        });

        it('should work with empty instructions', () => {
            const extended = solanaPayMerchant()(createMockClient());
            const result = extended.pay.buildTransaction(feePayer, []);

            expect(typeof result).toBe('string');
            expect(result.length).toBeGreaterThan(0);
        });

        it('should round-trip: decode back to a valid transaction', () => {
            const extended = solanaPayMerchant()(createMockClient());
            const ix = createMockInstruction();
            const base64 = extended.pay.buildTransaction(feePayer, [ix]);

            // Decode the base64 wire transaction
            const bytes = getBase64Encoder().encode(base64);
            const transaction = getTransactionDecoder().decode(bytes);
            const message = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);

            // Fee payer should be the first static account
            expect(message.staticAccounts[0]).toBe(feePayer);
            // Transaction should be version 0
            expect(message.version).toBe(0);
        });

        it('should include the correct number of instructions', () => {
            const extended = solanaPayMerchant()(createMockClient());
            const ix1 = createMockInstruction(new Uint8Array([1]));
            const ix2 = createMockInstruction(new Uint8Array([2]));
            const base64 = extended.pay.buildTransaction(feePayer, [ix1, ix2]);

            const bytes = getBase64Encoder().encode(base64);
            const transaction = getTransactionDecoder().decode(bytes);
            const message = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);

            expect(message.instructions).toHaveLength(2);
        });

        it('should set signatures to empty (unsigned)', () => {
            const extended = solanaPayMerchant()(createMockClient());
            const base64 = extended.pay.buildTransaction(feePayer, [createMockInstruction()]);

            const bytes = getBase64Encoder().encode(base64);
            const transaction = getTransactionDecoder().decode(bytes);

            // All signatures should be null or zero-filled (unsigned)
            for (const sig of Object.values(transaction.signatures)) {
                if (sig === null) continue;
                expect(sig.every((b: number) => b === 0)).toBe(true);
            }
        });

        it('should build a version 1 transaction carrying the provided config', () => {
            const extended = solanaPayMerchant()(createMockClient());
            const config = { computeUnitLimit: 200_000, priorityFeeLamports: 10_000n };
            const base64 = extended.pay.buildTransaction(feePayer, [createMockInstruction()], {
                version: 1,
                config,
            });

            const bytes = getBase64Encoder().encode(base64);
            const transaction = getTransactionDecoder().decode(bytes);
            const compiledMessage = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);

            expect(compiledMessage.version).toBe(1);
            expect(compiledMessage.staticAccounts[0]).toBe(feePayer);
            const message = decompileTransactionMessage(compiledMessage as any);
            if (message.version !== 1) throw new Error('expected a v1 message');
            expect(message.config).toEqual(config);
        });

        it('should throw when a config is provided for a non-v1 transaction', () => {
            const extended = solanaPayMerchant()(createMockClient());

            expect(() =>
                extended.pay.buildTransaction(feePayer, [createMockInstruction()], {
                    version: 0,
                    config: { computeUnitLimit: 200_000 },
                }),
            ).toThrow('only valid for version 1');
        });
    });
});

describe('solanaPayWallet plugin', () => {
    describe('installation', () => {
        it('should add pay namespace with wallet methods', () => {
            const client = createMockClient();
            const extended = solanaPayWallet()(client);

            expect(extended.pay).toBeDefined();
            expect(typeof extended.pay.parseURL).toBe('function');
            expect(typeof extended.pay.createTransfer).toBe('function');
            expect(typeof extended.pay.fetchTransaction).toBe('function');
        });

        it('should not include merchant methods', () => {
            const client = createMockClient();
            const extended = solanaPayWallet()(client) as any;

            expect(extended.pay.encodeURL).toBeUndefined();
            expect(extended.pay.createQR).toBeUndefined();
            expect(extended.pay.findReference).toBeUndefined();
            expect(extended.pay.validateTransfer).toBeUndefined();
        });

        it('should return a frozen object', () => {
            const client = createMockClient();
            const extended = solanaPayWallet()(client);

            expect(Object.isFrozen(extended)).toBe(true);
        });
    });

    describe('parseURL', () => {
        it('should parse a transfer request URL', () => {
            const extended = solanaPayWallet()(createMockClient());
            const recipient = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');

            const parsed = extended.pay.parseURL(`solana:${recipient}?amount=1`);

            expect(parsed.recipient).toBe(recipient);
        });
    });

    describe('createTransfer', () => {
        it('should throw when no sender or payer is available', async () => {
            const extended = solanaPayWallet()(createMockClient());

            await expect(
                extended.pay.createTransfer({
                    recipient: address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'),
                    amount: 1,
                }),
            ).rejects.toThrow('requires a sender or client.payer');
        });

        it('should use client.payer when no explicit sender is provided', async () => {
            const payerSigner = createMockSigner(address('FnHyam9w4NZoWR6mKN1CuGBritdsEWZQa4Z4oawLZGxa'));
            const recipientAddr = address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
            const makeInfo = (addr: any) => ({
                owner: address('11111111111111111111111111111111'),
                executable: false,
                lamports: addr === payerSigner.address ? 1_000_000_000n : 0n,
                data: new Uint8Array(0),
                rentEpoch: 0n,
            });
            const mockRpc = {
                getAccountInfo: vi.fn().mockImplementation((addr: any) => ({
                    send: vi.fn().mockResolvedValue({ value: makeInfo(addr) }),
                })),
                getMultipleAccounts: vi.fn().mockImplementation((addrs: any[]) => ({
                    send: vi.fn().mockResolvedValue({ value: addrs.map(makeInfo) }),
                })),
            };

            const client = { rpc: mockRpc as any, payer: payerSigner };
            const extended = solanaPayWallet()(client);

            const instructions = await extended.pay.createTransfer({
                recipient: recipientAddr,
                amount: 1,
            });

            expect(Array.isArray(instructions)).toBe(true);
            expect(instructions.length).toBeGreaterThan(0);
        });

        it('should use explicit sender over client.payer', async () => {
            const payerSigner = createMockSigner(address('FnHyam9w4NZoWR6mKN1CuGBritdsEWZQa4Z4oawLZGxa'));
            const sender = createMockSigner(address('82ZJ7nbGpixjeDCmEhUcmwXYfvurzAgGdtSMuHnUgyny'));

            const accountInfo = {
                owner: address('11111111111111111111111111111111'),
                executable: false,
                lamports: 1_000_000_000n,
                data: new Uint8Array(0),
                rentEpoch: 0n,
            };
            const mockRpc = {
                getAccountInfo: vi.fn().mockImplementation(() => ({
                    send: vi.fn().mockResolvedValue({ value: accountInfo }),
                })),
                getMultipleAccounts: vi.fn().mockImplementation((addrs: any[]) => ({
                    send: vi.fn().mockResolvedValue({ value: addrs.map(() => accountInfo) }),
                })),
            };

            const client = { rpc: mockRpc as any, payer: payerSigner };
            const extended = solanaPayWallet()(client);

            const instructions = await extended.pay.createTransfer(
                {
                    recipient: address('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'),
                    amount: 1,
                },
                sender,
            );

            expect(Array.isArray(instructions)).toBe(true);
            const transferIx = instructions[0] as any;
            const senderAccount = transferIx.accounts?.find((a: any) => a.address === sender.address);
            expect(senderAccount).toBeDefined();
        });
    });
});
