import { Keypair, PublicKey, SystemProgram, Transaction } from '@solana/web3.js';
import BigNumber from 'bignumber.js';
import { createTransfer, CreateTransferError } from '../src';
import type { Connection } from '@solana/web3.js';

// Mocks for SPL Token
jest.mock('@solana/spl-token', () => ({
    getMint: jest.fn(),
    getAccount: jest.fn(),
    getAssociatedTokenAddress: jest.fn(),
    createTransferCheckedInstruction: jest.fn(() => ({ keys: [] })),
}));

const { getMint, getAccount, getAssociatedTokenAddress } = require('@solana/spl-token');

describe('CreateTransferError', () => {
    it('should set the correct name', () => {
        const err = new CreateTransferError('fail');
        expect(err.name).toBe('CreateTransferError');
        expect(err.message).toBe('fail');
    });
});

describe('createTransfer', () => {
    let connection: jest.Mocked<Connection>;
    let sender: PublicKey;
    let recipient: PublicKey;

    beforeEach(() => {
        sender = Keypair.generate().publicKey;
        recipient = Keypair.generate().publicKey;
        connection = {
            getAccountInfo: jest.fn(),
            getLatestBlockhash: jest.fn(),
        } as any;
        jest.clearAllMocks();
    });

    it('creates a SOL transfer transaction', async () => {
        connection.getAccountInfo
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 1000000000, data: Buffer.alloc(0) }) // sender (createTransfer)
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 0, data: Buffer.alloc(0) }) // recipient (createTransfer)
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 1000000000, data: Buffer.alloc(0) }) // sender (createSystemInstruction)
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 0, data: Buffer.alloc(0) }); // recipient (createSystemInstruction)
        connection.getLatestBlockhash.mockResolvedValue({ blockhash: 'blockhash', lastValidBlockHeight: 100 });

        const tx = await createTransfer(connection, sender, {
            recipient,
            amount: new BigNumber(1),
        });
        expect(tx).toBeInstanceOf(Transaction);
        expect(connection.getAccountInfo).toHaveBeenCalledTimes(4);
        expect(connection.getLatestBlockhash).toHaveBeenCalled();
    });

    it('throws if sender not found', async () => {
        connection.getAccountInfo.mockResolvedValueOnce(null);
        await expect(
            createTransfer(connection, sender, { recipient, amount: new BigNumber(1) })
        ).rejects.toThrow(CreateTransferError);
    });

    it('throws if recipient not found', async () => {
        connection.getAccountInfo
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 1000000000, data: Buffer.alloc(0) })
            .mockResolvedValueOnce(null);
        await expect(
            createTransfer(connection, sender, { recipient, amount: new BigNumber(1) })
        ).rejects.toThrow(CreateTransferError);
    });

    it('creates an SPL token transfer transaction', async () => {
        const splToken = Keypair.generate().publicKey;
        connection.getAccountInfo
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 1000000000, data: Buffer.alloc(0) }) // sender
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 0, data: Buffer.alloc(0) }); // recipient
        connection.getLatestBlockhash.mockResolvedValue({ blockhash: 'blockhash', lastValidBlockHeight: 100 });

        // SPL mocks
        getMint.mockResolvedValue({ isInitialized: true, decimals: 6 });
        getAssociatedTokenAddress.mockResolvedValueOnce('senderATA').mockResolvedValueOnce('recipientATA');
        getAccount
            .mockResolvedValueOnce({ isInitialized: true, isFrozen: false, amount: BigInt(1000000) }) // sender
            .mockResolvedValueOnce({ isInitialized: true, isFrozen: false, amount: BigInt(0) }); // recipient

        const tx = await createTransfer(connection, sender, {
            recipient,
            amount: new BigNumber(1),
            splToken,
        });
        expect(tx).toBeInstanceOf(Transaction);
        expect(getMint).toHaveBeenCalledWith(connection, splToken);
        expect(getAccount).toHaveBeenCalledTimes(2);
    });

    it('throws if SPL mint not initialized', async () => {
        const splToken = Keypair.generate().publicKey;
        connection.getAccountInfo
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 1000000000, data: Buffer.alloc(0) })
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 0, data: Buffer.alloc(0) });
        getMint.mockResolvedValue({ isInitialized: false });
        await expect(
            createTransfer(connection, sender, {
                recipient,
                amount: new BigNumber(1),
                splToken,
            })
        ).rejects.toThrow(CreateTransferError);
    });

    it('throws if SPL sender account not initialized', async () => {
        const splToken = Keypair.generate().publicKey;
        connection.getAccountInfo
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 1000000000, data: Buffer.alloc(0) })
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 0, data: Buffer.alloc(0) });
        getMint.mockResolvedValue({ isInitialized: true, decimals: 6 });
        getAssociatedTokenAddress.mockResolvedValueOnce('senderATA').mockResolvedValueOnce('recipientATA');
        getAccount
            .mockResolvedValueOnce({ isInitialized: false })
            .mockResolvedValueOnce({ isInitialized: true, isFrozen: false, amount: BigInt(0) });
        await expect(
            createTransfer(connection, sender, {
                recipient,
                amount: new BigNumber(1),
                splToken,
            })
        ).rejects.toThrow(CreateTransferError);
    });

    it('throws if SPL sender account is frozen', async () => {
        const splToken = Keypair.generate().publicKey;
        connection.getAccountInfo
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 1000000000, data: Buffer.alloc(0) })
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 0, data: Buffer.alloc(0) });
        getMint.mockResolvedValue({ isInitialized: true, decimals: 6 });
        getAssociatedTokenAddress.mockResolvedValueOnce('senderATA').mockResolvedValueOnce('recipientATA');
        getAccount
            .mockResolvedValueOnce({ isInitialized: true, isFrozen: true })
            .mockResolvedValueOnce({ isInitialized: true, isFrozen: false, amount: BigInt(0) });
        await expect(
            createTransfer(connection, sender, {
                recipient,
                amount: new BigNumber(1),
                splToken,
            })
        ).rejects.toThrow(CreateTransferError);
    });

    it('throws if SPL recipient account not initialized', async () => {
        const splToken = Keypair.generate().publicKey;
        connection.getAccountInfo
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 1000000000, data: Buffer.alloc(0) })
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 0, data: Buffer.alloc(0) });
        getMint.mockResolvedValue({ isInitialized: true, decimals: 6 });
        getAssociatedTokenAddress.mockResolvedValueOnce('senderATA').mockResolvedValueOnce('recipientATA');
        getAccount
            .mockResolvedValueOnce({ isInitialized: true, isFrozen: false, amount: BigInt(1000000) })
            .mockResolvedValueOnce({ isInitialized: false });
        await expect(
            createTransfer(connection, sender, {
                recipient,
                amount: new BigNumber(1),
                splToken,
            })
        ).rejects.toThrow(CreateTransferError);
    });

    it('throws if SPL recipient account is frozen', async () => {
        const splToken = Keypair.generate().publicKey;
        connection.getAccountInfo
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 1000000000, data: Buffer.alloc(0) })
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 0, data: Buffer.alloc(0) });
        getMint.mockResolvedValue({ isInitialized: true, decimals: 6 });
        getAssociatedTokenAddress.mockResolvedValueOnce('senderATA').mockResolvedValueOnce('recipientATA');
        getAccount
            .mockResolvedValueOnce({ isInitialized: true, isFrozen: false, amount: BigInt(1000000) })
            .mockResolvedValueOnce({ isInitialized: true, isFrozen: true });
        await expect(
            createTransfer(connection, sender, {
                recipient,
                amount: new BigNumber(1),
                splToken,
            })
        ).rejects.toThrow(CreateTransferError);
    });

    it('throws if SPL sender has insufficient funds', async () => {
        const splToken = Keypair.generate().publicKey;
        connection.getAccountInfo
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 1000000000, data: Buffer.alloc(0) })
            .mockResolvedValueOnce({ owner: SystemProgram.programId, executable: false, lamports: 0, data: Buffer.alloc(0) });
        getMint.mockResolvedValue({ isInitialized: true, decimals: 6 });
        getAssociatedTokenAddress.mockResolvedValueOnce('senderATA').mockResolvedValueOnce('recipientATA');
        getAccount
            .mockResolvedValueOnce({ isInitialized: true, isFrozen: false, amount: BigInt(1) })
            .mockResolvedValueOnce({ isInitialized: true, isFrozen: false, amount: BigInt(0) });
        await expect(
            createTransfer(connection, sender, {
                recipient,
                amount: new BigNumber(2),
                splToken,
            })
        ).rejects.toThrow(CreateTransferError);
    });
});