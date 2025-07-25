import {
    createTransferCheckedInstruction,
    getAccount,
    getAssociatedTokenAddress,
    getMint,
    TOKEN_2022_PROGRAM_ID,
    TOKEN_PROGRAM_ID,
} from '@solana/spl-token';
import type { Commitment, Connection, GetLatestBlockhashConfig, PublicKey } from '@solana/web3.js';
import { LAMPORTS_PER_SOL, SystemProgram, Transaction, TransactionInstruction } from '@solana/web3.js';
import BigNumber from 'bignumber.js';
import { MEMO_PROGRAM_ID, SOL_DECIMALS, TEN } from './constants.js';
import type { Amount, Memo, Recipient, References, SPLToken } from './types.js';

/**
 * Thrown when a Solana Pay transfer transaction can't be created from the fields provided.
 */
export class CreateTransferError extends Error {
    name = 'CreateTransferError';
}

/**
 * Fields of a Solana Pay transfer request URL.
 */
export interface CreateTransferFields {
    /** `recipient` in the [Solana Pay spec](https://github.com/solana-labs/solana-pay/blob/master/SPEC.md#recipient). */
    recipient: Recipient;
    /** `amount` in the [Solana Pay spec](https://github.com/solana-labs/solana-pay/blob/master/SPEC.md#amount). */
    amount: Amount;
    /** `spl-token` in the [Solana Pay spec](https://github.com/solana-labs/solana-pay/blob/master/SPEC.md#spl-token). */
    splToken?: SPLToken;
    /** `reference` in the [Solana Pay spec](https://github.com/solana-labs/solana-pay/blob/master/SPEC.md#reference). */
    reference?: References;
    /** `memo` in the [Solana Pay spec](https://github.com/solana-labs/solana-pay/blob/master/SPEC.md#memo). */
    memo?: Memo;
}

/**
 * Create a Solana Pay transfer transaction.
 *
 * @param connection - A connection to the cluster.
 * @param sender - Account that will send the transfer.
 * @param fields - Fields of a Solana Pay transfer request URL.
 * @param options - Options for `getLatestBlockhash`.
 *
 * @throws {CreateTransferError}
 */
export async function createTransfer(
    connection: Connection,
    sender: PublicKey,
    { recipient, amount, splToken, reference, memo }: CreateTransferFields,
    { commitment }: { commitment?: Commitment | GetLatestBlockhashConfig } = {}
): Promise<Transaction> {
    // Check that the sender and recipient accounts exist
    const senderInfo = await connection.getAccountInfo(sender);
    if (!senderInfo) throw new CreateTransferError('sender not found');

    const recipientInfo = await connection.getAccountInfo(recipient);
    if (!recipientInfo) throw new CreateTransferError('recipient not found');

    // A native SOL or SPL token transfer instruction
    const instruction = splToken
        ? await createSPLTokenInstruction(recipient, amount, splToken, sender, connection)
        : await createSystemInstruction(recipient, amount, sender, connection);

    // If reference accounts are provided, add them to the transfer instruction
    if (reference) {
        if (!Array.isArray(reference)) {
            reference = [reference];
        }

        for (const pubkey of reference) {
            instruction.keys.push({ pubkey, isWritable: false, isSigner: false });
        }
    }

    // Create the transaction
    const transaction = new Transaction();
    transaction.feePayer = sender;
    transaction.recentBlockhash = (await connection.getLatestBlockhash(commitment)).blockhash;

    // If a memo is provided, add it to the transaction before adding the transfer instruction
    if (memo != null) {
        transaction.add(
            new TransactionInstruction({
                programId: MEMO_PROGRAM_ID,
                keys: [],
                data: Buffer.from(memo, 'utf8'),
            })
        );
    }

    // Add the transfer instruction to the transaction
    transaction.add(instruction);

    return transaction;
}

async function createSystemInstruction(
    recipient: PublicKey,
    amount: BigNumber,
    sender: PublicKey,
    connection: Connection
): Promise<TransactionInstruction> {
    // Check that the sender and recipient accounts exist
    const senderInfo = await connection.getAccountInfo(sender);
    if (!senderInfo) throw new CreateTransferError('sender not found');

    const recipientInfo = await connection.getAccountInfo(recipient);
    if (!recipientInfo) throw new CreateTransferError('recipient not found');

    // Check that the sender and recipient are valid native accounts
    if (!senderInfo.owner.equals(SystemProgram.programId)) throw new CreateTransferError('sender owner invalid');
    if (senderInfo.executable) throw new CreateTransferError('sender executable');
    if (!recipientInfo.owner.equals(SystemProgram.programId)) throw new CreateTransferError('recipient owner invalid');
    if (recipientInfo.executable) throw new CreateTransferError('recipient executable');

    // Check that the amount provided doesn't have greater precision than SOL
    if ((amount.decimalPlaces() ?? 0) > SOL_DECIMALS) throw new CreateTransferError('amount decimals invalid');

    // Convert input decimal amount to integer lamports
    amount = amount.times(LAMPORTS_PER_SOL).integerValue(BigNumber.ROUND_FLOOR);

    // Check that the sender has enough lamports
    const lamports = amount.toNumber();
    if (lamports > senderInfo.lamports) throw new CreateTransferError('insufficient funds');

    // Create an instruction to transfer native SOL
    return SystemProgram.transfer({
        fromPubkey: sender,
        toPubkey: recipient,
        lamports,
    });
}

async function createSPLTokenInstruction(
    recipient: PublicKey,
    amount: BigNumber,
    splToken: PublicKey,
    sender: PublicKey,
    connection: Connection
): Promise<TransactionInstruction> {
    // Check if token owns the Token-2022 Program
    const accountInfo = await connection.getParsedAccountInfo(splToken);
    const accountOwner = accountInfo.value?.owner;
    const tokenProgram =
        accountOwner && accountOwner === TOKEN_2022_PROGRAM_ID ? TOKEN_2022_PROGRAM_ID : TOKEN_PROGRAM_ID;

    // Check that the token provided is an initialized mint
    const mint = await getMint(connection, splToken, undefined, tokenProgram);
    if (!mint.isInitialized) throw new CreateTransferError('mint not initialized');

    // Check that the amount provided doesn't have greater precision than the mint
    if ((amount.decimalPlaces() ?? 0) > mint.decimals) throw new CreateTransferError('amount decimals invalid');

    // Convert input decimal amount to integer tokens according to the mint decimals
    amount = amount.times(TEN.pow(mint.decimals)).integerValue(BigNumber.ROUND_FLOOR);

    // Get the sender's ATA and check that the account exists and can send tokens
    const senderATA = await getAssociatedTokenAddress(splToken, sender, undefined, tokenProgram);
    const senderAccount = await getAccount(connection, senderATA, undefined, tokenProgram);
    if (!senderAccount.isInitialized) throw new CreateTransferError('sender not initialized');
    if (senderAccount.isFrozen) throw new CreateTransferError('sender frozen');

    // Get the recipient's ATA and check that the account exists and can receive tokens
    const recipientATA = await getAssociatedTokenAddress(splToken, recipient, undefined, tokenProgram);
    const recipientAccount = await getAccount(connection, recipientATA, undefined, tokenProgram);
    if (!recipientAccount.isInitialized) throw new CreateTransferError('recipient not initialized');
    if (recipientAccount.isFrozen) throw new CreateTransferError('recipient frozen');

    // Check that the sender has enough tokens
    const tokens = BigInt(String(amount));
    if (tokens > senderAccount.amount) throw new CreateTransferError('insufficient funds');

    // Create an instruction to transfer SPL tokens, asserting the mint and decimals match
    return createTransferCheckedInstruction(
        senderATA,
        splToken,
        recipientATA,
        sender,
        tokens,
        mint.decimals,
        [],
        tokenProgram
    );
}
