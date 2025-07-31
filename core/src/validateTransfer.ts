import {
    decodeInstruction,
    getAssociatedTokenAddress,
    isTransferCheckedInstruction,
    isTransferInstruction,
} from '@solana/spl-token';
import type {
    ConfirmedTransactionMeta,
    Connection,
    Finality,
    Message,
    TransactionInstruction,
    TransactionResponse,
    TransactionSignature,
} from '@solana/web3.js';
import { LAMPORTS_PER_SOL, SystemInstruction, Transaction } from '@solana/web3.js';
import BigNumber from 'bignumber.js';
import { MEMO_PROGRAM_ID } from './constants.js';
import type { Amount, Memo, Recipient, Reference, References, SPLToken } from './types.js';

/**
 * Thrown when a transaction doesn't contain a valid Solana Pay transfer.
 */
export class ValidateTransferError extends Error {
    name = 'ValidateTransferError';
}

/**
 * Fields of a Solana Pay transfer request to validate.
 */
export interface ValidateTransferFields {
    /** `recipient` in the [Solana Pay spec](https://github.com/solana-labs/solana-pay/blob/master/SPEC.md#recipient). */
    recipient: Recipient;
    /** `amount` in the [Solana Pay spec](https://github.com/solana-labs/solana-pay/blob/master/SPEC.md#amount). */
    amount?: Amount;
    /** `spl-token` in the [Solana Pay spec](https://github.com/solana-labs/solana-pay/blob/master/SPEC.md#spl-token). */
    splToken?: SPLToken;
    /** `reference` in the [Solana Pay spec](https://github.com/solana-labs/solana-pay/blob/master/SPEC.md#reference). */
    reference?: References;
    /** `memo` in the [Solana Pay spec](https://github.com/solana-labs/solana-pay/blob/master/SPEC.md#memo). */
    memo?: Memo;
}

/**
 * Check that a given transaction contains a valid Solana Pay transfer.
 *
 * @param connection - A connection to the cluster.
 * @param signature - The signature of the transaction to validate.
 * @param fields - Fields of a Solana Pay transfer request to validate.
 * @param options - Options for `getTransaction`.
 *
 * @throws {ValidateTransferError}
 */

export function validateTransfer(
    connection: Connection,
    signature: TransactionSignature,
    { recipient, amount, splToken, reference, memo }: ValidateTransferFields & { amount: Amount },
    options?: { commitment?: Finality }
): Promise<TransactionResponse>;

/**
 * Check that a given transaction contains a valid Solana Pay transfer.
 *
 * @param connection - A connection to the cluster.
 * @param signature - The signature of the transaction to validate.
 * @param fields - Fields of a Solana Pay transfer request to validate.
 * @param options - Options for `getTransaction`.
 *
 * @throws {ValidateTransferError}
 */

export function validateTransfer(
    connection: Connection,
    signature: TransactionSignature,
    { recipient, amount, splToken, reference, memo }: ValidateTransferFields,
    options?: { commitment?: Finality }
): Promise<[transactionResponse: TransactionResponse, amount: Amount]>;

export async function validateTransfer(
    connection: Connection,
    signature: TransactionSignature,
    { recipient, amount, splToken, reference, memo }: ValidateTransferFields,
    options?: { commitment?: Finality }
): Promise<TransactionResponse | [TransactionResponse, Amount]> {
    const response = await connection.getTransaction(signature, options);
    if (!response) throw new ValidateTransferError('not found');

    const { message, signatures } = response.transaction;
    const meta = response.meta;
    if (!meta) throw new ValidateTransferError('missing meta');
    if (meta.err) throw meta.err;

    if (reference && !Array.isArray(reference)) {
        reference = [reference];
    }

    // Deserialize the transaction and make a copy of the instructions we're going to validate.
    const transaction = Transaction.populate(message, signatures);
    const instructions = transaction.instructions.slice();

    // Transfer instruction must be the last instruction
    const instruction = instructions.pop();
    if (!instruction) throw new ValidateTransferError('missing transfer instruction');
    const [preAmount, postAmount] = splToken
        ? await validateSPLTokenTransfer(instruction, message, meta, recipient, splToken, reference)
        : await validateSystemTransfer(instruction, message, meta, recipient, reference);

    const delta = postAmount.minus(preAmount);
    if (delta.lt(amount ?? BigNumber(1).div(LAMPORTS_PER_SOL)))
        throw new ValidateTransferError('amount not transferred');

    if (memo !== undefined) {
        // Memo instruction must be the second to last instruction
        const instruction = instructions.pop();
        if (!instruction) throw new ValidateTransferError('missing memo instruction');
        validateMemo(instruction, memo);
    }

    if (amount) return response;

    return [response, delta];
}

function validateMemo(instruction: TransactionInstruction, memo: string): void {
    // Check that the instruction is a memo instruction with no keys and the expected memo data.
    if (!instruction.programId.equals(MEMO_PROGRAM_ID)) throw new ValidateTransferError('invalid memo program');
    if (instruction.keys.length) throw new ValidateTransferError('invalid memo keys');
    if (!instruction.data.equals(Buffer.from(memo, 'utf8'))) throw new ValidateTransferError('invalid memo');
}

async function validateSystemTransfer(
    instruction: TransactionInstruction,
    message: Message,
    meta: ConfirmedTransactionMeta,
    recipient: Recipient,
    references?: Reference[]
): Promise<[BigNumber, BigNumber]> {
    const accountIndex = message.accountKeys.findIndex((pubkey) => pubkey.equals(recipient));
    if (accountIndex === -1) throw new ValidateTransferError('recipient not found');

    if (references) {
        // Check that the instruction is a system transfer instruction.
        SystemInstruction.decodeTransfer(instruction);

        // Check that the expected reference keys exactly match the extra keys provided to the instruction.
        const [_from, _to, ...extraKeys] = instruction.keys;
        const length = extraKeys.length;
        if (length !== references.length) throw new ValidateTransferError('invalid references');

        for (let i = 0; i < length; i++) {
            if (!extraKeys[i].pubkey.equals(references[i])) throw new ValidateTransferError(`invalid reference ${i}`);
        }
    }

    return [
        new BigNumber(meta.preBalances[accountIndex] || 0).div(LAMPORTS_PER_SOL),
        new BigNumber(meta.postBalances[accountIndex] || 0).div(LAMPORTS_PER_SOL),
    ];
}

async function validateSPLTokenTransfer(
    instruction: TransactionInstruction,
    message: Message,
    meta: ConfirmedTransactionMeta,
    recipient: Recipient,
    splToken: SPLToken,
    references?: Reference[]
): Promise<[BigNumber, BigNumber]> {
    const recipientATA = await getAssociatedTokenAddress(splToken, recipient);
    const accountIndex = message.accountKeys.findIndex((pubkey) => pubkey.equals(recipientATA));
    if (accountIndex === -1) throw new ValidateTransferError('recipient not found');

    if (references) {
        // Check that the first instruction is an SPL token transfer instruction.
        const decodedInstruction = decodeInstruction(instruction);
        if (!isTransferCheckedInstruction(decodedInstruction) && !isTransferInstruction(decodedInstruction))
            throw new ValidateTransferError('invalid transfer');

        // Check that the expected reference keys exactly match the extra keys provided to the instruction.
        const extraKeys = decodedInstruction.keys.multiSigners;
        const length = extraKeys.length;
        if (length !== references.length) throw new ValidateTransferError('invalid references');

        for (let i = 0; i < length; i++) {
            if (!extraKeys[i].pubkey.equals(references[i])) throw new ValidateTransferError(`invalid reference ${i}`);
        }
    }

    const preBalance = meta.preTokenBalances?.find((x) => x.accountIndex === accountIndex);
    const postBalance = meta.postTokenBalances?.find((x) => x.accountIndex === accountIndex);

    return [
        new BigNumber(preBalance?.uiTokenAmount.uiAmountString || 0),
        new BigNumber(postBalance?.uiTokenAmount.uiAmountString || 0),
    ];
}
