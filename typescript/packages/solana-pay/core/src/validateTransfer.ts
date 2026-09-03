import type {
    AccountMeta,
    Address,
    Base64EncodedDataResponse,
    GetTransactionApi,
    Instruction,
    InstructionWithAccounts,
    InstructionWithData,
    Lamports,
    ReadonlyUint8Array,
    Rpc,
    Signature,
    TokenBalance,
} from '@solana/kit';
import {
    decompileTransactionMessage,
    getBase64Codec,
    getCompiledTransactionMessageCodec,
    getTransactionCodec,
    MAX_SUPPORTED_TRANSACTION_VERSION,
} from '@solana/kit';
import { parseAddMemoInstruction } from '@solana-program/memo';
import {
    identifySystemInstruction,
    parseTransferSolInstruction,
    SYSTEM_PROGRAM_ADDRESS,
    SystemInstruction,
} from '@solana-program/system';
import {
    findAssociatedTokenPda,
    identifyTokenInstruction,
    parseTransferCheckedInstruction,
    parseTransferInstruction,
    TOKEN_PROGRAM_ADDRESS,
    TokenInstruction,
} from '@solana-program/token';

import { MEMO_PROGRAM_ADDRESS, SOL_DECIMALS, TOKEN_2022_PROGRAM_ADDRESS } from './constants.js';
import type { Finality, Reference, TransferFields } from './types.js';
import { amountToBaseUnits } from './utils/amount.js';
import { normalizeReferences } from './utils/reference.js';

/**
 * Thrown when a transaction doesn't contain a valid Solana Pay transfer.
 */
export class ValidateTransferError extends Error {
    name = 'ValidateTransferError';
}

/** A decompiled instruction with accounts and data present. */
type DecompiledInstruction = Instruction &
    InstructionWithAccounts<readonly AccountMeta[]> &
    InstructionWithData<ReadonlyUint8Array>;

/** Balance change result from validation helpers. */
interface BalanceChange {
    pre: bigint;
    post: bigint;
    decimals: number;
}

/** Meta from a base64-encoded getTransaction response. */
type TransactionMeta = {
    err: unknown;
    preBalances: readonly Lamports[];
    postBalances: readonly Lamports[];
    preTokenBalances?: readonly TokenBalance[];
    postTokenBalances?: readonly TokenBalance[];
};

function validateAmount(amount: number): void {
    if (!Number.isFinite(amount) || amount < 0) {
        throw new ValidateTransferError('amount invalid');
    }
}

function parseBase64Transaction(b64TransactionResponse: Base64EncodedDataResponse) {
    const [base64Transaction] = b64TransactionResponse;
    const transactionBytes = getBase64Codec().encode(base64Transaction);
    const transaction = getTransactionCodec().decode(transactionBytes);
    const compiledMessage = getCompiledTransactionMessageCodec().decode(transaction.messageBytes);
    const decompiledMessage = decompileTransactionMessage(compiledMessage);
    const { staticAccounts } = compiledMessage;
    const instructions = [...decompiledMessage.instructions];
    return { instructions, staticAccounts };
}

function getMeta(meta: TransactionMeta | null) {
    if (!meta) throw new ValidateTransferError('missing meta');
    if (meta.err) throw new ValidateTransferError(JSON.stringify(meta.err));
    return meta;
}

function validateInstruction(instruction: Instruction | undefined): asserts instruction is DecompiledInstruction {
    if (!instruction) {
        throw new ValidateTransferError('missing instruction');
    }

    if (!instruction.accounts) {
        throw new ValidateTransferError('missing instruction accounts');
    }

    if (!instruction.data) {
        throw new ValidateTransferError('missing instruction data');
    }
}

/**
 * Check that a given transaction contains a valid Solana Pay transfer.
 *
 * @param rpc - An RPC client supporting `getTransaction`.
 * @param signature - The signature of the transaction to validate.
 * @param fields - Fields of a Solana Pay transfer request to validate.
 * @param options - Options for `getTransaction`.
 *
 * @throws {ValidateTransferError}
 */
export async function validateTransfer(
    rpc: Rpc<GetTransactionApi>,
    signature: Signature,
    { recipient, amount, splToken, reference, memo }: TransferFields,
    options?: { commitment?: Finality },
) {
    validateAmount(amount);
    const refs = normalizeReferences(reference);

    const response = await rpc
        .getTransaction(signature, {
            commitment: options?.commitment ?? 'confirmed',
            maxSupportedTransactionVersion: MAX_SUPPORTED_TRANSACTION_VERSION,
            encoding: 'base64',
        })
        .send();

    if (!response) throw new ValidateTransferError('not found');

    const meta = getMeta(response.meta);
    const { instructions, staticAccounts } = parseBase64Transaction(response.transaction);

    // Transfer instruction must be the last instruction
    const instruction = instructions.pop();
    validateInstruction(instruction);

    const { pre, post, decimals } = splToken
        ? await validateSPLTokenTransfer(instruction, staticAccounts, meta, recipient, splToken, refs)
        : validateSystemTransfer(instruction, staticAccounts, meta, recipient, refs);

    const expected = amountToBaseUnits(amount, decimals);
    if (post - pre < expected) throw new ValidateTransferError('amount not transferred');

    if (memo !== undefined) {
        validateMemo(instructions.pop(), memo);
    }

    return response;
}

function validateMemo(instruction: Instruction | undefined, memo: string): void {
    if (!instruction) throw new ValidateTransferError('missing memo instruction');
    if (instruction.programAddress !== MEMO_PROGRAM_ADDRESS) {
        throw new ValidateTransferError('invalid memo program');
    }
    if (!instruction.data) throw new ValidateTransferError('invalid memo');

    const parsed = parseAddMemoInstruction(instruction as Instruction & InstructionWithData<ReadonlyUint8Array>);
    if (parsed.data.memo !== memo) throw new ValidateTransferError('invalid memo');
}

function validateProgram(instruction: DecompiledInstruction, validPrograms: readonly Address[]): void {
    if (!validPrograms.includes(instruction.programAddress)) {
        throw new ValidateTransferError('invalid transfer');
    }
}

function validateReferences(
    instruction: DecompiledInstruction,
    requiredAccounts: number,
    references?: Reference[],
): void {
    if (!references) return;
    const extraAccounts = instruction.accounts.slice(requiredAccounts);
    if (extraAccounts.length !== references.length) throw new ValidateTransferError('invalid references');

    for (let i = 0; i < extraAccounts.length; i++) {
        if (extraAccounts[i].address !== references[i]) throw new ValidateTransferError(`invalid reference ${i}`);
    }
}

function validateSystemTransfer(
    instruction: DecompiledInstruction,
    staticAccounts: readonly Address[],
    meta: TransactionMeta,
    recipient: Address,
    references?: Reference[],
): BalanceChange {
    validateProgram(instruction, [SYSTEM_PROGRAM_ADDRESS]);

    const instructionType = identifySystemInstruction(instruction);
    if (instructionType !== SystemInstruction.TransferSol) {
        throw new ValidateTransferError('invalid transfer');
    }

    const parsed = parseTransferSolInstruction(instruction);
    if (parsed.accounts.destination.address !== recipient) {
        throw new ValidateTransferError('invalid transfer');
    }

    validateReferences(instruction, Object.keys(parsed.accounts).length, references);

    const accountIndex = staticAccounts.indexOf(recipient);
    if (accountIndex === -1) throw new ValidateTransferError('recipient not found');

    const pre = meta.preBalances[accountIndex];
    const post = meta.postBalances[accountIndex];
    if (pre === undefined || post === undefined) throw new ValidateTransferError('missing balance data');
    return { pre, post, decimals: SOL_DECIMALS };
}

async function validateSPLTokenTransfer(
    instruction: DecompiledInstruction,
    staticAccounts: readonly Address[],
    meta: TransactionMeta,
    recipient: Address,
    splToken: Address,
    references?: Reference[],
): Promise<BalanceChange> {
    validateProgram(instruction, [TOKEN_PROGRAM_ADDRESS, TOKEN_2022_PROGRAM_ADDRESS]);

    const instructionType = identifyTokenInstruction(instruction);

    const [recipientATA] = await findAssociatedTokenPda({
        owner: recipient,
        tokenProgram: instruction.programAddress,
        mint: splToken,
    });

    let requiredAccounts: number;
    switch (instructionType) {
        case TokenInstruction.TransferChecked: {
            const parsed = parseTransferCheckedInstruction(instruction);
            if (parsed.accounts.destination.address !== recipientATA) {
                throw new ValidateTransferError('invalid transfer');
            }
            if (parsed.accounts.mint.address !== splToken) {
                throw new ValidateTransferError('invalid transfer');
            }
            requiredAccounts = Object.keys(parsed.accounts).length;
            break;
        }
        case TokenInstruction.Transfer: {
            const parsed = parseTransferInstruction(instruction);
            if (parsed.accounts.destination.address !== recipientATA) {
                throw new ValidateTransferError('invalid transfer');
            }
            requiredAccounts = Object.keys(parsed.accounts).length;
            break;
        }
        default:
            throw new ValidateTransferError('invalid transfer instruction');
    }

    validateReferences(instruction, requiredAccounts, references);

    const accountIndex = staticAccounts.indexOf(recipientATA);
    if (accountIndex === -1) throw new ValidateTransferError('recipient not found');

    const preBalance = meta.preTokenBalances?.find(x => x.accountIndex === accountIndex);
    const postBalance = meta.postTokenBalances?.find(x => x.accountIndex === accountIndex);
    if (!preBalance || !postBalance) throw new ValidateTransferError('missing balance data');

    return {
        pre: BigInt(preBalance.uiTokenAmount.amount),
        post: BigInt(postBalance.uiTokenAmount.amount),
        decimals: preBalance.uiTokenAmount.decimals,
    };
}
