import { assertIsSignatureBytes, verifySignature } from '@solana/keys';
import type {
    Address,
    Commitment,
    CompiledTransactionMessage,
    CompiledTransactionMessageWithLifetime,
    GetLatestBlockhashApi,
    Instruction,
    ReadonlyUint8Array,
    Rpc,
    Transaction,
    TransactionMessage,
    TransactionVersion,
} from '@solana/kit';
import {
    address,
    compileTransaction,
    decompileTransactionMessage,
    getAddressEncoder,
    getBase64Encoder,
    getCompiledTransactionMessageDecoder,
    getTransactionDecoder,
    getTransactionMessageComputeUnitLimit,
    getTransactionMessageComputeUnitPrice,
    setTransactionMessageFeePayer,
    setTransactionMessageLifetimeUsingBlockhash,
} from '@solana/kit';
import { SYSTEM_PROGRAM_ADDRESS } from '@solana-program/system';
import { TOKEN_PROGRAM_ADDRESS } from '@solana-program/token';

import { MEMO_PROGRAM_ADDRESS, TOKEN_2022_PROGRAM_ADDRESS } from './constants.js';

/**
 * Thrown when a transaction response can't be fetched.
 */
export class FetchTransactionError extends Error {
    name = 'FetchTransactionError';
}

const SUPPORTED_TRANSACTION_VERSIONS: readonly TransactionVersion[] = ['legacy', 0, 1];

/** Default ceiling for the total priority fee the account may be asked to pay (0.001 SOL). */
export const DEFAULT_MAX_PRIORITY_FEE_LAMPORTS = 1_000_000n;

/** Default ceiling for the compute unit limit (the network maximum). */
export const DEFAULT_MAX_COMPUTE_UNIT_LIMIT = 1_400_000;

const COMPUTE_BUDGET_PROGRAM_ADDRESS = address('ComputeBudget111111111111111111111111111111');

/** Compute units budgeted per instruction when a legacy/v0 transaction sets no explicit limit. */
const DEFAULT_COMPUTE_UNITS_PER_INSTRUCTION = 200_000;

const MICRO_LAMPORTS_PER_LAMPORT = 1_000_000n;

/** Programs on which `account` is expected to sign in a Solana Pay transaction. */
const EXPECTED_SIGNER_PROGRAMS: readonly Address[] = [
    SYSTEM_PROGRAM_ADDRESS,
    TOKEN_PROGRAM_ADDRESS,
    TOKEN_2022_PROGRAM_ADDRESS,
    MEMO_PROGRAM_ADDRESS,
];

/** What a merchant-supplied transaction asks of the account, decoded before it is signed. */
export interface TransactionInspection {
    /** Compute unit limit the transaction requests, explicit or defaulted per network rules. */
    readonly computeUnitLimit: number;
    /** The decoded instructions of the transaction message. */
    readonly instructions: readonly Instruction[];
    /**
     * Maximum total priority fee in lamports the fee payer would pay: for legacy/v0, the
     * ComputeBudget unit price times the compute unit limit; for v1, the message config's
     * `priorityFeeLamports`.
     */
    readonly maxPriorityFeeLamports: bigint;
    /** The transaction version. */
    readonly version: TransactionVersion;
}

/**
 * A compiled transaction with message bytes and signatures, plus the decoded
 * {@link TransactionInspection} so callers can display what the account is signing.
 */
export type FetchedTransaction = Transaction & {
    readonly inspection: TransactionInspection;
};

/** Options for {@link fetchTransaction}. */
export interface FetchTransactionOptions {
    /** Options for `getLatestBlockhash`. */
    commitment?: Commitment;
    /**
     * Reject transactions requesting a compute unit limit above this value when the account
     * pays the fees. Defaults to {@link DEFAULT_MAX_COMPUTE_UNIT_LIMIT}.
     */
    maxComputeUnitLimit?: number;
    /**
     * Reject transactions asking the account to pay a total priority fee above this value.
     * Defaults to {@link DEFAULT_MAX_PRIORITY_FEE_LAMPORTS}.
     */
    maxPriorityFeeLamports?: bigint;
}

function inspectTransactionMessage(message: TransactionMessage): TransactionInspection {
    const explicitLimit = getTransactionMessageComputeUnitLimit(message);
    let computeUnitLimit: number;
    let maxPriorityFeeLamports: bigint;
    if (message.version === 1) {
        computeUnitLimit = explicitLimit ?? 0;
        maxPriorityFeeLamports = message.config?.priorityFeeLamports ?? 0n;
    } else {
        const budgetedInstructions = message.instructions.filter(
            ix => ix.programAddress !== COMPUTE_BUDGET_PROGRAM_ADDRESS,
        ).length;
        computeUnitLimit =
            explicitLimit ??
            Math.min(budgetedInstructions * DEFAULT_COMPUTE_UNITS_PER_INSTRUCTION, DEFAULT_MAX_COMPUTE_UNIT_LIMIT);
        const computeUnitPriceMicroLamports = getTransactionMessageComputeUnitPrice(message) ?? 0n;
        maxPriorityFeeLamports =
            (computeUnitPriceMicroLamports * BigInt(computeUnitLimit) + MICRO_LAMPORTS_PER_LAMPORT - 1n) /
            MICRO_LAMPORTS_PER_LAMPORT;
    }
    return {
        computeUnitLimit,
        instructions: message.instructions,
        maxPriorityFeeLamports,
        version: message.version,
    };
}

function assertNoUnexpectedAccountUse(instructions: readonly Instruction[], account: Address): void {
    // Signer privileges are transaction-global on Solana: once the account signs the transaction,
    // every instruction referencing the account can act with its signature, regardless of the
    // role the merchant declared for it. So any reference from an unexpected program is rejected.
    for (const instruction of instructions) {
        const referencesAccount = instruction.accounts?.some(meta => meta.address === account);
        if (referencesAccount && !EXPECTED_SIGNER_PROGRAMS.includes(instruction.programAddress)) {
            throw new FetchTransactionError(
                `account is a signer on an unexpected instruction for program ${instruction.programAddress}`,
            );
        }
    }
}

function assertWithinFeeCeilings(inspection: TransactionInspection, options: FetchTransactionOptions): void {
    const maxPriorityFeeLamports = options.maxPriorityFeeLamports ?? DEFAULT_MAX_PRIORITY_FEE_LAMPORTS;
    const maxComputeUnitLimit = options.maxComputeUnitLimit ?? DEFAULT_MAX_COMPUTE_UNIT_LIMIT;
    if (inspection.maxPriorityFeeLamports > maxPriorityFeeLamports) {
        throw new FetchTransactionError(
            `priority fee of ${inspection.maxPriorityFeeLamports} lamports exceeds maximum of ${maxPriorityFeeLamports} lamports`,
        );
    }
    if (inspection.computeUnitLimit > maxComputeUnitLimit) {
        throw new FetchTransactionError(
            `compute unit limit of ${inspection.computeUnitLimit} exceeds maximum of ${maxComputeUnitLimit}`,
        );
    }
}

/**
 * Fetch a transaction from a Solana Pay transaction request link.
 *
 * The merchant-supplied transaction is inspected before it is returned for signing: unsupported
 * transaction versions are rejected, the account may only be a signer on transfer and memo
 * instructions, and — whenever the account pays the fees — the requested priority fee and compute
 * unit limit are checked against configurable ceilings. The decoded instructions, version, and
 * maximum priority fee are returned on the transaction's `inspection` field so wallets can
 * display them before signing.
 *
 * @param rpc - An RPC client supporting `getLatestBlockhash`.
 * @param account - Address of the account that may sign the transaction.
 * @param link - `link` in the [Solana Pay spec](https://github.com/solana-foundation/pay/blob/main/typescript/packages/solana-pay/spec/SPEC.md#link).
 * @param options - Fee ceilings and options for `getLatestBlockhash`.
 *
 * @throws {FetchTransactionError}
 */
export async function fetchTransaction(
    rpc: Rpc<GetLatestBlockhashApi>,
    account: Address,
    link: URL | string,
    options: FetchTransactionOptions = {},
): Promise<FetchedTransaction> {
    const { commitment } = options;
    let response: Response;
    try {
        response = await fetch(String(link), {
            method: 'POST',
            mode: 'cors',
            credentials: 'omit',
            headers: {
                'Cache-Control': 'no-cache',
                Accept: 'application/json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ account }),
        });
    } catch (error) {
        throw new FetchTransactionError(`network error: ${error instanceof Error ? error.message : String(error)}`);
    }

    if (!response.ok) throw new FetchTransactionError(`request failed: ${response.status}`);

    let json: Record<string, unknown>;
    try {
        json = (await response.json()) as Record<string, unknown>;
    } catch {
        throw new FetchTransactionError('response is not valid JSON');
    }
    if (!json?.transaction) throw new FetchTransactionError('missing transaction');
    if (typeof json.transaction !== 'string') throw new FetchTransactionError('invalid transaction');

    // Decode the base64 transaction string to bytes, then decode the transaction
    let transactionBytes: ReadonlyUint8Array;
    try {
        transactionBytes = getBase64Encoder().encode(json.transaction);
    } catch {
        throw new FetchTransactionError('invalid base64 in transaction');
    }

    let transaction: Transaction;
    try {
        transaction = getTransactionDecoder().decode(transactionBytes);
    } catch {
        throw new FetchTransactionError('failed to decode transaction wire format');
    }

    let compiledMessage: CompiledTransactionMessage & CompiledTransactionMessageWithLifetime;
    try {
        compiledMessage = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
    } catch {
        throw new FetchTransactionError('failed to decode compiled transaction message');
    }

    if (!SUPPORTED_TRANSACTION_VERSIONS.includes(compiledMessage.version)) {
        throw new FetchTransactionError(`unsupported transaction version: ${compiledMessage.version}`);
    }

    const message = decompileTransactionMessage(compiledMessage);
    const inspection = inspectTransactionMessage(message);

    // Extract signatures map
    const signatures = transaction.signatures;
    const signerAddresses = Object.keys(signatures).map(addr => address(addr));

    const hasSignatures = signerAddresses.some(addr => {
        const sig = signatures[addr];
        return sig != null && !sig.every((b: number) => b === 0);
    });

    const accountSignature = signatures[account];
    const accountMustSign = !hasSignatures || (accountSignature != null && accountSignature.every(b => b === 0));
    if (accountMustSign) {
        assertNoUnexpectedAccountUse(inspection.instructions, account);
    }

    const accountPaysFees = !hasSignatures || (accountMustSign && compiledMessage.staticAccounts[0] === account);
    if (accountPaysFees) {
        assertWithinFeeCeilings(inspection, options);
    }

    if (hasSignatures) {
        const feePayer = signerAddresses[0];
        if (!feePayer) throw new FetchTransactionError('missing fee payer');

        if (compiledMessage.staticAccounts.length === 0 || compiledMessage.staticAccounts[0] !== feePayer) {
            throw new FetchTransactionError('invalid fee payer');
        }

        if (!compiledMessage.lifetimeToken) {
            throw new FetchTransactionError('missing recent blockhash');
        }

        // A valid signature for everything except `account` must be provided.
        const addressEncoder = getAddressEncoder();
        for (const addr of signerAddresses) {
            const sig = signatures[addr];
            const isNonZero = sig != null && !sig.every((b: number) => b === 0);

            if (isNonZero) {
                const publicKeyBytes = addressEncoder.encode(addr);
                const cryptoKey = await crypto.subtle.importKey('raw', publicKeyBytes, { name: 'Ed25519' }, false, [
                    'verify',
                ]);
                assertIsSignatureBytes(sig);
                const isValid = await verifySignature(cryptoKey, sig, transaction.messageBytes);
                if (!isValid) throw new FetchTransactionError('invalid signature');
            } else if (addr === account) {
                // If the only signature needed is for `account`, refresh the blockhash
                if (signerAddresses.length === 1) {
                    const { value } = await rpc.getLatestBlockhash({ commitment }).send();
                    const updatedMsg = setTransactionMessageLifetimeUsingBlockhash(value, message);
                    return { ...compileTransaction(updatedMsg), inspection };
                }
            } else {
                throw new FetchTransactionError('missing signature');
            }
        }

        return { ...transaction, inspection };
    } else {
        // Ignore the fee payer and recent blockhash in the transaction and initialize them.
        const { value } = await rpc.getLatestBlockhash({ commitment }).send();
        const withFeePayer = setTransactionMessageFeePayer(account, message);
        const withLifetime = setTransactionMessageLifetimeUsingBlockhash(value, withFeePayer);
        return { ...compileTransaction(withLifetime), inspection };
    }
}
