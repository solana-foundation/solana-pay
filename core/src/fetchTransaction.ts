import type { Commitment, Connection, GetLatestBlockhashConfig, PublicKey } from '@solana/web3.js';
import { Transaction } from '@solana/web3.js';
import fetch from 'cross-fetch';
import { toUint8Array } from 'js-base64';
import nacl from 'tweetnacl';

/**
 * Thrown when a transaction response can't be fetched.
 */
export class FetchTransactionError extends Error {
    name = 'FetchTransactionError';
}

/**
 * Fetch a transaction from a Solana Pay transaction request link.
 *
 * @param connection - A connection to the cluster.
 * @param account - Account that may sign the transaction.
 * @param link - `link` in the [Solana Pay spec](https://github.com/solana-labs/solana-pay/blob/master/SPEC.md#link).
 * @param options - Options for `getLatestBlockhash`.
 *
 * @throws {FetchTransactionError}
 */
export async function fetchTransaction(
    connection: Connection,
    account: PublicKey,
    link: string | URL,
    { commitment }: { commitment?: Commitment | GetLatestBlockhashConfig } = {}
): Promise<Transaction> {
    const response = await fetch(String(link), {
        method: 'POST',
        mode: 'cors',
        cache: 'no-cache',
        credentials: 'omit',
        headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ account }),
    });

    const json = await response.json();
    if (!json?.transaction) throw new FetchTransactionError('missing transaction');
    if (typeof json.transaction !== 'string') throw new FetchTransactionError('invalid transaction');

    const transaction = Transaction.from(toUint8Array(json.transaction));
    const { signatures, feePayer, recentBlockhash } = transaction;

    if (signatures.length) {
        if (!feePayer) throw new FetchTransactionError('missing fee payer');
        if (!feePayer.equals(signatures[0].publicKey)) throw new FetchTransactionError('invalid fee payer');
        if (!recentBlockhash) throw new FetchTransactionError('missing recent blockhash');

        // A valid signature for everything except `account` must be provided.
        const message = transaction.serializeMessage();
        for (const { signature, publicKey } of signatures) {
            if (signature) {
                if (!nacl.sign.detached.verify(message, signature, publicKey.toBuffer()))
                    throw new FetchTransactionError('invalid signature');
            } else if (publicKey.equals(account)) {
                // If the only signature expected is for `account`, ignore the recent blockhash in the transaction.
                if (signatures.length === 1) {
                    transaction.recentBlockhash = (await connection.getLatestBlockhash(commitment)).blockhash;
                }
            } else {
                throw new FetchTransactionError('missing signature');
            }
        }
    } else {
        // Ignore the fee payer and recent blockhash in the transaction and initialize them.
        transaction.feePayer = account;
        transaction.recentBlockhash = (await connection.getLatestBlockhash(commitment)).blockhash;
    }

    return transaction;
}
