import type {
    Address,
    Commitment,
    GetAccountInfoApi,
    GetLatestBlockhashApi,
    GetMultipleAccountsApi,
    Instruction,
    TransactionSigner,
} from '@solana/kit';
import type { ClientWithPayer, ClientWithRpc } from '@solana/plugin-interfaces';

import { createTransfer } from '../createTransfer.js';
import type { FetchedTransaction } from '../fetchTransaction.js';
import { fetchTransaction } from '../fetchTransaction.js';
import type { TransactionRequestURL, TransferRequestURL } from '../parseURL.js';
import { parseURL } from '../parseURL.js';
import type { TransferFields } from '../types.js';

type WalletRpcApi = GetAccountInfoApi & GetLatestBlockhashApi & GetMultipleAccountsApi;

type WalletCompatibleClient = ClientWithRpc<WalletRpcApi> & Partial<ClientWithPayer>;

/** Methods added to a client by the wallet plugin. */
export interface SolanaPayWalletMethods {
    readonly pay: {
        parseURL(url: URL | string): TransactionRequestURL | TransferRequestURL;
        createTransfer(fields: TransferFields, sender?: TransactionSigner): Promise<Instruction[]>;
        fetchTransaction(
            account: Address,
            link: URL | string,
            options?: { commitment?: Commitment },
        ): Promise<FetchedTransaction>;
    };
}

/**
 * Wallet plugin for Solana Pay.
 *
 * Adds a `pay` namespace with wallet-side methods: URL parsing,
 * transfer instruction creation, and transaction request fetching.
 * Payer is required for `createTransfer` (via explicit sender or `client.payer`).
 */
export function solanaPayWallet() {
    return function installWallet<TClient extends WalletCompatibleClient>(
        client: TClient,
    ): SolanaPayWalletMethods & TClient {
        const existingPay = 'pay' in client ? (client as { pay: Record<string, unknown> }).pay : {};
        const pay: SolanaPayWalletMethods['pay'] = {
            ...existingPay,
            parseURL(url: URL | string): TransactionRequestURL | TransferRequestURL {
                return parseURL(url);
            },
            async createTransfer(fields: TransferFields, sender?: TransactionSigner): Promise<Instruction[]> {
                const signer = sender ?? client.payer;
                if (!signer) {
                    throw new Error('solanaPayWallet.createTransfer requires a sender or client.payer');
                }
                return await createTransfer(client.rpc, signer, fields);
            },
            async fetchTransaction(
                account: Address,
                link: URL | string,
                options?: { commitment?: Commitment },
            ): Promise<FetchedTransaction> {
                return await fetchTransaction(client.rpc, account, link, options);
            },
        };

        return Object.freeze({ ...client, pay });
    };
}
