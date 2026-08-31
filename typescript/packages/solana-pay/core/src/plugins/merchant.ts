import type { Address, GetSignaturesForAddressApi, GetTransactionApi, Instruction, Signature } from '@solana/kit';
import {
    appendTransactionMessageInstructions,
    compileTransaction,
    createTransactionMessage,
    getBase64EncodedWireTransaction,
    pipe,
    setTransactionMessageFeePayer,
} from '@solana/kit';
import type { ClientWithRpc, ClientWithRpcSubscriptions } from '@solana/plugin-interfaces';
import type { LogsNotificationsApi } from '@solana/rpc-subscriptions-api';

import { createQR, createQROptions } from '../createQR.js';
import type { TransactionRequestURLFields, TransferRequestURLFields } from '../encodeURL.js';
import { encodeURL } from '../encodeURL.js';
import type { ConfirmedSignatureInfo, FindReferenceOptions } from '../findReference.js';
import { findReference } from '../findReference.js';
import type { Finality, Reference, TransferFields } from '../types.js';
import { validateTransfer } from '../validateTransfer.js';
import type { WatchReferenceOptions, WatchReferenceResult } from '../watchReference.js';
import { watchReference } from '../watchReference.js';

type MerchantRpcApi = GetSignaturesForAddressApi & GetTransactionApi;

type MerchantRpcSubscriptionsApi = LogsNotificationsApi;

type MerchantCompatibleClient = ClientWithRpc<MerchantRpcApi> & ClientWithRpcSubscriptions<MerchantRpcSubscriptionsApi>;

/** Methods added to a client by the merchant plugin. */
export interface SolanaPayMerchantMethods {
    readonly pay: {
        encodeURL(fields: TransactionRequestURLFields | TransferRequestURLFields): URL;
        createQR(url: URL | string, size?: number, background?: string, color?: string): any;
        createQROptions(
            url: URL | string,
            size?: number,
            background?: string,
            color?: string,
        ): ReturnType<typeof createQROptions>;
        findReference(reference: Reference, options?: FindReferenceOptions): Promise<ConfirmedSignatureInfo>;
        watchReference(reference: Reference, options?: WatchReferenceOptions): Promise<WatchReferenceResult>;
        validateTransfer(
            signature: Signature,
            fields: TransferFields,
            options?: { commitment?: Finality },
        ): Promise<Awaited<ReturnType<typeof validateTransfer>>>;
        buildTransaction(feePayer: Address, instructions: Instruction[]): string;
    };
}

/**
 * Merchant plugin for Solana Pay.
 *
 * Adds a `pay` namespace with merchant-side methods: URL encoding,
 * QR code generation, reference lookup, and transfer validation.
 * No payer/signer required — merchant only reads from the network.
 */
export function solanaPayMerchant() {
    return function installMerchant<TClient extends MerchantCompatibleClient>(
        client: TClient,
    ): SolanaPayMerchantMethods & TClient {
        const existingPay = 'pay' in client ? (client as { pay: Record<string, unknown> }).pay : {};
        const pay: SolanaPayMerchantMethods['pay'] = {
            ...existingPay,
            encodeURL(fields: TransactionRequestURLFields | TransferRequestURLFields): URL {
                return encodeURL(fields);
            },
            createQR(url: URL | string, size?: number, background?: string, color?: string): any {
                return createQR(url, size, background, color);
            },
            createQROptions(url: URL | string, size?: number, background?: string, color?: string) {
                return createQROptions(url, size, background, color);
            },
            async findReference(reference: Reference, options?: FindReferenceOptions): Promise<ConfirmedSignatureInfo> {
                return await findReference(client.rpc, reference, options);
            },
            async watchReference(reference: Reference, options?: WatchReferenceOptions): Promise<WatchReferenceResult> {
                return await watchReference(client.rpcSubscriptions, reference, options);
            },
            async validateTransfer(signature: Signature, fields: TransferFields, options?: { commitment?: Finality }) {
                return await validateTransfer(client.rpc, signature, fields, options);
            },
            buildTransaction(feePayer: Address, instructions: Instruction[]): string {
                const tx = pipe(
                    createTransactionMessage({ version: 0 }),
                    m => setTransactionMessageFeePayer(feePayer, m),
                    m => appendTransactionMessageInstructions(instructions, m),
                );
                return getBase64EncodedWireTransaction(compileTransaction(tx));
            },
        };

        return Object.freeze({ ...client, pay });
    };
}
