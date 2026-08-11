//! Associated Token Account derivation.
//!
//! ATA = `find_program_address([owner, token_program, mint], ATA_PROGRAM_ID)`.
//! See: <https://spl.solana.com/associated-token-account>.

use solana_pubkey::{Pubkey, pubkey};

pub const ATA_PROGRAM_ID: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const SPL_TOKEN_PROGRAM_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN_2022_PROGRAM_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Derive the ATA for `owner` holding `mint` under `token_program`.
pub fn associated_token_address(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    let (ata, _) = Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ATA_PROGRAM_ID,
    );
    ata
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn fixed_owner() -> Pubkey {
        Pubkey::from_str("11111111111111111111111111111112").unwrap()
    }
    fn usdc() -> Pubkey {
        Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap()
    }
    fn usdt() -> Pubkey {
        Pubkey::from_str("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB").unwrap()
    }

    #[test]
    fn deterministic() {
        let a = associated_token_address(&fixed_owner(), &usdc(), &SPL_TOKEN_PROGRAM_ID);
        let b = associated_token_address(&fixed_owner(), &usdc(), &SPL_TOKEN_PROGRAM_ID);
        assert_eq!(a, b);
    }

    #[test]
    fn differs_per_token_program() {
        let a = associated_token_address(&fixed_owner(), &usdc(), &SPL_TOKEN_PROGRAM_ID);
        let b = associated_token_address(&fixed_owner(), &usdc(), &TOKEN_2022_PROGRAM_ID);
        assert_ne!(a, b);
    }

    #[test]
    fn differs_per_mint() {
        let a = associated_token_address(&fixed_owner(), &usdc(), &SPL_TOKEN_PROGRAM_ID);
        let b = associated_token_address(&fixed_owner(), &usdt(), &SPL_TOKEN_PROGRAM_ID);
        assert_ne!(a, b);
    }

    #[test]
    fn differs_per_owner() {
        let other_owner = Pubkey::from_str("So11111111111111111111111111111111111111112").unwrap();
        let a = associated_token_address(&fixed_owner(), &usdc(), &SPL_TOKEN_PROGRAM_ID);
        let b = associated_token_address(&other_owner, &usdc(), &SPL_TOKEN_PROGRAM_ID);
        assert_ne!(a, b);
    }
}
