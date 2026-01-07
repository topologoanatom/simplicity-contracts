//! Bug reproduction for Simplicity dual bip_0340_verify issue.
//!
//! This module reproduces the exact structure that causes
//! `ReachedPrunedBranch` error when calling `bip_0340_verify` twice.

use std::collections::HashMap;
use std::sync::Arc;

use simplicityhl::num::U256;
use simplicityhl::parse::ParseFromStr;
use simplicityhl::str::WitnessName;
use simplicityhl::types::TypeConstructible;
use simplicityhl::value::ValueConstructible;
use simplicityhl::{Arguments, CompiledProgram, ResolvedType, TemplateProgram, WitnessValues};

use simplicityhl::simplicity::elements::Transaction;
use simplicityhl::simplicity::jet::elements::ElementsEnv;

use simplicityhl::tracker::TrackerLogLevel;
use simplicityhl_core::{ProgramError, run_program};

pub const SIG_VERIFICATION_SOURCE: &str = include_str!("source_simf/sig_verification.simf");
pub const SIG_VERIFICATION_SOURCE_COMMENTED: &str =
    include_str!("source_simf/sig_verification_commented.simf");

/// Arguments for the sig verification contract
#[derive(Debug, Clone)]
pub struct SigVerificationArguments {
    pub oracle_pk: [u8; 32],
    pub user_pk: [u8; 32],
}

impl SigVerificationArguments {
    pub fn build_arguments(&self) -> Arguments {
        Arguments::from(HashMap::from([
            (
                WitnessName::from_str_unchecked("ORACLE_PK"),
                simplicityhl::Value::u256(U256::from_byte_array(self.oracle_pk)),
            ),
            (
                WitnessName::from_str_unchecked("USER_PK"),
                simplicityhl::Value::u256(U256::from_byte_array(self.user_pk)),
            ),
        ]))
    }
}

/// Get the template program.
#[must_use]
pub fn get_sig_verification_template_program(comment_asserts: bool) -> TemplateProgram {
    if comment_asserts {
        TemplateProgram::new(SIG_VERIFICATION_SOURCE_COMMENTED)
            .expect("INTERNAL: expected to compile successfully.")
    } else {
        TemplateProgram::new(SIG_VERIFICATION_SOURCE)
            .expect("INTERNAL: expected to compile successfully.")
    }
}

/// Get compiled program.
#[must_use]
pub fn get_compiled_sig_verification_program(
    args: &SigVerificationArguments,
    comment_asserts: bool,
) -> CompiledProgram {
    let program = get_sig_verification_template_program(comment_asserts);

    program.instantiate(args.build_arguments(), true).unwrap()
}

/// Branch for witness
pub enum SigVerificationBranch {
    /// Left(Left) - Negative settlement (7 params)
    SettlementNegative {
        current_price: u64,
        new_price: u64,
        timestamp: u32,
        amount: u64,
        oracle_sig: [u8; 64],
        secondary_sig: [u8; 64],
        is_change_needed: bool,
    },
    /// Left(Right) - Positive settlement (6 params) - THE BUG CASE
    SettlementPositive {
        current_price: u64,
        new_price: u64,
        timestamp: u32,
        amount: u64,
        oracle_sig: [u8; 64],
        secondary_sig: [u8; 64],
    },
    /// Right(Left) - Cooperative close (3 params)
    CooperativeClose {
        current_price: u64,
        user_sig: [u8; 64],
        oracle_sig: [u8; 64],
    },
    /// Right(Right) - Expiry (2 params)
    Expiry {
        current_price: u64,
        user_sig: [u8; 64],
    },
}

/// Build witness values
pub fn build_sig_verification_witness(branch: SigVerificationBranch) -> WitnessValues {
    let negative_type =
        ResolvedType::parse_from_str("(u64, u64, u32, u64, Signature, Signature, bool)").unwrap();
    let positive_type =
        ResolvedType::parse_from_str("(u64, u64, u32, u64, Signature, Signature)").unwrap();
    let close_type = ResolvedType::parse_from_str("(u64, Signature, Signature)").unwrap();
    let expiry_type = ResolvedType::parse_from_str("(u64, Signature)").unwrap();

    let settlement_either = ResolvedType::either(negative_type, positive_type);
    let close_either = ResolvedType::either(close_type, expiry_type);
    let path_type = ResolvedType::either(settlement_either, close_either);

    let branch_str = match branch {
        SigVerificationBranch::SettlementNegative {
            current_price,
            new_price,
            timestamp,
            amount,
            oracle_sig,
            secondary_sig,
            is_change_needed,
        } => {
            format!(
                "Left(Left(({}, {}, {}, {}, 0x{}, 0x{}, {})))",
                current_price,
                new_price,
                timestamp,
                amount,
                hex::encode(oracle_sig),
                hex::encode(secondary_sig),
                is_change_needed
            )
        }
        SigVerificationBranch::SettlementPositive {
            current_price,
            new_price,
            timestamp,
            amount,
            oracle_sig,
            secondary_sig,
        } => {
            format!(
                "Left(Right(({}, {}, {}, {}, 0x{}, 0x{})))",
                current_price,
                new_price,
                timestamp,
                amount,
                hex::encode(oracle_sig),
                hex::encode(secondary_sig)
            )
        }
        SigVerificationBranch::CooperativeClose {
            current_price,
            user_sig,
            oracle_sig,
        } => {
            format!(
                "Right(Left(({}, 0x{}, 0x{})))",
                current_price,
                hex::encode(user_sig),
                hex::encode(oracle_sig)
            )
        }
        SigVerificationBranch::Expiry {
            current_price,
            user_sig,
        } => {
            format!(
                "Right(Right(({}, 0x{})))",
                current_price,
                hex::encode(user_sig)
            )
        }
    };

    WitnessValues::from(HashMap::from([(
        WitnessName::from_str_unchecked("PATH"),
        simplicityhl::Value::parse_from_str(&branch_str, &path_type).unwrap(),
    )]))
}

/// Execute the program.
pub fn execute_sig_verification(
    program: &CompiledProgram,
    env: &ElementsEnv<Arc<Transaction>>,
    branch: SigVerificationBranch,
    log_level: TrackerLogLevel,
) -> Result<(), ProgramError> {
    let witness = build_sig_verification_witness(branch);
    run_program(program, witness, env, log_level)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::dual_sig_bug::comp_dot::convert_to_dot;

    use super::*;
    use anyhow::{Error, Result};
    use std::path::PathBuf;
    use std::sync::Arc;

    use simplicityhl::elements::confidential::{Asset, Value};
    use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
    use simplicityhl::elements::{self, AssetId, OutPoint, Script, Txid};
    use simplicityhl::simplicity::bitcoin::key::Keypair;
    use simplicityhl::simplicity::bitcoin::secp256k1::{self, Secp256k1};
    use simplicityhl::simplicity::elements::taproot::ControlBlock;
    use simplicityhl::simplicity::elements::taproot::{LeafVersion, TaprootBuilder};
    use simplicityhl::simplicity::hashes::{Hash, HashEngine, sha256};
    use simplicityhl::simplicity::jet::elements::ElementsUtxo;
    use simplicityhl::simplicity::{Cmr, leaf_version};

    fn unspendable_internal_key() -> secp256k1::XOnlyPublicKey {
        secp256k1::XOnlyPublicKey::from_slice(&[
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
            0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
            0xce, 0x80, 0x3a, 0xc0,
        ])
        .expect("key should be valid")
    }

    fn script_ver(cmr: Cmr) -> (Script, LeafVersion) {
        (Script::from(cmr.as_ref().to_vec()), leaf_version())
    }

    /// Sign price attestation: SHA256(timestamp || price)
    fn sign_price_attestation(keypair: &Keypair, timestamp: u32, price: u64) -> [u8; 64] {
        let mut eng = sha256::Hash::engine();
        eng.input(&timestamp.to_be_bytes());
        eng.input(&price.to_be_bytes());
        let msg_hash = sha256::Hash::from_engine(eng);
        let msg = secp256k1::Message::from_digest(msg_hash.to_byte_array());
        keypair.sign_schnorr(msg).serialize()
    }

    /// Test settlement_positive_path
    fn settlement_positive_dual_sig_main(comment_asserts: bool, graph_str: &mut String) -> Result<()> {
        let secp = Secp256k1::new();

        let oracle_keypair =
            Keypair::from_secret_key(&secp, &secp256k1::SecretKey::from_slice(&[1u8; 32])?);
        let user_keypair =
            Keypair::from_secret_key(&secp, &secp256k1::SecretKey::from_slice(&[1u8; 32])?);

        let args = SigVerificationArguments {
            oracle_pk: oracle_keypair.x_only_public_key().0.serialize(),
            user_pk: user_keypair.x_only_public_key().0.serialize(),
        };

        let program = get_compiled_sig_verification_program(&args, comment_asserts);

        let comp_str = format!("{:#?}", program);
        let opening_str = "CompiledProgram {
    simplicity:";
        let closing_str = "witness_types: WitnessTypes(";

        *graph_str = convert_to_dot({
            let start = comp_str.rfind(opening_str).unwrap() + opening_str.len();
            let end = comp_str.rfind(closing_str).unwrap();

            &comp_str[start..end]
        });       

        let cmr = program.commit().cmr();

        // Simple taproot (no TapData for this minimal test)
        let spend_info = TaprootBuilder::new()
            .add_leaf_with_ver(0, Script::from(cmr.as_ref().to_vec()), leaf_version())
            .expect("valid")
            .finalize(secp256k1::SECP256K1, unspendable_internal_key())
            .expect("valid");
        let script_pubkey = Script::new_v1_p2tr_tweaked(spend_info.output_key());

        let mut pst = PartiallySignedTransaction::new_v2();
        pst.add_input(Input::from_prevout(OutPoint::new(
            Txid::from_slice(&[0; 32])?,
            0,
        )));
        pst.add_output(Output::new_explicit(
            Script::new(),
            0,
            AssetId::default(),
            None,
        ));
        let tx = pst.extract_tx()?;

        let control_block = spend_info.control_block(&script_ver(cmr)).expect("cb");

        let env = simplicityhl::simplicity::jet::elements::ElementsEnv::new(
            Arc::new(tx),
            vec![ElementsUtxo {
                script_pubkey,
                asset: Asset::default(),
                value: Value::default(),
            }],
            0,
            cmr,
            ControlBlock::from_slice(&control_block.serialize())?,
            None,
            elements::BlockHash::all_zeros(),
        );

        let current_price = 100_000u64;
        let new_price = 105_000u64;
        let timestamp = 1735689600u32;
        let amount = 500u64;

        let oracle_sig = sign_price_attestation(&oracle_keypair, timestamp, new_price);
        let secondary_sig = sign_price_attestation(&user_keypair, timestamp, new_price);

        let branch = SigVerificationBranch::SettlementPositive {
            current_price,
            new_price,
            timestamp,
            amount,
            oracle_sig,
            secondary_sig,
        };

        let program_exec = execute_sig_verification(&program, &env, branch, TrackerLogLevel::Trace);

        match program_exec {
            Err(ProgramError::Execution(e)) => {
                let error_str = format!("{:?}", e);
                if error_str.contains("ReachedPrunedBranch") {
                    return Err(Error::msg("BUG REPRODUCED: Dual checksig causes ReachedPrunedBranch!"));
                } else {
                    return Err(Error::msg(error_str));
                }
            }
            Ok(_) => {
            }
            Err(e) => {
                    return Err(Error::msg(format!("Other error: {:?}", e)));
            }
        }

        Ok(())
    }

    const GRAPH_PATH: &str = "src/dual_sig_bug/assets";

    #[test]
    fn test_settlement_positive_dual_sig_bug() -> Result<()> {
        let mut graph_str = String::new();
        let res = settlement_positive_dual_sig_main(false, &mut graph_str);

        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(GRAPH_PATH);
        std::fs::write(&format!("{}/graph_bug.dot", GRAPH_PATH), graph_str)
            .expect("Failed to save file");

        assert!(res.is_ok(), "{}", res.err().unwrap());

        Ok(())
    }

    #[test]
    fn test_settlement_positive_dual_sig_pass() -> Result<()> {
        let mut graph_str = String::new();
        let res = settlement_positive_dual_sig_main(true, &mut graph_str);

        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(GRAPH_PATH);
        std::fs::write(&format!("{}/graph_pass.dot", GRAPH_PATH), graph_str)
            .expect("Failed to save file");

        assert!(res.is_ok());

        Ok(())
    }
}
