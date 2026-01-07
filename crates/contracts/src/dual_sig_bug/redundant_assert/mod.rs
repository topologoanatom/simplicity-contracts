use std::collections::HashMap;
use std::sync::Arc;

use simplicityhl::simplicity::bitcoin::secp256k1;
use simplicityhl::simplicity::elements::hashes::HashEngine as _;
use simplicityhl::simplicity::elements::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use simplicityhl::simplicity::elements::{Script, Transaction};
use simplicityhl::simplicity::hashes::{Hash, sha256};
use simplicityhl::simplicity::jet::Elements;
use simplicityhl::simplicity::jet::elements::ElementsEnv;
use simplicityhl::simplicity::{Cmr, RedeemNode, leaf_version};
use simplicityhl::str::WitnessName;
use simplicityhl::tracker::TrackerLogLevel;
use simplicityhl::value::ValueConstructible;
use simplicityhl::{Arguments, CompiledProgram, TemplateProgram, WitnessValues};
use simplicityhl_core::{ProgramError, run_program};

pub const SIMF_SOURCE: &str = include_str!("source_simf/bug.simf");
pub const SIMF_SOURCE_COMMENTED: &str = include_str!("source_simf/bug_commented.simf");

fn build_arguments(y: u64, z: u64) -> Arguments {
    Arguments::from(HashMap::from([
        (
            WitnessName::from_str_unchecked("Y"),
            simplicityhl::Value::u64(y),
        ),
        (
            WitnessName::from_str_unchecked("Z"),
            simplicityhl::Value::u64(z),
        ),
    ]))
}

pub fn build_witness(x: u64) -> WitnessValues {
    simplicityhl::WitnessValues::from(HashMap::from([(
        WitnessName::from_str_unchecked("X"),
        simplicityhl::Value::u64(x),
    )]))
}

fn get_template_program(commented: bool) -> TemplateProgram {
    if commented {
        TemplateProgram::new(SIMF_SOURCE_COMMENTED)
            .expect("INTERNAL: expected to compile successfully.")
    } else {
        TemplateProgram::new(SIMF_SOURCE).expect("INTERNAL: expected to compile successfully.")
    }
}

fn get_compiled_program(y: u64, z: u64, commented: bool) -> CompiledProgram {
    let program = get_template_program(commented);

    program.instantiate(build_arguments(y, z), true).unwrap()
}

/// Execute storage program with new state.
///
/// # Errors
/// Returns error if program execution fails.
pub fn execute_program(
    x: u64,
    compiled_program: &CompiledProgram,
    env: &ElementsEnv<Arc<Transaction>>,
) -> Result<Arc<RedeemNode<Elements>>, ProgramError> {
    let witness_values = build_witness(x);
    Ok(run_program(
        compiled_program,
        witness_values,
        env,
        TrackerLogLevel::Debug,
    )?
    .0)
}

/// The unspendable internal key specified in BIP-0341.
///
/// # Panics
///
/// This function **panics** if the hard-coded 32-byte slice is not a valid
/// x-only public key. The panic originates from
/// `secp256k1::XOnlyPublicKey::from_slice(...).expect(...)`.
/// The unspendable internal key specified in BIP-0341.
#[rustfmt::skip] // mangles byte vectors
#[must_use]
pub fn unspendable_internal_key() -> secp256k1::XOnlyPublicKey {
	secp256k1::XOnlyPublicKey::from_slice(&[
		0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
		0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0, 
	])
	.expect("key should be valid")
}

fn unlimited_storage_script_ver(cmr: Cmr) -> (Script, LeafVersion) {
    (Script::from(cmr.as_ref().to_vec()), leaf_version())
}

/// Given a Simplicity CMR and an internal key, computes the [`TaprootSpendInfo`]
/// for a Taptree with this CMR as its single leaf.
///
/// # Panics
///
/// This function **panics** if building the taproot tree fails (the calls to
/// `TaprootBuilder::add_leaf_with_ver` or `.add_hidden` return `Err`) or if
/// finalizing the builder fails. Those panics come from the `.expect(...)`
/// calls on the builder methods.
#[must_use]
pub fn taproot_spend_info(
    internal_key: secp256k1::XOnlyPublicKey,
    x: u64,
    cmr: Cmr,
) -> TaprootSpendInfo {
    let (script, version) = unlimited_storage_script_ver(cmr);

    // Compute TapData-tagged hash of the state
    let tag = sha256::Hash::hash(b"TapData");
    let mut eng = sha256::Hash::engine();
    eng.input(tag.as_byte_array());
    eng.input(tag.as_byte_array());
    eng.input(&x.to_le_bytes());
    let storage_hash = sha256::Hash::from_engine(eng);

    // Build taproot tree with hidden leaf
    let builder = TaprootBuilder::new()
        .add_leaf_with_ver(1, script, version)
        .expect("tap tree should be valid")
        .add_hidden(1, storage_hash)
        .expect("tap tree should be valid");

    builder
        .finalize(secp256k1::SECP256K1, internal_key)
        .expect("tap tree should be valid")
}

#[cfg(test)]
mod array_tr_storage_tests {
    use super::*;
    use anyhow::Result;
    use std::sync::Arc;

    use simplicityhl::elements::confidential::{Asset, Value};
    use simplicityhl::elements::pset::{Input, Output, PartiallySignedTransaction};
    use simplicityhl::elements::{AssetId, BlockHash, OutPoint, Script, Txid};
    use simplicityhl::simplicity::elements::taproot::ControlBlock;
    use simplicityhl::simplicity::jet::elements::{ElementsEnv, ElementsUtxo};

    fn test_bug_aux(comment_assert: bool) -> Result<()> {
        let x = 4;
        let y = 5;
        let z = 6;

        let program = get_compiled_program(y, z, comment_assert);
        let cmr = program.commit().cmr();

        let spend_info = taproot_spend_info(unspendable_internal_key(), x, cmr);
        let script_pubkey = Script::new_v1_p2tr_tweaked(spend_info.output_key());

        let mut pst = PartiallySignedTransaction::new_v2();
        let outpoint = OutPoint::new(Txid::from_slice(&[0; 32])?, 0);
        pst.add_input(Input::from_prevout(outpoint));
        pst.add_output(Output::new_explicit(
            script_pubkey.clone(),
            0,
            AssetId::default(),
            None,
        ));

        let control_block = spend_info
            .control_block(&unlimited_storage_script_ver(cmr))
            .expect("must get control block");

        let env = ElementsEnv::new(
            Arc::new(pst.extract_tx()?),
            vec![ElementsUtxo {
                script_pubkey,
                asset: Asset::default(),
                value: Value::default(),
            }],
            0,
            cmr,
            ControlBlock::from_slice(&control_block.serialize())?,
            None,
            BlockHash::all_zeros(),
        );

        let result = execute_program(x, &program, &env);
        match result {
            Err(ProgramError::Execution(e)) => {
                let error_str = format!("{:?}", e);
                if error_str.contains("ReachedPrunedBranch") {
                    panic!("BUG REPRODUCED: Dual checksig causes ReachedPrunedBranch!");
                } else {
                    println!("Execution error: {}", error_str);
                }
            }
            Ok(_) => {
                println!("Test passed - no bug with this structure");
            }
            Err(e) => {
                println!("Other error: {:?}", e);
            }
        }
        Ok(())
    }

    // Does not reproduce the bug !
    #[test]
    fn test_redundant_assert_bug() -> Result<()> {
        test_bug_aux(false)
    }

    #[test]
    fn test_redundant_assert_pass() -> Result<()> {
        test_bug_aux(true)
    }
}
