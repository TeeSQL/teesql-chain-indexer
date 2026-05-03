//! `ClusterDiamondFactory` event bindings + decoder.
//!
//! Source of truth: `open-source/teesql-group-auth/src/interfaces/IClusterDiamondFactory.sol`.

use alloy::rpc::types::Log;
use alloy::sol;
use alloy::sol_types::SolEvent;
use anyhow::Context;
use serde_json::{json, Value};

use crate::encoding::{address_to_json, bytes32_to_json};
use teesql_chain_indexer_core::decode::Decoder;

sol! {
    #[sol(rpc)]
    contract IClusterDiamondFactory {
        event ClusterDeployed(
            address indexed diamond,
            address indexed deployer,
            bytes32 indexed salt
        );
    }
}

/// Decoder for `ClusterDeployed(address,address,bytes32)`.
///
/// Emitted by the canonical `ClusterDiamondFactory` every time a new
/// cluster diamond proxy is minted via `deployCluster`. Drives the
/// indexer's "watch every diamond this factory has ever produced"
/// behavior — every decoded event registers a new entry in
/// `watched_contracts` so subsequent ingest picks up the diamond's
/// own event surface.
pub struct ClusterDeployedDecoder;

impl Decoder for ClusterDeployedDecoder {
    fn topic0(&self) -> [u8; 32] {
        IClusterDiamondFactory::ClusterDeployed::SIGNATURE_HASH.0
    }

    fn kind(&self) -> &'static str {
        "ClusterDeployed"
    }

    fn decode(&self, log: &Log) -> anyhow::Result<Value> {
        let decoded = IClusterDiamondFactory::ClusterDeployed::decode_log(&log.inner)
            .context("decode ClusterDeployed log")?;
        Ok(json!({
            "diamond":    address_to_json(&decoded.diamond),
            "deployer":   address_to_json(&decoded.deployer),
            "salt":       bytes32_to_json(&decoded.salt),
            "_topic0":    bytes32_to_json(&IClusterDiamondFactory::ClusterDeployed::SIGNATURE_HASH),
            "_signature": IClusterDiamondFactory::ClusterDeployed::SIGNATURE,
        }))
    }
}
