//! Compile `proto/chain_indexer.proto` into Rust bindings under
//! `OUT_DIR/teesql.chain_indexer.v1.rs`. Included from `grpc.rs` via
//! `tonic::include_proto!("teesql.chain_indexer.v1")`.
//!
//! `protoc` is sourced from the `protoc-bin-vendored` crate so the
//! build is hermetic — operators don't need a system protobuf-
//! compiler installed.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../../proto/chain_indexer.proto";
    println!("cargo:rerun-if-changed={proto}");

    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&[proto], &["../../proto"])?;
    Ok(())
}
