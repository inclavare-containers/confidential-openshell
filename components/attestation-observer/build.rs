#![allow(unsafe_code)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/plugin.proto");
    // SAFETY: code generation is started only after this single-threaded setup.
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_prost_build::configure().compile_protos(&["proto/plugin.proto"], &["proto"])?;
    Ok(())
}
