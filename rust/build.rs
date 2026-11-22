fn main() {
    // scripts/build_native.py fija el sello de las fuentes en esta variable; si cambia, se recompila.
    println!("cargo:rerun-if-env-changed=MALTEGO_CORE_SRC_HASH");
}
