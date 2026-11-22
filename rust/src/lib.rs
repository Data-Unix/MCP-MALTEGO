use pyo3::prelude::*;

mod layout;

/// Sello de las fuentes Rust con el que se compiló este binario (lo fija scripts/build_native.py).
/// La capa Python lo compara con las fuentes de `rust/` y descarta el binario si está obsoleto.
const SRC_HASH: &str = match option_env!("MALTEGO_CORE_SRC_HASH") {
    Some(h) => h,
    None => "",
};

#[pymodule]
fn _accel_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__src_hash__", SRC_HASH)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(layout::force_layout, m)?)?;
    Ok(())
}
