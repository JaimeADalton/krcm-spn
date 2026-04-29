#![allow(clippy::useless_conversion)]

use krcm_core::block::{
    decrypt_blocks as core_decrypt_blocks, encrypt_blocks as core_encrypt_blocks,
};
use krcm_core::kdf::EncKey;
use krcm_core::{
    decrypt_auto, encrypt_v4, encrypt_v5, EncryptV4Options, EncryptV5Options, KdfParams, KrcmError,
    PaddingPolicy,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn py_error(error: KrcmError) -> PyErr {
    PyValueError::new_err(error.to_string())
}

fn enc_key_from_slice(enc_key: &[u8]) -> PyResult<EncKey> {
    let key: [u8; 32] = enc_key
        .try_into()
        .map_err(|_| PyValueError::new_err("enc_key must be 32 bytes"))?;
    Ok(EncKey::from_bytes(key))
}

#[pyfunction]
fn encrypt_blocks<'py>(
    py: Python<'py>,
    padded: &[u8],
    enc_key: &[u8],
    nonce: &[u8],
    version: u8,
) -> PyResult<Bound<'py, PyBytes>> {
    if version != 4 {
        return Err(PyValueError::new_err(
            "native block accelerator supports v4 only",
        ));
    }
    if nonce.len() != 16 {
        return Err(PyValueError::new_err("nonce must be 16 bytes"));
    }
    let key = enc_key_from_slice(enc_key)?;
    let out = core_encrypt_blocks(padded, &key, nonce).map_err(py_error)?;
    Ok(PyBytes::new_bound(py, &out))
}

#[pyfunction]
fn decrypt_blocks<'py>(
    py: Python<'py>,
    ciphertext: &[u8],
    enc_key: &[u8],
    nonce: &[u8],
    version: u8,
) -> PyResult<Bound<'py, PyBytes>> {
    if version != 4 {
        return Err(PyValueError::new_err(
            "native block accelerator supports v4 only",
        ));
    }
    if nonce.len() != 16 {
        return Err(PyValueError::new_err("nonce must be 16 bytes"));
    }
    let key = enc_key_from_slice(enc_key)?;
    let out = core_decrypt_blocks(ciphertext, &key, nonce).map_err(py_error)?;
    Ok(PyBytes::new_bound(py, &out))
}

#[pyfunction]
#[pyo3(signature = (data, password, version=5))]
fn encrypt_bytes<'py>(
    py: Python<'py>,
    data: &[u8],
    password: &[u8],
    version: u8,
) -> PyResult<Bound<'py, PyBytes>> {
    let out = match version {
        4 => encrypt_v4(data, password, EncryptV4Options::default()).map_err(py_error),
        5 => encrypt_v5(
            data,
            password,
            EncryptV5Options {
                kdf: KdfParams::Pbkdf2 {
                    iterations: 200_000,
                },
                padding_policy: PaddingPolicy::MinimalBlock,
                segment_size: 4 * 1024 * 1024,
                workers: 1,
                salt: None,
                public_nonce: None,
            },
        )
        .map_err(py_error),
        _ => Err(PyValueError::new_err("unsupported KRCM-SPN version")),
    }?;
    Ok(PyBytes::new_bound(py, &out))
}

#[pyfunction]
fn decrypt_bytes<'py>(
    py: Python<'py>,
    container: &[u8],
    password: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let out = decrypt_auto(container, password).map_err(py_error)?;
    Ok(PyBytes::new_bound(py, &out))
}

#[pymodule]
fn _krcm_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt_blocks, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_blocks, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_bytes, m)?)?;
    Ok(())
}
