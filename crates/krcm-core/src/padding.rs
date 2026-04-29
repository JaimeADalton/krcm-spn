use crate::constants::BLOCK_BYTES;
use crate::error::KrcmError;

pub fn pad(data: &[u8]) -> Vec<u8> {
    let mut pad_len = BLOCK_BYTES - (data.len() % BLOCK_BYTES);
    if pad_len == 0 {
        pad_len = BLOCK_BYTES;
    }
    let mut out = Vec::with_capacity(data.len() + pad_len);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    out
}

pub fn unpad(data: &[u8]) -> Result<Vec<u8>, KrcmError> {
    if data.is_empty() || data.len() % BLOCK_BYTES != 0 {
        return Err(KrcmError::Format);
    }
    let pad_len = *data.last().ok_or(KrcmError::Format)? as usize;
    if !(1..=BLOCK_BYTES).contains(&pad_len) || data.len() < pad_len {
        return Err(KrcmError::Authentication);
    }
    if data[data.len() - pad_len..]
        .iter()
        .any(|&byte| byte as usize != pad_len)
    {
        return Err(KrcmError::Authentication);
    }
    Ok(data[..data.len() - pad_len].to_vec())
}
