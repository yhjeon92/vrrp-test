pub fn vec_to_addr_arr(src: Vec<u8>) -> Result<[u8; 4], String> {
    if src.len() != 4 {
        return Err(format!("Mismatched vector size {}", src.len()));
    }

    let mut addr = [0u8; 4];

    addr[0] = *src.get(0).ok_or(format!(""))?;
    addr[1] = *src.get(1).ok_or(format!(""))?;
    addr[2] = *src.get(2).ok_or(format!(""))?;
    addr[3] = *src.get(3).ok_or(format!(""))?;

    Ok(addr)
}

pub fn pad_len(len: usize, align_to: usize) -> usize {
    (len + align_to - 1) & !(align_to - 1)
}
