
pub fn parse_memory(memory_hex: Vec<String>) -> Vec<u8> {
    memory_hex
        .join("")
        .chars()
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|chunk| {
            let hex_str: String = chunk.iter().collect();
            u8::from_str_radix(&hex_str, 16).unwrap_or(0)
        })
        .collect()
}

pub fn extract_bytes(memory: &[u8], offset: usize, size: usize) -> Vec<u8> {
    let start = offset.min(memory.len());
    let end = (offset + size).min(memory.len());
    
    if start >= end {
        return vec![];
    }
    
    memory[start..end].to_vec()
}

pub fn parse_trace_memory(memory: &Option<Vec<String>>) -> Option<Vec<u8>> {
    memory.as_ref().map(|m| parse_memory(m.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_memory() {
        let memory_hex = vec!["00".to_string(), "01".to_string(), "02".to_string(), "ff".to_string()];
        let result = parse_memory(memory_hex);
        assert_eq!(result, vec![0, 1, 2, 255]);
    }

    #[test]
    fn test_extract_bytes() {
        let memory = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        
        let result = extract_bytes(&memory, 2, 3);
        assert_eq!(result, vec![2, 3, 4]);
        
        let result = extract_bytes(&memory, 8, 5);
        assert_eq!(result, vec![8, 9]);
        
        let result = extract_bytes(&memory, 15, 5);
        assert_eq!(result, vec![] as Vec<u8>);
    }
}