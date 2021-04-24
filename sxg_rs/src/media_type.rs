struct MediaType {
    weight_milliles: u16,
    is_sxg_b3: bool,
}

impl<'a> MediaType {
    fn new(input: &'a str) -> Self {
        let input = input.trim();
        let tokens: Vec<_> = input.split(';').collect();
        let is_sxg = tokens[0].eq_ignore_ascii_case("application/signed-exchange");
        let mut weight_milliles = 1000;
        let mut version = None;
        for param in tokens.iter().skip(1) {
            let entry: Vec<_> = param.trim().split('=').collect();
            if entry.len() == 2 {
                let name = entry[0].trim();
                let value = entry[1].trim();
                if name == "q" {
                    if let Ok(value) = value.parse::<f64>() {
                        weight_milliles = (value * 1000.0) as u16;
                    }
                } else if name == "v" {
                    version = Some(value);
                }
            }
        }
        MediaType {
            is_sxg_b3: is_sxg && version == Some("b3"),
            weight_milliles,
        }
    }
}

pub fn request_accepts_sxg(accept: &str) -> bool {
    let media_types = accept.split(',');
    let media_types: Vec<_> = media_types.map(|s| MediaType::new(s)).collect();
    let max_sxg_weight = media_types.iter().map(|t| t.weight_milliles * t.is_sxg_b3 as u16).max();
    let max_weight = media_types.iter().map(|t| t.weight_milliles).max();
    max_sxg_weight == max_weight
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        assert!(request_accepts_sxg("application/signed-exchange;v=b3"));
        assert!(request_accepts_sxg("application/signed-exchange;v=b3;q=0.9,*/*;q=0.8"));
        assert_eq!(request_accepts_sxg("text/html,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"), false);
    }
}

