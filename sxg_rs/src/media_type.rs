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

pub fn validate_sxg_request_header(accept: &str) -> Result<(), String> {
    const SXG: &'static str = "application/signed-exchange;v=b3";
    let media_types = accept.split(',');
    let media_types: Vec<_> = media_types.map(|s| MediaType::new(s)).collect();
    let q_sxg = media_types.iter().map(|t| t.weight_milliles * t.is_sxg_b3 as u16).max().unwrap();
    let q_max = media_types.iter().map(|t| t.weight_milliles).max().unwrap();
    if q_sxg == 0 {
        Err(format!("The request accept header does not contain {}.", SXG))
    } else if q_sxg < q_max {
        Err(format!("The q value of {} is not the max in request accept header", SXG))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        assert!(validate_sxg_request_header("application/signed-exchange;v=b3").is_ok());
        assert!(validate_sxg_request_header("application/signed-exchange;v=b3;q=0.9,*/*;q=0.8").is_ok());
        assert!(validate_sxg_request_header("").is_err());
        assert!(validate_sxg_request_header("text/html,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9").is_err());
    }
}

