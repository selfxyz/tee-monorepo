use anyhow::{anyhow, Context, Result};
use clap::Args;
use serde_json;

#[derive(Args, Debug)]
#[group(multiple = true)]
pub struct PcrArgs {
    /// Path to PCR JSON file
    #[arg(short = 'j', long, conflicts_with_all = ["pcr0", "pcr1", "pcr2"])]
    pub pcr_json: Option<String>,

    /// PCR 0 value
    #[arg(short = '0', long, conflicts_with = "pcr_json")]
    pub pcr0: Option<String>,

    /// PCR 1 value
    #[arg(short = '1', long, conflicts_with = "pcr_json")]
    pub pcr1: Option<String>,

    /// PCR 2 value
    #[arg(short = '2', long, conflicts_with = "pcr_json")]
    pub pcr2: Option<String>,
}

impl PcrArgs {
    pub fn load(&self) -> Result<Option<(String, String, String)>> {
        match &self.pcr_json {
            Some(path) => {
                let file = std::fs::File::open(path)?;
                let json: serde_json::Value =
                    serde_json::from_reader(file).context("Failed to parse PCR JSON file")?;
                let json_obj = json
                    .as_object()
                    .context("PCR data should be a JSON object")?;
                let lower_keys_map: std::collections::HashMap<_, _> = json_obj
                    .iter()
                    .map(|(k, v)| (k.to_lowercase(), v))
                    .collect();

                Ok(Some((
                    lower_keys_map
                        .get("pcr0")
                        .and_then(|v| v.as_str())
                        .ok_or(anyhow!("Missing PCR0"))?
                        .into(),
                    lower_keys_map
                        .get("pcr1")
                        .and_then(|v| v.as_str())
                        .ok_or(anyhow!("Missing PCR1"))?
                        .into(),
                    lower_keys_map
                        .get("pcr2")
                        .and_then(|v| v.as_str())
                        .ok_or(anyhow!("Missing PCR2"))?
                        .into(),
                )))
            }
            None => {
                // If any PCR is provided, all must be provided
                let has_any = self.pcr0.is_some() || self.pcr1.is_some() || self.pcr2.is_some();
                let has_all = self.pcr0.is_some() && self.pcr1.is_some() && self.pcr2.is_some();
                if has_any && !has_all {
                    return Err(anyhow!("If any 1 PCR value is provided, all PCRs (pcr0, pcr1, pcr2) must be provided"));
                }

                if !has_any {
                    return Ok(None);
                }

                let pcr0 = self.pcr0.as_ref().unwrap().clone();
                let pcr1 = self.pcr1.as_ref().unwrap().clone();
                let pcr2 = self.pcr2.as_ref().unwrap().clone();

                if pcr0.is_empty() && pcr1.is_empty() && pcr2.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some((pcr0, pcr1, pcr2)))
                }
            }
        }
    }
}
