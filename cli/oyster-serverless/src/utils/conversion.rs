use alloy::primitives::U256;

pub fn to_wei(eth: f64) -> U256 {
    let wei = (eth * 1e18).round() as u128;
    U256::from(wei)
}

pub fn to_usdc_units(usdc: f64) -> U256 {
    let base_units = (usdc * 1e6).round() as u128;
    U256::from(base_units)
}

pub fn to_eth(wei: U256) -> f64 {
    let wei_f64: f64 = wei.to_string().parse().unwrap();
    wei_f64 / 1e18
}

pub fn to_usdc(base_units: U256) -> f64 {
    let units_f64: f64 = base_units.to_string().parse().unwrap();
    units_f64 / 1e6
}
