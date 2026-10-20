pub fn version() -> &'static str {
    match option_env!("SITEGATE_VERSION") {
        Some(v) if !v.is_empty() => v,
        _ => env!("CARGO_PKG_VERSION"),
    }
}
