//! Visitor-page appearance. Preset palettes live in `ui.css`. This module
//! only names them and checks an optional accent override.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    Ink,
    Harbor,
    Grove,
    Ember,
}

impl Preset {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ink => "ink",
            Self::Harbor => "harbor",
            Self::Grove => "grove",
            Self::Ember => "ember",
        }
    }

    fn class(self) -> &'static str {
        match self {
            Self::Ink => "preset-ink",
            Self::Harbor => "preset-harbor",
            Self::Grove => "preset-grove",
            Self::Ember => "preset-ember",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorMode {
    Light,
    Dark,
    Auto,
}

impl ColorMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
            Self::Auto => "auto",
        }
    }

    fn class(self) -> &'static str {
        match self {
            Self::Light => "mode-light",
            Self::Dark => "mode-dark",
            Self::Auto => "mode-auto",
        }
    }

    pub fn color_scheme(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
            Self::Auto => "light dark",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    pub fn css(self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.r, self.g, self.b)
    }

    /// Ink that stays readable on this fill. Prefers the higher WCAG contrast.
    pub fn on_fill(self) -> &'static str {
        let white = contrast(self, Rgb { r: 255, g: 255, b: 255 });
        let black = contrast(self, Rgb { r: 20, g: 20, b: 20 });
        if white >= black { "#ffffff" } else { "#141414" }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Appearance {
    pub preset: Preset,
    pub mode: ColorMode,
    pub accent: Option<Rgb>,
}

impl Default for Appearance {
    fn default() -> Self {
        Self { preset: Preset::Ink, mode: ColorMode::Auto, accent: None }
    }
}

impl Appearance {
    pub fn classes(self) -> String {
        format!("{} {}", self.preset.class(), self.mode.class())
    }

    pub fn color_scheme(self) -> &'static str {
        self.mode.color_scheme()
    }

    /// Overrides `--accent` on `body`, which wins over the preset custom properties inherited from `html`.
    pub fn accent_css(self) -> String {
        let Some(accent) = self.accent else {
            return String::new();
        };
        format!("body{{--accent:{};--on-accent:{};}}", accent.css(), accent.on_fill())
    }
}

pub fn parse_preset(raw: &str) -> Result<Preset, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "ink" => Ok(Preset::Ink),
        "harbor" => Ok(Preset::Harbor),
        "grove" => Ok(Preset::Grove),
        "ember" => Ok(Preset::Ember),
        other => Err(format!("appearance.preset {other:?} must be ink, harbor, grove, or ember")),
    }
}

pub fn parse_mode(raw: &str) -> Result<ColorMode, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(ColorMode::Auto),
        "light" => Ok(ColorMode::Light),
        "dark" => Ok(ColorMode::Dark),
        other => Err(format!("appearance.mode {other:?} must be light, dark, or auto")),
    }
}

pub fn parse_accent(raw: &str) -> Result<Option<Rgb>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let Some(hex) = raw.strip_prefix('#') else {
        return Err("appearance.accent must be a hex color like #1f4b3a".into());
    };
    let hex = hex.to_ascii_lowercase();
    let full = match hex.len() {
        3 => {
            let b = hex.as_bytes();
            format!("{}{}{}{}{}{}", b[0] as char, b[0] as char, b[1] as char, b[1] as char, b[2] as char, b[2] as char)
        }
        6 => hex,
        _ => return Err("appearance.accent must be a hex color like #1f4b3a".into()),
    };
    if !full.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("appearance.accent must be a hex color like #1f4b3a".into());
    }
    let n = u32::from_str_radix(&full, 16).map_err(|_| "appearance.accent must be a hex color like #1f4b3a")?;
    Ok(Some(Rgb { r: (n >> 16) as u8, g: (n >> 8) as u8, b: n as u8 }))
}

fn channel(c: u8) -> f64 {
    let x = f64::from(c) / 255.0;
    if x <= 0.04045 { x / 12.92 } else { ((x + 0.055) / 1.055).powf(2.4) }
}

fn luminance(rgb: Rgb) -> f64 {
    0.2126 * channel(rgb.r) + 0.7152 * channel(rgb.g) + 0.0722 * channel(rgb.b)
}

fn contrast(a: Rgb, b: Rgb) -> f64 {
    let l1 = luminance(a);
    let l2 = luminance(b);
    let (hi, lo) = if l1 > l2 { (l1, l2) } else { (l2, l1) };
    (hi + 0.05) / (lo + 0.05)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accent_and_contrast() {
        assert_eq!(parse_accent("").unwrap(), None);
        assert_eq!(parse_accent("#abc").unwrap(), Some(Rgb { r: 0xaa, g: 0xbb, b: 0xcc }));
        assert_eq!(parse_accent("#0B6E4F").unwrap(), Some(Rgb { r: 0x0b, g: 0x6e, b: 0x4f }));
        assert!(parse_accent("green").is_err());
        assert!(parse_accent("#12").is_err());
        assert!(parse_accent("#gggggg").is_err());
        assert_eq!(Rgb { r: 0x11, g: 0x11, b: 0x11 }.on_fill(), "#ffffff");
        assert_eq!(Rgb { r: 0xee, g: 0xee, b: 0xee }.on_fill(), "#141414");
        let look = Appearance { preset: Preset::Harbor, mode: ColorMode::Dark, accent: Some(Rgb { r: 1, g: 2, b: 3 }) };
        assert_eq!(look.classes(), "preset-harbor mode-dark");
        assert!(look.accent_css().contains("#010203"));
        assert!(Appearance::default().accent_css().is_empty());
    }
}
