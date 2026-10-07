//! Image release channel. Registry eligibility and verified image authority are
//! separate: a Beta row alone never proves that an installed image was signed.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReleaseChannel {
    Stable,
    Beta,
    Unsupported,
}

impl ReleaseChannel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Unsupported => "unsupported",
        }
    }

    pub const fn is_publishable(self) -> bool {
        matches!(self, Self::Stable | Self::Beta)
    }
}

impl std::str::FromStr for ReleaseChannel {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "stable" => Ok(Self::Stable),
            "beta" => Ok(Self::Beta),
            "unsupported" => Ok(Self::Unsupported),
            _ => Err("unknown release channel"),
        }
    }
}

impl std::fmt::Display for ReleaseChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_tokens_are_exact_and_unsupported_is_not_publishable() {
        for channel in [ReleaseChannel::Stable, ReleaseChannel::Beta, ReleaseChannel::Unsupported] {
            assert_eq!(channel.as_str().parse(), Ok(channel));
        }
        for unknown in ["", "Beta", " beta", "beta\n", "lab", "experimental", "production"] {
            assert!(unknown.parse::<ReleaseChannel>().is_err());
        }
        assert!(ReleaseChannel::Stable.is_publishable());
        assert!(ReleaseChannel::Beta.is_publishable());
        assert!(!ReleaseChannel::Unsupported.is_publishable());
    }
}
