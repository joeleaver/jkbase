//! CLI ⇄ control-API version contract. The `jkbase` CLI and the server are built from ONE
//! workspace version (`[workspace.package] version`), so the server can advertise, at the
//! unauthenticated `GET /cli`, the CLI release that matches it — and the floor below which the
//! CLI is known not to speak its API. The CLI checks this (cached, at most daily) and nudges the
//! user toward `jkbase upgrade`. Self-hosters get the version of the tree THEY deployed, never
//! ours.

/// The CLI release this tree ships — the server advertises it as `latest`.
pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Oldest CLI that still works against this API. **Bump only on an incompatible API change**
/// (a removed/renamed route or field an older CLI sends or reads); a CLI below it warns on
/// every run instead of once a day.
pub const MIN_CLI_VERSION: &str = "0.1.0";

/// The body of `GET /cli`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CliVersionInfo {
    pub latest: String,
    pub minimum: String,
}

impl CliVersionInfo {
    pub fn current() -> Self {
        Self {
            latest: CLI_VERSION.to_string(),
            minimum: MIN_CLI_VERSION.to_string(),
        }
    }
}

/// `major.minor.patch`, numeric only. Pre-release / build suffixes are refused rather than
/// guessed at: a malformed advertised version must never make the CLI think it is stale.
pub fn parse(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().trim_start_matches('v').split('.');
    let p = |s: Option<&str>| s.filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))?.parse().ok();
    let out = (p(it.next())?, p(it.next())?, p(it.next())?);
    it.next().is_none().then_some(out)
}

/// `a < b`, false when either side doesn't parse.
pub fn older(a: &str, b: &str) -> bool {
    matches!((parse(a), parse(b)), (Some(a), Some(b)) if a < b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_orders() {
        assert_eq!(parse("0.2.0"), Some((0, 2, 0)));
        assert_eq!(parse("v1.10.3"), Some((1, 10, 3)));
        assert!(older("0.2.9", "0.10.0"));
        assert!(!older("0.2.0", "0.2.0"));
        assert!(!older("1.0.0", "0.9.9"));
    }

    #[test]
    fn malformed_never_reads_as_newer() {
        for bad in ["", "1", "1.2", "1.2.3.4", "1.2.x", "1.2.3-rc1", "99999999999999999999.0.0", "1..2"] {
            assert_eq!(parse(bad), None, "{bad:?}");
            assert!(!older("0.0.1", bad), "{bad:?}");
        }
    }

    #[test]
    fn current_is_well_formed() {
        assert!(parse(CLI_VERSION).is_some());
        assert!(!older(CLI_VERSION, MIN_CLI_VERSION), "MIN_CLI_VERSION above the shipped CLI");
    }
}
