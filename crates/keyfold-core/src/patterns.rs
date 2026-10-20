//! Recognise API keys and other secrets in a piece of text (clipboard, file).
//! Provider patterns first, then a generic high-entropy rule. Matching happens
//! in memory only; nothing here stores anything.

use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Detection {
    /// Human label, e.g. "Stripe secret key".
    pub provider: String,
    /// ENV_VAR style name to prefill, e.g. STRIPE_SECRET_KEY.
    pub suggested_name: String,
    /// Optional dashboard link to prefill "where to rotate".
    pub url: String,
    /// True for provider-specific matches, false for the generic entropy rule.
    pub confident: bool,
}

struct Rule {
    provider: &'static str,
    name: &'static str,
    url: &'static str,
    re: Regex,
}

macro_rules! rule {
    ($provider:expr, $name:expr, $url:expr, $re:expr) => {
        Rule {
            provider: $provider,
            name: $name,
            url: $url,
            re: Regex::new($re).expect("static regex"),
        }
    };
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        rule!(
            "Stripe secret key",
            "STRIPE_SECRET_KEY",
            "https://dashboard.stripe.com/apikeys",
            r"^sk_(live|test)_[0-9A-Za-z]{16,}$"
        ),
        rule!(
            "Stripe restricted key",
            "STRIPE_RESTRICTED_KEY",
            "https://dashboard.stripe.com/apikeys",
            r"^rk_(live|test)_[0-9A-Za-z]{16,}$"
        ),
        rule!(
            "Stripe publishable key",
            "STRIPE_PUBLISHABLE_KEY",
            "https://dashboard.stripe.com/apikeys",
            r"^pk_(live|test)_[0-9A-Za-z]{16,}$"
        ),
        rule!(
            "Stripe webhook secret",
            "STRIPE_WEBHOOK_SECRET",
            "https://dashboard.stripe.com/webhooks",
            r"^whsec_[0-9A-Za-z]{20,}$"
        ),
        rule!(
            "Anthropic API key",
            "ANTHROPIC_API_KEY",
            "https://platform.claude.com/settings/keys",
            r"^sk-ant-[A-Za-z0-9_-]{20,}$"
        ),
        rule!(
            "OpenAI API key",
            "OPENAI_API_KEY",
            "https://platform.openai.com/api-keys",
            r"^sk-(proj-|svcacct-)?[A-Za-z0-9_-]{20,}$"
        ),
        rule!(
            "GitHub token",
            "GITHUB_TOKEN",
            "https://github.com/settings/tokens",
            r"^(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})$"
        ),
        rule!(
            "GitLab token",
            "GITLAB_TOKEN",
            "https://gitlab.com/-/user_settings/personal_access_tokens",
            r"^glpat-[A-Za-z0-9_-]{20,}$"
        ),
        rule!(
            "Slack token",
            "SLACK_TOKEN",
            "https://api.slack.com/apps",
            r"^xox[baprs]-[0-9A-Za-z-]{10,}$"
        ),
        rule!(
            "Google API key",
            "GOOGLE_API_KEY",
            "https://console.cloud.google.com/apis/credentials",
            r"^AIza[0-9A-Za-z_-]{35}$"
        ),
        rule!(
            "AWS access key id",
            "AWS_ACCESS_KEY_ID",
            "https://console.aws.amazon.com/iam/",
            r"^(AKIA|ASIA)[0-9A-Z]{16}$"
        ),
        rule!(
            "SendGrid API key",
            "SENDGRID_API_KEY",
            "https://app.sendgrid.com/settings/api_keys",
            r"^SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$"
        ),
        rule!(
            "Twilio API key",
            "TWILIO_API_KEY",
            "https://console.twilio.com/",
            r"^SK[0-9a-fA-F]{32}$"
        ),
        rule!(
            "Mailgun API key",
            "MAILGUN_API_KEY",
            "https://app.mailgun.com/",
            r"^key-[0-9A-Za-z]{32}$"
        ),
        rule!(
            "Hugging Face token",
            "HF_TOKEN",
            "https://huggingface.co/settings/tokens",
            r"^hf_[A-Za-z0-9]{30,}$"
        ),
        rule!(
            "npm token",
            "NPM_TOKEN",
            "https://www.npmjs.com/settings/~/tokens",
            r"^npm_[A-Za-z0-9]{36,}$"
        ),
        rule!(
            "PyPI token",
            "PYPI_TOKEN",
            "https://pypi.org/manage/account/token/",
            r"^pypi-AgEI[A-Za-z0-9_-]{50,}$"
        ),
        rule!(
            "Supabase access token",
            "SUPABASE_ACCESS_TOKEN",
            "https://supabase.com/dashboard/account/tokens",
            r"^sbp_[0-9a-f]{40}$"
        ),
        rule!(
            "DigitalOcean token",
            "DIGITALOCEAN_TOKEN",
            "https://cloud.digitalocean.com/account/api/tokens",
            r"^dop_v1_[0-9a-f]{64}$"
        ),
        rule!(
            "Shopify access token",
            "SHOPIFY_ACCESS_TOKEN",
            "https://admin.shopify.com/",
            r"^shp(at|ca|pa|ss)_[0-9a-fA-F]{32}$"
        ),
        rule!(
            "Telegram bot token",
            "TELEGRAM_BOT_TOKEN",
            "https://t.me/BotFather",
            r"^[0-9]{8,10}:[A-Za-z0-9_-]{35}$"
        ),
        rule!(
            "Resend API key",
            "RESEND_API_KEY",
            "https://resend.com/api-keys",
            r"^re_[A-Za-z0-9_-]{20,}$"
        ),
        rule!(
            "Vercel token",
            "VERCEL_TOKEN",
            "https://vercel.com/account/tokens",
            r"^vercel_[A-Za-z0-9]{20,}$"
        ),
        rule!(
            "Database URL with password",
            "DATABASE_URL",
            "",
            r"^(postgres(ql)?|mysql|mongodb(\+srv)?|redis(s)?|amqp(s)?)://[^\s/:@]+:[^\s@]+@[^\s]+$"
        ),
        rule!(
            "JSON web token",
            "JWT",
            "",
            r"^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"
        ),
    ]
});

static PEM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY-----").unwrap()
});
static HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]+$").unwrap());
static UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        .unwrap()
});

const MAX_LEN: usize = 4096;

/// Shannon entropy in bits per character.
pub fn entropy(s: &str) -> f64 {
    let mut counts = std::collections::HashMap::<char, usize>::new();
    let mut n = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n as f64;
            -p * p.log2()
        })
        .sum()
}

/// Classify a clipboard-sized piece of text. Returns `None` for ordinary text.
pub fn classify(text: &str) -> Option<Detection> {
    if text.len() > MAX_LEN {
        return None;
    }
    let trimmed = text.trim();
    if PEM.is_match(trimmed) {
        return Some(Detection {
            provider: "Private key (PEM)".into(),
            suggested_name: "PRIVATE_KEY".into(),
            url: String::new(),
            confident: true,
        });
    }
    // Only single tokens from here on: no whitespace inside.
    if trimmed.is_empty() || trimmed.contains(char::is_whitespace) {
        return None;
    }
    // Strip a surrounding pair of quotes people often copy along.
    let token = trimmed.trim_matches(|c| c == '"' || c == '\'' || c == '`');
    for r in RULES.iter() {
        if r.re.is_match(token) {
            return Some(Detection {
                provider: r.provider.into(),
                suggested_name: r.name.into(),
                url: r.url.into(),
                confident: true,
            });
        }
    }
    generic(token)
}

/// High-entropy token that is not obviously a hash, uuid, path or URL.
fn generic(token: &str) -> Option<Detection> {
    let len = token.chars().count();
    if !(32..=256).contains(&len) {
        return None;
    }
    if UUID.is_match(token) {
        return None;
    }
    if HEX.is_match(token) && matches!(len, 32 | 40 | 64 | 128) {
        return None; // md5 / sha1 / sha256 / sha512 hex digests, e.g. git commits
    }
    if token.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if token.contains("://")
        || token.matches('/').count() > 2
        || token.starts_with('/')
        || token.starts_with('~')
    {
        return None; // URLs and paths
    }
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '=' | '+' | '/'))
    {
        return None;
    }
    let has_digit = token.chars().any(|c| c.is_ascii_digit());
    let has_alpha = token.chars().any(|c| c.is_ascii_alphabetic());
    if !(has_digit && has_alpha) {
        return None;
    }
    if entropy(token) < 3.6 {
        return None;
    }
    Some(Detection {
        provider: "API key or token".into(),
        suggested_name: "API_KEY".into(),
        url: String::new(),
        confident: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Option<String> {
        classify(s).map(|d| d.suggested_name)
    }

    #[test]
    fn recognises_provider_keys() {
        assert_eq!(
            name(concat!("sk_", "live_51NxYq2LkP8ZJ4V6bQmR7TzW3aB9cD1eF")).as_deref(),
            Some("STRIPE_SECRET_KEY")
        );
        assert_eq!(
            name(concat!(
                "  \"sk_",
                "test_51NxYq2LkP8ZJ4V6bQmR7TzW3aB9cD1eF\"\n"
            ))
            .as_deref(),
            Some("STRIPE_SECRET_KEY"),
            "quotes and whitespace stripped"
        );
        assert_eq!(
            name(concat!(
                "sk-ant-",
                "api03-abcdefghijklmnopqrstuvwxyz0123456789"
            ))
            .as_deref(),
            Some("ANTHROPIC_API_KEY")
        );
        assert_eq!(
            name(concat!("sk-", "proj-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c")).as_deref(),
            Some("OPENAI_API_KEY")
        );
        assert_eq!(
            name(concat!("gh", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")).as_deref(),
            Some("GITHUB_TOKEN")
        );
        assert_eq!(
            name(concat!(
                "github_",
                "pat_11AAAAAAA0abcdefghijklmnopqrstuvwxyz"
            ))
            .as_deref(),
            Some("GITHUB_TOKEN")
        );
        assert_eq!(
            name(concat!(
                "xox",
                "b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
            ))
            .as_deref(),
            Some("SLACK_TOKEN")
        );
        assert_eq!(
            name(concat!("AI", "zaSyD-EXAMPLE-KEY-0123456789abcdefghi")).as_deref(),
            Some("GOOGLE_API_KEY")
        );
        assert_eq!(
            name(concat!("AK", "IAIOSFODNN7EXAMPLE")).as_deref(),
            Some("AWS_ACCESS_KEY_ID")
        );
        assert_eq!(
            name(concat!(
                "SG",
                ".abcdefghijklmnopqrst.uvwxyz0123456789ABCDEFGHIJ"
            ))
            .as_deref(),
            Some("SENDGRID_API_KEY")
        );
        assert_eq!(
            name(concat!("postgres://acme:", "s3cret@db.internal:5432/acme")).as_deref(),
            Some("DATABASE_URL")
        );
        assert_eq!(
            name(concat!(
                "mongodb+srv://user:",
                "pw@cluster0.abc.mongodb.net/db"
            ))
            .as_deref(),
            Some("DATABASE_URL")
        );
        assert_eq!(
            name(concat!(
                "eyJhbGciOiJIUzI1NiJ9",
                ".eyJzdWIiOiIxMjM0NTY3ODkwIn0",
                ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            ))
            .as_deref(),
            Some("JWT")
        );
        assert_eq!(
            name(concat!(
                "-----BEGIN RSA ",
                "PRIVATE KEY-----\nMIIE...\n-----END RSA ",
                "PRIVATE KEY-----"
            ))
            .as_deref(),
            Some("PRIVATE_KEY")
        );
        assert!(
            classify(concat!("sk_", "live_51NxYq2LkP8ZJ4V6bQmR7TzW3aB9cD1eF"))
                .unwrap()
                .confident
        );
    }

    #[test]
    fn generic_rule_catches_random_tokens_but_not_everyday_text() {
        let d = classify(concat!("wJalrXUtnFEMI", "/K7MDENG/bPxRfiCYEXAMPLEKEY")).unwrap();
        assert_eq!(d.suggested_name, "API_KEY");
        assert!(!d.confident);
        assert!(classify("Q7vB2nL9wE4tR8yU1iO5pA3sD6fG0hJ2kL4zX").is_some());
        for text in [
            "hello world",
            "https://example.com/some/path?x=1",
            "/Users/suman/mac_app/src/lib.rs",
            "3f786850e387550fdab836ed7e6dc881de23001b", // git sha
            "d41d8cd98f00b204e9800998ecf8427e",         // md5
            "550e8400-e29b-41d4-a716-446655440000",     // uuid
            "12345678901234567890123456789012345",      // digits
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // low entropy
            "short1",
            "",
        ] {
            assert!(classify(text).is_none(), "false positive on {text:?}");
        }
    }

    #[test]
    fn entropy_behaves() {
        assert!(entropy("aaaa") < 0.01);
        assert!(entropy("abcd") > 1.9);
        assert!(entropy("") < 0.01);
    }
}
