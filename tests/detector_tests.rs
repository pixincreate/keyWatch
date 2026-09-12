use key_watch::detector::{Detector, DetectorError, DetectorInitError};
use key_watch::report::Severity;
use std::str::FromStr;

#[test]
fn test_allowlist_suppresses_matched_content() -> Result<(), DetectorError> {
    let detector = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[r"secret_allowed".to_string()],
        &[],
        None,
    )?;

    assert!(
        detector.accepts_match("secret_here"),
        "a match the allowlist does not cover must be accepted"
    );
    assert!(
        !detector.accepts_match("secret_allowed"),
        "the allowlist must reject its matching token"
    );
    Ok(())
}

#[test]
fn test_detector_without_allowlist_allows_all() -> Result<(), DetectorError> {
    let detector = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[],
        &[],
        None,
    )?;

    assert!(
        detector.accepts_match("secret_anything"),
        "without an allowlist every regex match is accepted"
    );
    Ok(())
}

#[test]
fn test_invalid_allowlist_pattern_returns_error() {
    let result = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[r"[invalid".to_string()],
        &[],
        None,
    );
    assert!(
        result.is_err(),
        "Invalid allowlist pattern should return error"
    );
}

#[test]
fn test_keywords_prefilter_skips_non_matching_content() -> Result<(), DetectorError> {
    let detector = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[],
        &["apikey".to_string()],
        None,
    )?;

    assert!(!detector.has_keywords("some random text without the keyword"));
    assert!(detector.has_keywords("this text contains apikey in it"));
    Ok(())
}

#[test]
fn test_keywords_are_lowercased_at_construction() -> Result<(), DetectorError> {
    let detector = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[],
        &["ApiKey".to_string()],
        None,
    )?;

    // Callers lowercase content once per line; uppercase keyword definitions
    // must still match that lowered content.
    assert!(detector.has_keywords("this text contains apikey in it"));
    Ok(())
}

#[test]
fn test_empty_keywords_allows_all_content() -> Result<(), DetectorError> {
    let detector = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[],
        &[],
        None,
    )?;

    assert!(detector.has_keywords("any content should pass"));
    assert!(detector.has_keywords(""));
    Ok(())
}

#[test]
fn test_entropy_filters_low_entropy_matches() -> Result<(), DetectorError> {
    let detector = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[],
        &[],
        Some(3.0),
    )?;

    assert!(
        !detector.has_sufficient_entropy("secret_aaaaaaaa"),
        "Low entropy string should be rejected"
    );
    assert!(
        detector.has_sufficient_entropy("secret_a1B2c3D4e5"),
        "High entropy string should pass"
    );
    Ok(())
}

#[test]
fn test_no_entropy_threshold_allows_all() -> Result<(), DetectorError> {
    let detector = Detector::new(
        "TestDetector",
        r"\bsecret_\w+\b",
        "Test Secret",
        "HIGH",
        &[],
        &[],
        None,
    )?;

    assert!(detector.has_sufficient_entropy("secret_aaaaaaaa"));
    assert!(detector.has_sufficient_entropy("secret_a1B2c3D4e5"));
    Ok(())
}

#[test]
fn test_severity_from_str_valid_variants() {
    assert_eq!(Severity::from_str("CRITICAL").unwrap(), Severity::Critical);
    assert_eq!(Severity::from_str("HIGH").unwrap(), Severity::High);
    assert_eq!(Severity::from_str("MEDIUM").unwrap(), Severity::Medium);
    assert_eq!(Severity::from_str("LOW").unwrap(), Severity::Low);
    assert_eq!(Severity::from_str("critical").unwrap(), Severity::Critical);
    assert_eq!(Severity::from_str("  High  ").unwrap(), Severity::High);
}

#[test]
fn test_severity_from_str_invalid_returns_error() {
    let err = Severity::from_str("UNKNOWN").unwrap_err();
    assert!(
        err.to_string().contains("UNKNOWN"),
        "Error message should include the offending input"
    );
    assert!(Severity::from_str("").is_err());
    assert!(Severity::from_str("warn").is_err());
}

#[test]
fn test_severity_as_str_canonical_uppercase() {
    assert_eq!(Severity::Critical.as_str(), "CRITICAL");
    assert_eq!(Severity::High.as_str(), "HIGH");
    assert_eq!(Severity::Medium.as_str(), "MEDIUM");
    assert_eq!(Severity::Low.as_str(), "LOW");
}

#[test]
fn test_detector_new_invalid_severity_returns_typed_error() {
    let result = Detector::new(
        "BadSevDetector",
        r"\btest\b",
        "Test",
        "BOGUS",
        &[],
        &[],
        None,
    );
    match result {
        Err(DetectorError::InvalidSeverity { detector, source }) => {
            assert_eq!(detector, "BadSevDetector");
            assert!(source.to_string().contains("BOGUS"));
        }
        _ => panic!("expected InvalidSeverity error variant"),
    }
}

#[test]
fn test_detector_new_stores_parsed_severity() -> Result<(), DetectorError> {
    let detector = Detector::new("SevDetector", r"\btest\b", "Test", "MEDIUM", &[], &[], None)?;
    assert_eq!(detector.severity, Severity::Medium);
    Ok(())
}

#[test]
fn test_initialize_detectors_all_names_unique() {
    let detectors = key_watch::detector::initialize_detectors()
        .expect("detectors.toml should load without error");
    let mut names = std::collections::HashSet::new();
    for det in &detectors {
        assert!(
            names.insert(det.name.as_str()),
            "duplicate detector name: {}",
            det.name
        );
    }
}

#[test]
fn test_detector_init_error_duplicate_name_display() {
    let error = DetectorInitError::DuplicateName {
        detector: "Dup".to_string(),
    };

    assert_eq!(error.to_string(), "duplicate detector name 'Dup'");
}

#[test]
fn test_generic_key_value_ignores_unquoted_identifier_assignments() {
    let detectors = key_watch::detector::initialize_detectors().expect("load detectors");
    let generic = detectors
        .iter()
        .find(|d| d.name == "GenericKeyValueDetector")
        .expect("GenericKeyValueDetector should exist");

    let is_reported = |line: &str| {
        generic
            .regex
            .find_iter(line)
            .any(|m| generic.accepts_match(m.as_str()))
    };

    // Rust/Python/Go variable bindings are not credentials.
    for code in [
        "        let payment_method_token = card_token.clone();",
        "let secret = client_secret;",
        "token = payment_method_token",
        // Rust type paths in field declarations are not credentials either:
        // `token: PaymentTokenData,` reads identically to `token: <10 random
        // chars>` to the pattern above, but a bare CamelCase value is a type.
        "token: PaymentTokenData,",
        "secret: ConfigValue,",
        "auth: NmiAuthType,",
    ] {
        assert!(
            !is_reported(code),
            "should not flag identifier assignment: {code}"
        );
    }

    // Quoted literals, and unquoted values carrying digits, must still be
    // reported. A value with digits or symbols cannot be a type path.
    for secret in [
        "api_key = \"sk_live_51abcdefghij\"",
        "API_KEY=abc123def456789",
        "password = \"hunter2hunter2\"",
        "token = api_key_2024",
        "token = Abc123def456",
    ] {
        assert!(is_reported(secret), "should flag credential: {secret}");
    }
}

#[test]
fn test_generic_key_value_entropy_gates_the_captured_value() {
    let detectors = key_watch::detector::initialize_detectors().expect("load detectors");
    let generic = detectors
        .iter()
        .find(|d| d.name == "GenericKeyValueDetector")
        .expect("GenericKeyValueDetector should exist");

    let is_reported = |line: &str| {
        generic
            .regex
            .captures_iter(line)
            .any(|captures| generic.accepts_captures(&captures))
    };

    // The whole match clears the 2.5 threshold only because the key name
    // contributes entropy; the captured value is one repeated character and
    // must gate the match out.
    assert!(
        !is_reported("api_key = \"aaaaaaaaaa\""),
        "a repeated-character value must not report"
    );
    assert!(
        is_reported("api_key = \"aB3xK9mQ2pR7\""),
        "a real-looking value must still report"
    );
}

#[test]
fn test_accepts_captures_falls_back_to_the_whole_match() -> Result<(), DetectorError> {
    let is_reported = |detector: &Detector, line: &str| {
        detector
            .regex
            .captures_iter(line)
            .any(|captures| detector.accepts_captures(&captures))
    };

    // No capture group: entropy sees the whole match, as accepts_match does.
    let plain = Detector::new(
        "NoCaptureGroup",
        r"\bsecret_[a-z0-9]+\b",
        "Test Secret",
        "HIGH",
        &[],
        &[],
        Some(3.0),
    )?;
    assert!(
        !is_reported(&plain, "secret_aaaaaaaa"),
        "whole-match entropy below the threshold must reject"
    );
    assert!(
        is_reported(&plain, "secret_a1b2c3d4e5"),
        "whole-match entropy above the threshold must accept"
    );

    // A group that did not participate in the match also falls back to the
    // whole match; the participating group gates on its own value.
    let alternate = Detector::new(
        "AlternateGroup",
        r"alpha|beta([a-z]+)",
        "Test Secret",
        "HIGH",
        &[],
        &[],
        Some(1.5),
    )?;
    assert!(
        is_reported(&alternate, "alpha"),
        "a non-participating group must fall back to the whole match"
    );
    assert!(
        !is_reported(&alternate, "betaaaaaaaaaaa"),
        "the participating group's value must gate the match"
    );
    Ok(())
}

#[test]
fn test_password_detector_ignores_rust_expressions() {
    let detectors = key_watch::detector::initialize_detectors().expect("load detectors");
    let password_detector = detectors
        .iter()
        .find(|d| d.name == "PasswordDetector")
        .expect("PasswordDetector should exist");

    let is_reported = |line: &str| {
        password_detector
            .regex
            .find_iter(line)
            .any(|m| password_detector.accepts_match(m.as_str()))
    };

    // Rust expressions are plumbing, not credentials.
    for code in [
        "password: Secret<String>,",
        "password: password.to_owned(),",
        "password: config.db_password.clone(),",
        "password: Some(hyperswitch_masking::Secret::new(value)),",
        "password: String,",
    ] {
        assert!(
            !is_reported(code),
            "should not flag Rust expression: {code}"
        );
    }

    // Quoted literals and bare values stay reported.
    for secret in [
        "password = \"hunter2hunter2\"",
        "PASSWORD=abc123def456",
        "pwd = Swordfish2",
    ] {
        assert!(is_reported(secret), "should flag credential: {secret}");
    }
}

/// Helper: does any built-in detector report this line?
fn reported_by(line: &str) -> Vec<String> {
    let detectors = key_watch::detector::initialize_detectors().expect("load detectors");
    let lowered = line.to_lowercase();
    detectors
        .iter()
        .filter(|d| d.has_keywords(&lowered))
        .filter(|d| d.regex.find_iter(line).any(|m| d.accepts_match(m.as_str())))
        .map(|d| d.name.clone())
        .collect()
}

#[test]
fn test_credit_card_requires_issuer_prefix_and_luhn() {
    for card in [
        "4111111111111111",    // Visa
        "5500 0000 0000 0004", // Mastercard, space separated
        "4111-1111-1111-1111", // dash separated
        "378282246310005",     // Amex
    ] {
        assert!(
            reported_by(card).contains(&"CreditCardDetector".to_string()),
            "should detect card: {card}"
        );
    }

    for card in ["6500000000000002", "6441111111111117"] {
        assert!(
            reported_by(card).contains(&"CreditCardDetector".to_string()),
            "should detect Discover card: {card}"
        );
    }

    for not_a_card in [
        "4111111111111112",              // Visa prefix, fails Luhn
        "1234567890123456",              // no issuer prefix
        "6411111111111111",              // 641x is neither Discover nor UnionPay
        "index aabbcc0..1111111 100644", // spans two unrelated numbers
        "timestamp = 1700000000123",
    ] {
        assert!(
            !reported_by(not_a_card).contains(&"CreditCardDetector".to_string()),
            "should not detect card in: {not_a_card}"
        );
    }
}

#[test]
fn test_phone_number_requires_separator_or_country_code() {
    for phone in ["call 415-123-4567", "(415) 123-4567", "+1 415 123 4567"] {
        assert!(
            reported_by(phone).contains(&"PhoneNumberDetector".to_string()),
            "should detect phone: {phone}"
        );
    }
    assert!(
        !reported_by("ts 1700000000").contains(&"PhoneNumberDetector".to_string()),
        "a bare 10-digit run is a timestamp, not a phone number"
    );
    assert!(
        reported_by("call 555-123-4567").contains(&"PhoneNumberDetector".to_string()),
        "only the 555-0100..555-0199 reserved range is fictional; 555-123-4567 is not"
    );
}

#[test]
fn test_pkcs8_private_key_headers_are_detected() {
    // openssl genpkey and GCP/Azure service-account JSON emit these; before
    // the pattern required an algorithm word and matched neither.
    for header in [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    ] {
        assert!(
            !reported_by(header).is_empty(),
            "should detect private key header: {header}"
        );
    }
}

#[test]
fn test_high_entropy_hex_needs_credential_context() {
    let hex = "8b0e7153bf7c3706d85c524e440066559a6656c90bd5482a90a29b9fa5ff5180";
    assert!(
        reported_by(&format!("api_token = {hex}")).contains(&"HighEntropyDetector".to_string()),
        "hex assigned to a credential-named field should be reported"
    );
    assert!(
        !reported_by(&format!("let digest = compute({hex});"))
            .contains(&"HighEntropyDetector".to_string()),
        "a bare hex digest is indistinguishable from a hash and must not fire"
    );
}

#[test]
fn test_aws_example_key_is_allowlisted_but_real_keys_report() {
    // The AWS documentation example key/secret appear in READMEs everywhere.
    assert!(
        !reported_by("aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
            .contains(&"AWSKeyDetector".to_string())
    );
    assert!(
        !reported_by("secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
            .iter()
            .any(|name| name == "Base64Detector" || name == "AWSKeyDetector")
    );
    assert!(
        reported_by("aws_access_key_id = AKIA1234567890ABCDEF")
            .contains(&"AWSKeyDetector".to_string()),
        "any other AKIA key must still be reported"
    );
}

#[test]
fn test_placeholder_values_are_allowlisted_in_both_detectors() {
    let placeholders = [
        "API_KEY=your-api-key-here",
        "DATABASE_PASSWORD=changeme",
        "SECRET_KEY=replace-me-please",
        "PASSWORD: changeme",
        "TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxx",
    ];
    for line in &placeholders {
        let names = reported_by(line);
        assert!(
            !names.contains(&"GenericKeyValueDetector".to_string())
                && !names.contains(&"PasswordDetector".to_string()),
            "{line} must not report, got {names:?}"
        );
    }

    // Mixed-case or digit-carrying values do not match the placeholder
    // shapes and stay reported.
    for line in [
        "password = 'mySecretPassword'",
        "token = YourSpecialToken123",
        "pwd: ReplaceThisRealSecret123",
        "api_key = \"sk_live_51abcdefghij\"",
    ] {
        let names = reported_by(line);
        assert!(
            names.contains(&"GenericKeyValueDetector".to_string())
                || names.contains(&"PasswordDetector".to_string()),
            "{line} must still be reported, got {names:?}"
        );
    }
}

#[test]
fn test_email_allowlists_documentation_domains_but_not_real_ones() {
    for email in [
        "contact: support@example.com",
        "alice@example.org",
        "reply-to: noreply@github.com",
        "author: 12345+user@users.noreply.github.com",
    ] {
        assert!(
            !reported_by(email).contains(&"EmailDetector".to_string()),
            "{email} must not report"
        );
    }
    assert!(
        reported_by("owner: bob.smith@company.io").contains(&"EmailDetector".to_string()),
        "a real-looking address is still reported"
    );
    assert!(
        reported_by("owner: user@example.com.attacker.io").contains(&"EmailDetector".to_string()),
        "the documentation-domain allowlist is anchored and must not suppress lookalikes"
    );
}

#[test]
fn test_fictional_555_numbers_are_allowlisted() {
    for phone in [
        "call (212) 555-0100",
        "(415) 555-0199",
        "fax (646) 555-0123",
    ] {
        assert!(
            !reported_by(phone).contains(&"PhoneNumberDetector".to_string()),
            "{phone} is in the reserved 555-01xx range and must not report"
        );
    }
    for phone in ["call 555-123-4567", "call (212) 555-0200"] {
        assert!(
            reported_by(phone).contains(&"PhoneNumberDetector".to_string()),
            "{phone} is outside the reserved 555-01xx range and must report"
        );
    }
    assert!(
        reported_by("call 415-123-4567").contains(&"PhoneNumberDetector".to_string()),
        "a real-shaped number is still reported"
    );
}

#[test]
fn test_checksum_prefix_is_allowlisted_in_random_string() {
    let line = r#"integrity = "sha512-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG""#;
    assert!(
        !reported_by(line).contains(&"RandomString".to_string()),
        "sha-prefixed checksums must not report"
    );
    assert!(
        reported_by(r#"token = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd""#)
            .contains(&"RandomString".to_string()),
        "a quoted random string without a checksum prefix still reports"
    );
}

#[test]
fn test_supabase_service_role_key_requires_service_role_claim() {
    // Real service-role JWTs carry the base64url `service_role` claim in the
    // payload segment; the old pattern embedded one fixture's exact payload.
    let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let service_role = "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3AiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjIwMDAwMDAwMDB9";
    let anon = "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3AiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ";
    let signature = "sIGf0pXe9Bq8wZ1k3nR7vL5cQ2dY4uM6aJ0hT8eWxN";

    assert!(
        reported_by(&format!(
            "SUPABASE_SERVICE_ROLE_KEY={header}.{service_role}.{signature}"
        ))
        .contains(&"SupabaseServiceRoleKeyDetector".to_string()),
        "a service_role claim in the payload must report"
    );
    assert!(
        !reported_by(&format!("SUPABASE_ANON_KEY={header}.{anon}.{signature}"))
            .contains(&"SupabaseServiceRoleKeyDetector".to_string()),
        "an anon-role JWT must not report as a service-role key"
    );
}

#[test]
fn test_terraform_cloud_token_shape() {
    let suffix = "abcdefghij0123456789-abcdefghij0123456789_abcdefghij0123456789ab";
    assert_eq!(suffix.len(), 64);

    assert!(
        reported_by(&format!(
            "terraform_cloud_token = abcdefghijklmn.atlasv1.{suffix}"
        ))
        .contains(&"TerraformCloudTokenDetector".to_string()),
        "a 14.atlasv1.60-70 token must report"
    );
    assert!(
        !reported_by(&format!(
            "terraform_cloud_token = abcdefghijklmn.atlasv2.{suffix}"
        ))
        .contains(&"TerraformCloudTokenDetector".to_string()),
        "the atlasv1 literal is required"
    );
    assert!(
        !reported_by(&format!(
            "terraform_cloud_token = abcdefghijklm.atlasv1.{suffix}"
        ))
        .contains(&"TerraformCloudTokenDetector".to_string()),
        "the prefix before atlasv1 is exactly 14 characters"
    );
}

#[test]
fn test_azure_storage_key_is_86_to_88_base64_chars() {
    let body_86 =
        "AbCdEf0123456789+/AbCdEf0123456789+/AbCdEf0123456789+/AbCdEf0123456789+/AbCdEf01234567";
    let body_84 =
        "AbCdEf0123456789+/AbCdEf0123456789+/AbCdEf0123456789+/AbCdEf0123456789+/AbCdEf012345";
    assert_eq!(body_86.len(), 86);
    assert_eq!(body_84.len(), 84);

    assert!(
        reported_by(&format!("AccountKey={body_86}=="))
            .contains(&"AzureStorageKeyDetector".to_string()),
        "a 512-bit key is 86 base64 chars plus '=='"
    );
    assert!(
        !reported_by(&format!("AccountKey={body_84}=="))
            .contains(&"AzureStorageKeyDetector".to_string()),
        "an 84-char body is not a storage key"
    );
}

#[test]
fn test_dockerhub_personal_and_organization_token_shapes() {
    // Composed at runtime so push-protection scanners do not treat the
    // fixture as a live credential.
    let pat = format!("dckr_{}_{}", "pat", "0123456789abcdefghijklmnoAB");
    let oat = format!("dckr_{}_{}", "oat", "0123456789abcdefghijklmnopqrstuv");
    assert_eq!(pat.len(), "dckr_pat_".len() + 27);
    assert_eq!(oat.len(), "dckr_oat_".len() + 32);

    assert!(reported_by(&pat).contains(&"DockerHubTokenDetector".to_string()));
    assert!(reported_by(&oat).contains(&"DockerHubTokenDetector".to_string()));
    assert!(
        !reported_by("dckr_pat_0123456789abcdefghijklmn")
            .contains(&"DockerHubTokenDetector".to_string()),
        "a 26-char personal token is not a valid PAT"
    );
}

#[test]
fn test_circleci_v2_token_shape() {
    let hex = "0123456789abcdef".repeat(2) + "01234567";
    assert_eq!(hex.len(), 40);

    assert!(
        reported_by(&format!("circleci_token = CCIPAT_{}_{hex}", "A".repeat(22)))
            .contains(&"CircleCITokenDetector".to_string()),
        "a CCIPAT v2 token must report"
    );
    assert!(
        !reported_by(&format!("circleci_token = CCIPRJ_{}_{hex}", "A".repeat(21)))
            .contains(&"CircleCITokenDetector".to_string()),
        "the middle segment is exactly 22 alphanumerics"
    );
    assert!(
        !reported_by("circleci_token = CIRCLE_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF")
            .contains(&"CircleCITokenDetector".to_string()),
        "the legacy CIRCLE_ shape is not a v2 token"
    );
}

#[test]
fn test_discord_tokens_report_without_keyword_gate() {
    let classic = format!("{}.{}.{}", "a".repeat(24), "b".repeat(6), "c".repeat(27));
    let mfa = format!("mfa.{}", "a".repeat(84));
    let short_tail = format!("{}.{}.{}", "a".repeat(24), "b".repeat(6), "c".repeat(26));

    assert!(
        reported_by(&classic).contains(&"DiscordTokenDetector".to_string()),
        "the classic 24.6.27 token must report without a keyword"
    );
    assert!(
        reported_by(&mfa).contains(&"DiscordTokenDetector".to_string()),
        "the mfa 84-char token must report"
    );
    assert!(
        !reported_by(&short_tail).contains(&"DiscordTokenDetector".to_string()),
        "a 26-char last segment is not a Discord token"
    );
}

#[test]
fn test_netlify_token_uses_nfp_prefix() {
    let token = "nfp_0123456789abcdefghijklmnopqrstuvwxyz";
    assert_eq!(token.len(), "nfp_".len() + 36);

    assert!(
        reported_by(&format!("netlify_token = {token}"))
            .contains(&"NetlifyTokenDetector".to_string()),
        "an nfp_ token must report"
    );
    assert!(
        !reported_by("netlify_token = nf_0123456789abcdefghijklmnopqrstuvwxyz")
            .contains(&"NetlifyTokenDetector".to_string()),
        "the old nf_ prefix is not a real token shape"
    );
}

#[test]
fn test_codecov_token_requires_context_and_uuid() {
    let uuid = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    assert!(
        reported_by(&format!("CODECOV_TOKEN = \"{uuid}\""))
            .contains(&"CodecovTokenDetector".to_string()),
        "a UUID next to codecov context must report"
    );
    assert!(
        !reported_by("codecov_token = 8b0e7153bf7c3706d85c524e44006655")
            .contains(&"CodecovTokenDetector".to_string()),
        "a bare 32-hex md5 is not a Codecov token"
    );
    assert!(
        !reported_by(&format!("id: {uuid}")).contains(&"CodecovTokenDetector".to_string()),
        "a UUID without codecov context must not report"
    );
}

#[test]
fn test_adyen_username_and_bare_rzp_prefix_do_not_report() {
    // The deleted Adyen detector matched the credential username shape, not
    // the API key.
    assert!(
        !reported_by("ADYEN_API_KEY = ws_1234567890@Company.adyen.com")
            .contains(&"AdyenAPIKeyDetector".to_string())
    );
    // `rzp_` without `live`/`test` is not a key; the real shape stays covered.
    assert!(
        !reported_by("razorpay_key = rzp_0123456789abcdef")
            .contains(&"RazorpayKeyDetector".to_string())
    );
    assert!(
        reported_by("razorpay_key = rzp_live_0123456789abcdefghij")
            .contains(&"RazorpayAPIKeyDetector".to_string())
    );
}

#[test]
fn test_ip_address_validates_every_octet() {
    for ip in ["10.0.0.1", "192.168.1.1", "255.255.255.255", "0.0.0.0"] {
        assert!(
            reported_by(ip).contains(&"IPAddressDetector".to_string()),
            "valid address must report: {ip}"
        );
    }
    for not_an_ip in [
        "10.999.999.999",
        "256.1.1.1",
        "1.2.3.256",
        "999.999.999.999",
    ] {
        assert!(
            !reported_by(not_an_ip).contains(&"IPAddressDetector".to_string()),
            "invalid address must not report: {not_an_ip}"
        );
    }
}

#[test]
fn test_twilio_api_key_word_boundaries() {
    let hex32 = "0123456789abcdef".repeat(2);
    let hex31 = &hex32[..31];
    assert!(
        reported_by(&format!("twilio_api_key = SK{hex32}"))
            .contains(&"TwilioAPIKeyDetector".to_string()),
        "a 32-hex SK key must report"
    );
    assert!(
        !reported_by(&format!("twilio_api_key = SK{hex31}"))
            .contains(&"TwilioAPIKeyDetector".to_string()),
        "31 hex chars is not a Twilio key"
    );
    assert!(
        !reported_by(&format!("prefixSK{hex32}suffix"))
            .contains(&"TwilioAPIKeyDetector".to_string()),
        "the SK prefix must sit on a word boundary"
    );
}

#[test]
fn test_mailgun_api_key_word_boundaries() {
    let hex32 = "0123456789abcdef".repeat(2);
    let hex31 = &hex32[..31];
    assert!(
        reported_by(&format!("mailgun_api_key = key-{hex32}"))
            .contains(&"MailgunAPIKeyDetector".to_string()),
        "a 32-char key- value must report"
    );
    assert!(
        !reported_by(&format!("mailgun_api_key = key-{hex31}"))
            .contains(&"MailgunAPIKeyDetector".to_string()),
        "31 chars after key- is not a Mailgun key"
    );
    assert!(
        !reported_by(&format!("mailgun_api_key = xkey-{hex32}"))
            .contains(&"MailgunAPIKeyDetector".to_string()),
        "the key- prefix must sit on a word boundary"
    );
}

#[test]
fn test_gcp_service_account_requires_private_key() {
    let with_key = r#"{"type": "service_account", "project_id": "demo", "private_key_id": "abc", "private_key": "-----BEGIN PRIVATE KEY-----"}"#;
    assert!(
        reported_by(with_key).contains(&"GCPServiceAccountKeyDetector".to_string()),
        "service_account with private_key in the same object must report"
    );
    assert!(
        !reported_by(r#"{"type": "service_account", "project_id": "demo"}"#)
            .contains(&"GCPServiceAccountKeyDetector".to_string()),
        "the public type marker alone must not report"
    );
}

#[test]
fn test_detector_severities_match_credential_impact() {
    let detectors = key_watch::detector::initialize_detectors().expect("load detectors");
    let severity_of = |name: &str| {
        detectors
            .iter()
            .find(|detector| detector.name == name)
            .unwrap_or_else(|| panic!("{name} should exist"))
            .severity
    };

    assert_eq!(severity_of("MasterAPIKeyDetector"), Severity::High);
    assert_eq!(severity_of("AzureDevOpsPATDetector"), Severity::High);
    assert_eq!(severity_of("KimiMoonshotAPIKeyDetector"), Severity::High);
    assert_eq!(severity_of("GCPServiceAccountKeyDetector"), Severity::High);
    assert_eq!(severity_of("CertificateDetector"), Severity::Low);
}
