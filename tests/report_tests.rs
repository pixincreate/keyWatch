use key_watch::report::{
    Finding, ScanMetadata, Severity, SeverityCounts, create_report, create_sarif_report,
    get_severity_counts,
};
use serde_json::Value;

fn parse_json(output: &str) -> Value {
    serde_json::from_str(output).expect("valid JSON output")
}

#[test]
fn test_create_report() {
    let findings = vec![];
    let metadata = ScanMetadata {
        files_scanned: 5,
        total_lines: 100,
        excluded_files: vec![],
        unscannable_files: vec![],
        suppressed_by_baseline: 0,
    };

    let report = create_report(findings, metadata, "0.5s".to_string(), false)
        .expect("create_report should succeed");
    let json = parse_json(&report);

    assert_eq!(json["status"], "PASS");
    assert_eq!(json["files_scanned"], 5);
    assert_eq!(json["total_lines"], 100);
    assert_eq!(json["excluded"]["count"], 0);
    assert_eq!(json["scan_time"], "0.5s");
}

#[test]
fn test_report_with_findings() {
    let findings = vec![Finding {
        file_path: "secret.txt".to_string(),
        line_number: 10,
        finding_type: "AWS Key".to_string(),
        severity: Severity::High,
        matched_content: "AKIATESTKEY".to_string(),
        detector_name: "AWSKeyDetector".to_string(),
    }];
    let metadata = ScanMetadata {
        files_scanned: 1,
        total_lines: 50,
        excluded_files: vec![],
        unscannable_files: vec![],
        suppressed_by_baseline: 0,
    };

    let report = create_report(findings, metadata, "0.1s".to_string(), false)
        .expect("create_report should succeed");
    let json = parse_json(&report);

    assert_eq!(json["status"], "FAIL");
    assert_eq!(json["findings"][0]["finding_type"], "AWS Key");
    // Matched text is redacted unless --show-secrets is passed.
    assert_eq!(
        json["findings"][0]["matched_content"],
        "AKIA... (11 chars, redacted)"
    );
}

#[test]
fn test_create_report_includes_excluded_files_and_plugin_metadata() {
    let findings = vec![Finding {
        file_path: "secret.txt".to_string(),
        line_number: 7,
        finding_type: "API Token".to_string(),
        severity: Severity::Medium,
        matched_content: "tok_test_123".to_string(),
        detector_name: "TokenDetector".to_string(),
    }];
    let metadata = ScanMetadata {
        files_scanned: 2,
        total_lines: 80,
        excluded_files: vec!["ignored.log".to_string(), "vendor/secrets.txt".to_string()],
        unscannable_files: vec![],
        suppressed_by_baseline: 0,
    };

    let report = create_report(findings, metadata, "1.2s".to_string(), false)
        .expect("create_report should succeed");
    let json = parse_json(&report);

    assert_eq!(
        json["excluded"]["sample"],
        serde_json::json!(["ignored.log", "vendor/secrets.txt"])
    );
    assert_eq!(json["findings"][0]["plugin_name"], "TokenDetector");
    assert_eq!(
        json["findings"][0]["matched_content"],
        "tok_... (12 chars, redacted)"
    );
    assert_eq!(json["total_lines"], 80);
}

#[test]
fn test_create_sarif_report_uses_camel_case_fields_and_hides_matched_content() {
    let secret = "AKIATESTKEY".to_string();
    let findings = vec![Finding {
        file_path: "src/secret.txt".to_string(),
        line_number: 12,
        finding_type: "AWS Key".to_string(),
        severity: Severity::Critical,
        matched_content: secret.clone(),
        detector_name: "AwsKeyDetector".to_string(),
    }];
    let metadata = ScanMetadata {
        files_scanned: 5,
        total_lines: 120,
        excluded_files: vec!["skip.log".to_string()],
        unscannable_files: vec!["blob.bin".to_string()],
        suppressed_by_baseline: 3,
    };

    let sarif = create_sarif_report(findings, metadata, "2026-08-01T00:00:00Z".to_string())
        .expect("create_sarif_report should succeed");
    let json = parse_json(&sarif);

    assert_eq!(
        json["$schema"],
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    );
    assert_eq!(json["version"], "2.1.0");

    let driver = &json["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "KeyWatch");
    assert!(driver.get("informationUri").is_some());
    assert!(driver.get("semanticVersion").is_some());
    assert!(driver.get("information_uri").is_none());
    assert!(driver.get("semantic_version").is_none());

    let properties = &json["runs"][0]["properties"];
    let property_keys: Vec<&str> = properties
        .as_object()
        .expect("run properties object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        property_keys,
        vec![
            "excludedFiles",
            "filesScanned",
            "scanTime",
            "status",
            "suppressedByBaseline",
            "totalLines",
            "unscannableFiles",
        ],
        "run scan counts must serialize in deterministic key order"
    );
    assert_eq!(properties["filesScanned"], 5);
    assert_eq!(properties["totalLines"], 120);
    assert_eq!(properties["excludedFiles"], 1);
    assert_eq!(properties["unscannableFiles"], 1);
    assert_eq!(properties["suppressedByBaseline"], 3);
    assert_eq!(properties["status"], "fail");

    let result = &json["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "AWS Key");
    assert_eq!(result["level"], "error");
    assert_eq!(result["message"]["text"], "Potential AWS Key detected");
    assert_eq!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/secret.txt"
    );
    assert_eq!(
        result["locations"][0]["physicalLocation"]["region"]["startLine"],
        12
    );
    assert!(result.get("rule_id").is_none());
    assert!(result.get("physical_location").is_none());
    assert!(
        result["locations"][0]["physicalLocation"]
            .get("artifact_location")
            .is_none()
    );
    assert!(
        result["locations"][0]["physicalLocation"]["region"]
            .get("start_line")
            .is_none()
    );

    assert_eq!(
        result["properties"]["severity"],
        Severity::Critical.as_str()
    );
    assert_eq!(result["properties"]["precision"], "very-high");
    assert!(!sarif.contains(&secret));
}

#[test]
fn test_create_sarif_report_maps_all_severities_to_expected_levels() {
    let findings = vec![
        Finding {
            file_path: "critical.txt".to_string(),
            line_number: 1,
            finding_type: "CriticalRule".to_string(),
            severity: Severity::Critical,
            matched_content: "critical-secret".to_string(),
            detector_name: "CriticalDetector".to_string(),
        },
        Finding {
            file_path: "high.txt".to_string(),
            line_number: 2,
            finding_type: "HighRule".to_string(),
            severity: Severity::High,
            matched_content: "high-secret".to_string(),
            detector_name: "HighDetector".to_string(),
        },
        Finding {
            file_path: "medium.txt".to_string(),
            line_number: 3,
            finding_type: "MediumRule".to_string(),
            severity: Severity::Medium,
            matched_content: "medium-secret".to_string(),
            detector_name: "MediumDetector".to_string(),
        },
        Finding {
            file_path: "low.txt".to_string(),
            line_number: 4,
            finding_type: "LowRule".to_string(),
            severity: Severity::Low,
            matched_content: "low-secret".to_string(),
            detector_name: "LowDetector".to_string(),
        },
    ];
    let metadata = ScanMetadata {
        files_scanned: 4,
        total_lines: 4,
        excluded_files: vec![],
        unscannable_files: vec![],
        suppressed_by_baseline: 0,
    };

    let sarif = create_sarif_report(findings, metadata, "2026-08-01T00:00:00Z".to_string())
        .expect("create_sarif_report should succeed");
    let json = parse_json(&sarif);
    let results = json["runs"][0]["results"]
        .as_array()
        .expect("results array");

    let levels: Vec<&str> = results
        .iter()
        .map(|result| result["level"].as_str().expect("level string"))
        .collect();
    assert_eq!(levels, vec!["error", "error", "warning", "note"]);

    let severities: Vec<&str> = results
        .iter()
        .map(|result| {
            result["properties"]["severity"]
                .as_str()
                .expect("severity string")
        })
        .collect();
    assert_eq!(
        severities,
        vec![
            Severity::Critical.as_str(),
            Severity::High.as_str(),
            Severity::Medium.as_str(),
            Severity::Low.as_str()
        ]
    );
}

#[test]
fn test_get_severity_counts_groups_high_medium_low() {
    let findings = vec![
        Finding {
            file_path: "a.txt".to_string(),
            line_number: 1,
            finding_type: "A".to_string(),
            severity: Severity::High,
            matched_content: "a".to_string(),
            detector_name: "DetectorA".to_string(),
        },
        Finding {
            file_path: "b.txt".to_string(),
            line_number: 2,
            finding_type: "B".to_string(),
            severity: Severity::Medium,
            matched_content: "b".to_string(),
            detector_name: "DetectorB".to_string(),
        },
        Finding {
            file_path: "c.txt".to_string(),
            line_number: 3,
            finding_type: "C".to_string(),
            severity: Severity::Low,
            matched_content: "c".to_string(),
            detector_name: "DetectorC".to_string(),
        },
        Finding {
            file_path: "d.txt".to_string(),
            line_number: 4,
            finding_type: "D".to_string(),
            severity: Severity::High,
            matched_content: "d".to_string(),
            detector_name: "DetectorD".to_string(),
        },
    ];

    let counts = get_severity_counts(&findings);

    assert_eq!(
        counts,
        SeverityCounts {
            critical: 0,
            high: 2,
            medium: 1,
            low: 1,
        }
    );
}

#[test]
fn test_redact_shows_no_prefix_for_short_matches() {
    // Below eight characters a four-character prefix would reveal most or
    // all of the secret, so short matches are described by length only.
    assert_eq!(key_watch::report::redact("abc12"), "(5 chars, redacted)");
    assert_eq!(key_watch::report::redact("abc1234"), "(7 chars, redacted)");
    assert_eq!(
        key_watch::report::redact("AKIAABCDEFGHIJKLMNOP"),
        "AKIA... (20 chars, redacted)"
    );
}

#[test]
fn test_finding_wire_format_keeps_plugin_name_and_round_trips() {
    use key_watch::report::{Finding, Severity};

    let finding = Finding {
        file_path: "a.txt".to_string(),
        line_number: 7,
        finding_type: "AWS Key".to_string(),
        severity: Severity::High,
        matched_content: "AKIAIOSFODNN7EXAMPLE".to_string(),
        detector_name: "AWSKeyDetector".to_string(),
    };

    // The JSON wire format keeps the historical plugin_name key.
    let json = serde_json::to_value(&finding).expect("serialize");
    assert_eq!(json["plugin_name"], "AWSKeyDetector");
    assert!(json.get("detector_name").is_none(), "no duplicate key");

    // Deserialization accepts the historical key and the new one (alias).
    let from_historical: Finding =
        serde_json::from_value(json.clone()).expect("plugin_name must deserialize");
    assert_eq!(from_historical.detector_name, "AWSKeyDetector");

    let aliased = json;
    let mut with_new_key = serde_json::Map::new();
    for (key, value) in aliased.as_object().expect("object") {
        let key = if key == "plugin_name" {
            "detector_name".to_string()
        } else {
            key.clone()
        };
        with_new_key.insert(key, value.clone());
    }
    let from_new: Finding =
        serde_json::from_value(with_new_key.into()).expect("alias must deserialize");
    assert_eq!(from_new.detector_name, "AWSKeyDetector");
}
