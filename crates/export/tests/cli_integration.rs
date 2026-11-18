use std::fs;
use std::process::Command;

#[test]
fn cli_version_and_help() {
    let bin = env!("CARGO_BIN_EXE_foliora");

    let version_output = Command::new(bin)
        .arg("--version")
        .output()
        .expect("failed to execute foliora --version");
    assert!(version_output.status.success());
    let version_str = String::from_utf8_lossy(&version_output.stdout);
    assert!(version_str.contains("foliora 0.4.0"));

    let help_output = Command::new(bin)
        .arg("--help")
        .output()
        .expect("failed to execute foliora --help");
    assert!(help_output.status.success());
    let help_str = String::from_utf8_lossy(&help_output.stdout);
    assert!(help_str.contains("SUBCOMMANDS:"));
    assert!(help_str.contains("diff"));
    assert!(help_str.contains("graph"));
}

#[test]
fn cli_diff_and_graph_subcommands() {
    let bin = env!("CARGO_BIN_EXE_foliora");

    let dir = std::env::temp_dir().join(format!("foliora_cli_test_{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();

    let bundle1_path = dir.join("bundle1.json");
    let bundle2_path = dir.join("bundle2.json");

    let bundle1_json = r#"{
      "schema_version": 1,
      "domain_schema_version": 1,
      "id": "bundle:test-1",
      "purpose": "Security review alpha",
      "exported_at": "2026-11-18T00:00:00Z",
      "expires_at": null,
      "claims": [
        {
          "id": "claim:auth",
          "claim_type": "security.auth",
          "subject": "login",
          "value": "MFA required",
          "sensitivity": "internal",
          "provenance": {
            "source_id": "source:doc1",
            "locator": { "kind": "span", "start": 0, "end": 20 },
            "user_entered_at": null
          }
        }
      ],
      "evidence": [
        {
          "id": "source:doc1",
          "fingerprint": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
          "media_type": "text/plain",
          "title": "Auth Policy",
          "captured_at": "2026-11-18T00:00:00Z"
        }
      ]
    }"#;

    let bundle2_json = r#"{
      "schema_version": 1,
      "domain_schema_version": 1,
      "id": "bundle:test-2",
      "purpose": "Security review beta",
      "exported_at": "2026-11-18T01:00:00Z",
      "expires_at": null,
      "claims": [
        {
          "id": "claim:auth",
          "claim_type": "security.auth",
          "subject": "login",
          "value": "Passkey or MFA required",
          "sensitivity": "internal",
          "provenance": {
            "source_id": "source:doc1",
            "locator": { "kind": "span", "start": 0, "end": 25 },
            "user_entered_at": null
          }
        },
        {
          "id": "claim:audit",
          "claim_type": "compliance.audit",
          "subject": "logging",
          "value": "JSONL streaming audit enabled",
          "sensitivity": "public",
          "provenance": {
            "source_id": null,
            "locator": null,
            "user_entered_at": "2026-11-18T01:00:00Z"
          }
        }
      ],
      "evidence": [
        {
          "id": "source:doc1",
          "fingerprint": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
          "media_type": "text/plain",
          "title": "Auth Policy",
          "captured_at": "2026-11-18T00:00:00Z"
        }
      ]
    }"#;

    fs::write(&bundle1_path, bundle1_json).unwrap();
    fs::write(&bundle2_path, bundle2_json).unwrap();

    // 1. Test foliora diff summary
    let diff_output = Command::new(bin)
        .arg("diff")
        .arg(&bundle1_path)
        .arg(&bundle2_path)
        .output()
        .expect("foliora diff failed");
    if !diff_output.status.success() {
        eprintln!(
            "diff_output failed: stderr={}",
            String::from_utf8_lossy(&diff_output.stderr)
        );
    }
    assert!(diff_output.status.success());
    let diff_str = String::from_utf8_lossy(&diff_output.stdout);
    assert!(diff_str.contains("Diff between bundle:test-1 and bundle:test-2"));
    assert!(diff_str.contains("claim overlap"));

    // 2. Test foliora diff --format markdown
    let diff_md = Command::new(bin)
        .arg("diff")
        .arg(&bundle1_path)
        .arg(&bundle2_path)
        .arg("--format")
        .arg("markdown")
        .output()
        .expect("foliora diff markdown failed");
    assert!(diff_md.status.success());
    let diff_md_str = String::from_utf8_lossy(&diff_md.stdout);
    assert!(diff_md_str.contains("# Context Pack Diff: bundle:test-1 vs bundle:test-2"));
    assert!(diff_md_str.contains("claim:audit"));

    // 3. Test foliora diff --format json
    let diff_json = Command::new(bin)
        .arg("diff")
        .arg(&bundle1_path)
        .arg(&bundle2_path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("foliora diff json failed");
    assert!(diff_json.status.success());
    let diff_json_str = String::from_utf8_lossy(&diff_json.stdout);
    assert!(diff_json_str.contains("\"bundle_a_id\": \"bundle:test-1\""));
    assert!(diff_json_str.contains("\"claim_jaccard\": 0.5"));

    // 4. Test foliora graph --format dot
    let graph_dot = Command::new(bin)
        .arg("graph")
        .arg(&bundle1_path)
        .arg("--format")
        .arg("dot")
        .output()
        .expect("foliora graph dot failed");
    assert!(graph_dot.status.success());
    let graph_dot_str = String::from_utf8_lossy(&graph_dot.stdout);
    assert!(graph_dot_str.contains("digraph CitationGraph {"));
    assert!(graph_dot_str.contains("source_source:doc1"));
    assert!(graph_dot_str.contains("claim_claim:auth"));

    // 5. Test foliora graph --format mermaid
    let graph_mm = Command::new(bin)
        .arg("graph")
        .arg(&bundle1_path)
        .arg("--format")
        .arg("mermaid")
        .output()
        .expect("foliora graph mermaid failed");
    assert!(graph_mm.status.success());
    let graph_mm_str = String::from_utf8_lossy(&graph_mm.stdout);
    assert!(graph_mm_str.contains("flowchart LR"));

    // Clean up
    let _ = fs::remove_dir_all(&dir);
}
