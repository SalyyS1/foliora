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
    assert!(version_str.contains("foliora 0.6.0"));

    let help_output = Command::new(bin)
        .arg("--help")
        .output()
        .expect("failed to execute foliora --help");
    assert!(help_output.status.success());
    let help_str = String::from_utf8_lossy(&help_output.stdout);
    assert!(help_str.contains("SUBCOMMANDS:"));
    assert!(help_str.contains("diff"));
    assert!(help_str.contains("graph"));
    assert!(help_str.contains("tables"));
    assert!(help_str.contains("sign"));
    assert!(help_str.contains("verify-sig"));
    assert!(help_str.contains("contradictions"));
    assert!(help_str.contains("eval"));
    assert!(help_str.contains("search"));
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

    // 6. Test foliora graph --format svg and --format html
    let graph_svg = Command::new(bin)
        .arg("graph")
        .arg(&bundle1_path)
        .arg("--format")
        .arg("svg")
        .output()
        .expect("foliora graph svg failed");
    assert!(graph_svg.status.success());
    let graph_svg_str = String::from_utf8_lossy(&graph_svg.stdout);
    assert!(graph_svg_str.contains("<svg xmlns=\"http://www.w3.org/2000/svg\""));

    let graph_html = Command::new(bin)
        .arg("graph")
        .arg(&bundle1_path)
        .arg("--format")
        .arg("html")
        .output()
        .expect("foliora graph html failed");
    assert!(graph_html.status.success());
    let graph_html_str = String::from_utf8_lossy(&graph_html.stdout);
    assert!(graph_html_str.contains("<!DOCTYPE html>"));
    assert!(graph_html_str.contains("Foliora Citation Graph: bundle:test-1"));

    // 7. Test foliora keygen, sign, and verify-sig (detached, inline, and tamper fail-closed)
    let sec_path = dir.join("signer.secret");
    let pub_path = dir.join("signer.pub");
    let sig_path = dir.join("bundle1.sig.json");
    let inline_path = dir.join("bundle1.signed.json");

    let keygen_out = Command::new(bin)
        .arg("keygen")
        .arg("--out-secret")
        .arg(&sec_path)
        .arg("--out-public")
        .arg(&pub_path)
        .output()
        .expect("foliora keygen failed");
    assert!(keygen_out.status.success());

    let sign_out = Command::new(bin)
        .arg("sign")
        .arg(&bundle1_path)
        .arg("--key")
        .arg(&sec_path)
        .arg("--out")
        .arg(&sig_path)
        .output()
        .expect("foliora sign failed");
    assert!(sign_out.status.success());

    let verify_ok = Command::new(bin)
        .arg("verify-sig")
        .arg(&bundle1_path)
        .arg("--sig")
        .arg(&sig_path)
        .arg("--pubkey")
        .arg(&pub_path)
        .output()
        .expect("foliora verify-sig failed");
    assert!(verify_ok.status.success());
    assert!(String::from_utf8_lossy(&verify_ok.stdout).contains("pinned_key=true"));

    // Verify fails closed when signature for bundle1 is checked against bundle2
    let verify_tampered = Command::new(bin)
        .arg("verify-sig")
        .arg(&bundle2_path)
        .arg("--sig")
        .arg(&sig_path)
        .arg("--pubkey")
        .arg(&pub_path)
        .output()
        .expect("foliora verify-sig tampered run failed");
    assert!(!verify_tampered.status.success());

    // Inline signed bundle roundtrip
    let sign_inline = Command::new(bin)
        .arg("sign")
        .arg(&bundle1_path)
        .arg("--key")
        .arg(&sec_path)
        .arg("--inline")
        .arg("--out")
        .arg(&inline_path)
        .output()
        .expect("foliora sign --inline failed");
    assert!(sign_inline.status.success());

    let verify_inline = Command::new(bin)
        .arg("verify-sig")
        .arg(&inline_path)
        .arg("--pubkey")
        .arg(&pub_path)
        .output()
        .expect("foliora verify-sig inline failed");
    assert!(verify_inline.status.success());

    // 8. Test verify --sarif, contradictions --sarif, search, and eval subcommands
    let contrad_bundle_path = dir.join("bundle_contrad.json");
    let contrad_bundle_json = r#"{
      "schema_version": 1,
      "domain_schema_version": 1,
      "id": "bundle:contrad-1",
      "purpose": "Contradiction audit",
      "exported_at": "2026-11-18T00:00:00Z",
      "expires_at": null,
      "claims": [
        {
          "id": "claim:sla-v1",
          "claim_type": "sla.uptime",
          "subject": "sync-api",
          "value": "Monthly uptime SLA is 99.95% and expires on 2027-12-31",
          "sensitivity": "public",
          "provenance": {
            "source_id": "source:doc1",
            "locator": { "kind": "span", "start": 0, "end": 54 },
            "user_entered_at": null
          }
        },
        {
          "id": "claim:sla-v2",
          "claim_type": "sla.summary",
          "subject": "sync-api",
          "value": "Monthly uptime SLA is 99.50% and expires on 2026-06-30",
          "sensitivity": "public",
          "provenance": {
            "source_id": "source:doc1",
            "locator": { "kind": "span", "start": 55, "end": 109 },
            "user_entered_at": null
          }
        }
      ],
      "evidence": [
        {
          "id": "source:doc1",
          "fingerprint": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
          "media_type": "text/plain",
          "title": "SLA Appendix",
          "captured_at": "2026-11-18T00:00:00Z"
        }
      ]
    }"#;
    fs::write(&contrad_bundle_path, contrad_bundle_json).unwrap();

    let verify_sarif = Command::new(bin)
        .arg("verify")
        .arg(&contrad_bundle_path)
        .arg("--sarif")
        .output()
        .expect("foliora verify --sarif failed");
    assert!(verify_sarif.status.success());
    let sarif_str = String::from_utf8_lossy(&verify_sarif.stdout);
    assert!(sarif_str.contains("\"version\": \"2.1.0\""));
    assert!(sarif_str.contains("\"FP005\""));
    assert!(sarif_str.contains("\"FP006\""));

    let search_out = Command::new(bin)
        .arg("search")
        .arg(&bundle2_path)
        .arg("Passkey MFA login")
        .arg("--mode")
        .arg("rrf")
        .output()
        .expect("foliora search failed");
    assert!(search_out.status.success());
    assert!(String::from_utf8_lossy(&search_out.stdout).contains("claim:auth"));

    let bench_path = dir.join("bench.json");
    let bench_json = r#"{
      "benchmark_id": "bench:cli-1",
      "documents": [
        { "id": "d1", "text": "Argon2id passphrase key derivation salt", "embedding": [0.9, 0.1, 0.0] },
        { "id": "d2", "text": "S3 bucket orphan garbage collection", "embedding": [0.0, 0.1, 0.9] }
      ],
      "queries": [
        {
          "query_id": "q1",
          "query": "Argon2id key derivation",
          "query_embedding": [0.95, 0.05, 0.0],
          "relevant_ids": ["d1"]
        }
      ]
    }"#;
    fs::write(&bench_path, bench_json).unwrap();

    let eval_out = Command::new(bin)
        .arg("eval")
        .arg(&bench_path)
        .arg("--k")
        .arg("2")
        .arg("--format")
        .arg("markdown")
        .output()
        .expect("foliora eval failed");
    assert!(eval_out.status.success());
    let eval_md = String::from_utf8_lossy(&eval_out.stdout);
    assert!(eval_md.contains("# Retrieval Evaluation: bench:cli-1"));
    assert!(eval_md.contains("Hybrid RRF"));

    // Clean up
    let _ = fs::remove_dir_all(&dir);
}
