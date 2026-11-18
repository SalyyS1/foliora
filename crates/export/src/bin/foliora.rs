use foliora_export::contradiction::{
    scan_bundle_contradictions, scan_chunk_contradictions, scan_segments, ContradictionSegment,
};
use foliora_export::diff::{diff_reviewed_bundles, render_diff_markdown};
use foliora_export::graph::{
    export_citation_graph, render_dot, render_html, render_mermaid, render_svg,
};
use foliora_export::retrieval::{
    evaluate_retrieval_benchmark, rank_bundle_claims, render_eval_markdown, render_eval_summary,
    RetrievalBenchmark, RetrievalConfig, RetrievalMode,
};
use foliora_export::sarif::{export_contradictions_sarif, export_verification_sarif};
use foliora_export::signature::{
    generate_signing_keypair, sign_reviewed_bundle, sign_reviewed_bundle_inline,
    verify_bundle_signature, BundleSignature, SignedReviewedBundle,
};
use foliora_export::{verify_portable_archive, verify_reviewed_bundle, ReviewedBundle};
use foliora_ingestion::{extract_pdf_tables, DocumentChunk, PdfImportLimits, PdfTableConfig};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::process::ExitCode;

const VERSION: &str = "0.6.0";

fn print_help() {
    println!(
        r#"foliora {VERSION} - Evidence-anchored Context Pack Toolkit

USAGE:
    foliora <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    diff <file_a> <file_b>   Compare two bundles (.json or .jsonl) by SHA-256 and citation overlap
    graph <file>             Export citation graph (dot, mermaid, svg, html, or json)
    tables <pdf_file>        Extract coordinate-aligned tables from native PDF content streams
    keygen                   Generate an Ed25519 signing keypair for bundle attestation
    sign <file>              Sign a ReviewedBundle with an Ed25519 secret key
    verify-sig <file>        Verify an Ed25519 bundle signature (detached or inline)
    verify <file>            Verify bundle schema, SHA-256 digests, and FP001-FP007 hazards
    contradictions <file>    Scan bundle or chunks for FP005-FP007 contradictions
    eval <benchmark.json>    Evaluate Hybrid RRF vs BM25+ and Dense retrieval (Recall/MRR/nDCG)
    search <bundle> <query>  Rank reviewed claims with Reciprocal Rank Fusion (rrf|bm25|dense)
    help                     Print this help message
    version                  Print version information

DIFF OPTIONS:
    --format <fmt>           Output format: summary (default), markdown, json
    --out <path>             Write output to file instead of stdout

GRAPH OPTIONS:
    --format <fmt>           Graph format: dot (default), mermaid, svg, html, json
    --out <path>             Write output to file instead of stdout

TABLES OPTIONS:
    --format <fmt>           Table format: markdown (default), csv, json
    --out <path>             Write output to file instead of stdout

VERIFY / CONTRADICTIONS OPTIONS:
    --sarif                  Emit OASIS SARIF v2.1.0 report (FP001-FP007)
    --json                   Emit structured JSON report
    --verified-at <utc>      Canonical UTC verification timestamp
    --out <path>             Write output to file instead of stdout

EVAL / SEARCH OPTIONS:
    --k <usize>              Top-K cutoff (default: 5)
    --rrf-k <f64>            Reciprocal Rank Fusion constant k (default: 60.0)
    --mode <mode>            Retrieval mode for search: rrf (default), bm25, dense
    --format <fmt>           Output format: summary (default), markdown (eval), json
    --out <path>             Write output to file instead of stdout

SIGN / VERIFY-SIG OPTIONS:
    --key <path>             Secret key file for 'sign'
    --signed-at <utc>        Canonical UTC timestamp for 'sign' (defaults to bundle exported_at)
    --inline                 Emit self-contained SignedReviewedBundle JSON in 'sign'
    --sig <path>             Detached BundleSignature JSON file for 'verify-sig'
    --pubkey <path>          Pinned Ed25519 public key file for 'verify-sig'
    --json                   Emit JSON verification report in 'verify-sig'
    --out <path>             Write output to file instead of stdout
"#
    );
}

fn load_bundle(path_str: &str) -> Result<ReviewedBundle, String> {
    let path = Path::new(path_str);
    if !path.exists() {
        return Err(format!("file does not exist: {path_str}"));
    }

    let file = File::open(path).map_err(|e| format!("cannot open {path_str}: {e}"))?;
    let mut reader = BufReader::new(file);

    if path_str.ends_with(".jsonl") {
        foliora_export::diff::read_bundle_from_jsonl(reader)
            .map_err(|e| format!("failed reading JSONL stream from {path_str}: {e}"))
    } else {
        let mut content = String::new();
        reader
            .read_to_string(&mut content)
            .map_err(|e| format!("cannot read {path_str}: {e}"))?;
        serde_json::from_str::<ReviewedBundle>(&content)
            .map_err(|e| format!("invalid ReviewedBundle JSON in {path_str}: {e}"))
    }
}

fn write_output(content: &str, out_path: Option<&str>) -> Result<(), String> {
    if let Some(dest) = out_path {
        fs::write(dest, content).map_err(|e| format!("cannot write to {dest}: {e}"))?;
        println!("Output written to {dest}");
    } else {
        io::stdout()
            .write_all(content.as_bytes())
            .map_err(|e| format!("stdout write error: {e}"))?;
        if !content.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

fn run_diff(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(
            "usage: foliora diff <bundle_a> <bundle_b> [--format summary|markdown|json] [--out <file>]"
                .into(),
        );
    }

    let file_a = &args[0];
    let file_b = &args[1];

    let mut format = "summary";
    let mut out_path: Option<&str> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --format".into());
                };
                format = val.as_str();
            }
            "--out" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --out".into());
                };
                out_path = Some(val.as_str());
            }
            other => return Err(format!("unknown option for diff: {other}")),
        }
        i += 1;
    }

    let bundle_a = load_bundle(file_a)?;
    let bundle_b = load_bundle(file_b)?;
    let report = diff_reviewed_bundles(&bundle_a, &bundle_b);

    let output = match format {
        "summary" => report.summary.clone(),
        "json" => serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?,
        "markdown" => render_diff_markdown(&report),
        other => {
            return Err(format!(
                "unsupported diff format '{other}'; expected summary, markdown, or json"
            ))
        }
    };

    write_output(&output, out_path)
}

fn run_graph(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "usage: foliora graph <bundle> [--format dot|mermaid|svg|html|json] [--out <file>]"
                .into(),
        );
    }

    let file_path = &args[0];
    let mut format = "dot";
    let mut out_path: Option<&str> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --format".into());
                };
                format = val.as_str();
            }
            "--out" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --out".into());
                };
                out_path = Some(val.as_str());
            }
            other => return Err(format!("unknown option for graph: {other}")),
        }
        i += 1;
    }

    let bundle = load_bundle(file_path)?;

    let output = match format {
        "dot" => render_dot(&bundle),
        "mermaid" => render_mermaid(&bundle),
        "svg" => render_svg(&bundle),
        "html" => render_html(&bundle).map_err(|e| e.to_string())?,
        "json" => {
            let export = export_citation_graph(&bundle).map_err(|e| e.to_string())?;
            serde_json::to_string_pretty(&export).map_err(|e| e.to_string())?
        }
        other => {
            return Err(format!(
                "unsupported graph format '{other}'; expected dot, mermaid, svg, html, or json"
            ))
        }
    };

    write_output(&output, out_path)
}

fn run_tables(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "usage: foliora tables <pdf_file> [--format markdown|csv|json] [--out <file>]".into(),
        );
    }

    let pdf_path = &args[0];
    let mut format = "markdown";
    let mut out_path: Option<&str> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --format".into());
                };
                format = val.as_str();
            }
            "--out" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --out".into());
                };
                out_path = Some(val.as_str());
            }
            other => return Err(format!("unknown option for tables: {other}")),
        }
        i += 1;
    }

    let bytes = fs::read(pdf_path).map_err(|e| format!("cannot read {pdf_path}: {e}"))?;
    let title = Path::new(pdf_path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned());
    let report = extract_pdf_tables(
        &bytes,
        title,
        "2026-11-18T00:00:00Z".to_owned(),
        PdfImportLimits::default(),
        PdfTableConfig::default(),
    )
    .map_err(|e| format!("PDF table extraction failed: {e}"))?;

    let output = match format {
        "json" => serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?,
        "csv" => {
            let mut buf = String::new();
            for (idx, tbl) in report.tables.iter().enumerate() {
                if idx > 0 {
                    buf.push('\n');
                }
                buf.push_str(&tbl.to_csv());
            }
            buf
        }
        "markdown" => {
            if report.tables.is_empty() {
                format!(
                    "No structured tables detected across {} page(s).\n",
                    report.page_count
                )
            } else {
                let mut buf = String::new();
                for tbl in &report.tables {
                    buf.push_str(&format!(
                        "### Table {} (Page {}, {})\n\n{}\n",
                        tbl.table_index + 1,
                        tbl.page,
                        tbl.sha256,
                        tbl.to_markdown()
                    ));
                }
                buf
            }
        }
        other => {
            return Err(format!(
                "unsupported tables format '{other}'; expected markdown, csv, or json"
            ))
        }
    };

    write_output(&output, out_path)
}

fn run_keygen(args: &[String]) -> Result<(), String> {
    let mut out_secret: Option<&str> = None;
    let mut out_public: Option<&str> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out-secret" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --out-secret".into());
                };
                out_secret = Some(val.as_str());
            }
            "--out-public" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --out-public".into());
                };
                out_public = Some(val.as_str());
            }
            other => return Err(format!("unknown option for keygen: {other}")),
        }
        i += 1;
    }

    let (Some(sec_path), Some(pub_path)) = (out_secret, out_public) else {
        return Err(
            "usage: foliora keygen --out-secret <secret.key> --out-public <public.key>".into(),
        );
    };

    let kp = generate_signing_keypair().map_err(|e| e.to_string())?;
    fs::write(sec_path, format!("{}\n", kp.secret_key.as_str()))
        .map_err(|e| format!("cannot write secret key to {sec_path}: {e}"))?;
    fs::write(pub_path, format!("{}\n", kp.public_key))
        .map_err(|e| format!("cannot write public key to {pub_path}: {e}"))?;
    println!("Generated Ed25519 keypair ({})", kp.key_id);
    Ok(())
}

fn run_sign(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "usage: foliora sign <bundle> --key <secret.key> [--signed-at <utc>] [--inline] [--out <file>]"
                .into(),
        );
    }

    let bundle_path = &args[0];
    let mut key_path: Option<&str> = None;
    let mut signed_at: Option<&str> = None;
    let mut inline = false;
    let mut out_path: Option<&str> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--key" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --key".into());
                };
                key_path = Some(val.as_str());
            }
            "--signed-at" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --signed-at".into());
                };
                signed_at = Some(val.as_str());
            }
            "--inline" => inline = true,
            "--out" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --out".into());
                };
                out_path = Some(val.as_str());
            }
            other => return Err(format!("unknown option for sign: {other}")),
        }
        i += 1;
    }

    let Some(sec_file) = key_path else {
        return Err("missing required --key <secret.key> argument".into());
    };
    let secret_key =
        fs::read_to_string(sec_file).map_err(|e| format!("cannot read {sec_file}: {e}"))?;
    let bundle = load_bundle(bundle_path)?;
    let ts = signed_at
        .map(str::to_owned)
        .unwrap_or_else(|| bundle.exported_at.clone());

    let output = if inline {
        let signed =
            sign_reviewed_bundle_inline(bundle, &secret_key, &ts).map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&signed).map_err(|e| e.to_string())?
    } else {
        let sig = sign_reviewed_bundle(&bundle, &secret_key, &ts).map_err(|e| e.to_string())?;
        serde_json::to_string_pretty(&sig).map_err(|e| e.to_string())?
    };

    write_output(&output, out_path)
}

fn run_verify_sig(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "usage: foliora verify-sig <bundle_or_inline> [--sig <sig.json>] [--pubkey <public.key>] [--json]"
                .into(),
        );
    }

    let target_path = &args[0];
    let mut sig_path: Option<&str> = None;
    let mut pubkey_path: Option<&str> = None;
    let mut json_output = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--sig" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --sig".into());
                };
                sig_path = Some(val.as_str());
            }
            "--pubkey" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --pubkey".into());
                };
                pubkey_path = Some(val.as_str());
            }
            "--json" => json_output = true,
            other => return Err(format!("unknown option for verify-sig: {other}")),
        }
        i += 1;
    }

    let pinned_pubkey = match pubkey_path {
        Some(pk_file) => {
            Some(fs::read_to_string(pk_file).map_err(|e| format!("cannot read {pk_file}: {e}"))?)
        }
        None => None,
    };

    let (bundle, sig) = if let Some(sf) = sig_path {
        let bundle = load_bundle(target_path)?;
        let sig_raw = fs::read_to_string(sf).map_err(|e| format!("cannot read {sf}: {e}"))?;
        let sig: BundleSignature = serde_json::from_str(&sig_raw)
            .map_err(|e| format!("invalid BundleSignature JSON in {sf}: {e}"))?;
        (bundle, sig)
    } else {
        let raw = fs::read_to_string(target_path)
            .map_err(|e| format!("cannot read {target_path}: {e}"))?;
        let inline: SignedReviewedBundle = serde_json::from_str(&raw).map_err(|e| {
            format!(
                "expected SignedReviewedBundle JSON in {target_path} (or pass --sig <file>): {e}"
            )
        })?;
        (inline.bundle, inline.signature)
    };

    let report = verify_bundle_signature(&bundle, &sig, pinned_pubkey.as_deref())
        .map_err(|e| format!("signature verification failed: {e}"))?;

    if json_output {
        let rendered = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
        println!("{rendered}");
    } else {
        println!(
            "Signature verified for {}: key_id={}, digest={}, pinned_key={}",
            report.bundle_id, report.key_id, report.bundle_sha256, report.pinned_key_verified
        );
    }
    Ok(())
}

fn run_verify(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "usage: foliora verify <bundle> [--sarif] [--json] [--verified-at <utc>] [--out <file>]"
                .into(),
        );
    }
    let file_path = &args[0];
    let mut sarif = false;
    let mut json_out = false;
    let mut verified_at = "2026-11-18T00:00:00Z";
    let mut out_path: Option<&str> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--sarif" => sarif = true,
            "--json" => json_out = true,
            "--verified-at" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --verified-at".into());
                };
                verified_at = val.as_str();
            }
            "--out" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --out".into());
                };
                out_path = Some(val.as_str());
            }
            other => return Err(format!("unknown option for verify: {other}")),
        }
        i += 1;
    }

    let (report, maybe_bundle) =
        if file_path.ends_with(".zip") || file_path.ends_with(".foliora-pack") {
            let bytes = fs::read(file_path).map_err(|e| format!("cannot read {file_path}: {e}"))?;
            let rep = verify_portable_archive(&bytes, verified_at, None)
                .map_err(|e| format!("verification failed: {e}"))?;
            (rep, None)
        } else {
            let bundle = load_bundle(file_path)?;
            let rep = verify_reviewed_bundle(&bundle, verified_at, None)
                .map_err(|e| format!("verification failed: {e}"))?;
            (rep, Some(bundle))
        };

    let output = if sarif {
        export_verification_sarif(&report, maybe_bundle.as_ref(), file_path)
            .map_err(|e| e.to_string())?
    } else if json_out {
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    } else {
        format!(
            "Bundle {} verified clean: {} claims, {} evidence sources, {} hazards detected.",
            report.bundle_id,
            report.claim_count,
            report.evidence_count,
            report.hazards.len()
        )
    };

    write_output(&output, out_path)
}

fn run_contradictions(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "usage: foliora contradictions <bundle_or_chunks.json> [--sarif] [--json] [--out <file>]"
                .into(),
        );
    }
    let file_path = &args[0];
    let mut sarif = false;
    let mut json_out = false;
    let mut out_path: Option<&str> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--sarif" => sarif = true,
            "--json" => json_out = true,
            "--out" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --out".into());
                };
                out_path = Some(val.as_str());
            }
            other => return Err(format!("unknown option for contradictions: {other}")),
        }
        i += 1;
    }

    let findings = if file_path.ends_with(".jsonl") {
        let bundle = load_bundle(file_path)?;
        scan_bundle_contradictions(&bundle)
    } else {
        let raw =
            fs::read_to_string(file_path).map_err(|e| format!("cannot read {file_path}: {e}"))?;
        if let Ok(bundle) = serde_json::from_str::<ReviewedBundle>(&raw) {
            scan_bundle_contradictions(&bundle)
        } else if let Ok(chunks) = serde_json::from_str::<Vec<DocumentChunk>>(&raw) {
            scan_chunk_contradictions(&chunks)
        } else if let Ok(segments) = serde_json::from_str::<Vec<ContradictionSegment>>(&raw) {
            scan_segments(&segments)
        } else {
            return Err(format!(
                "expected ReviewedBundle, DocumentChunk[], or ContradictionSegment[] JSON in {file_path}"
            ));
        }
    };

    let output = if sarif {
        export_contradictions_sarif(&findings, file_path).map_err(|e| e.to_string())?
    } else if json_out {
        serde_json::to_string_pretty(&findings).map_err(|e| e.to_string())?
    } else if findings.is_empty() {
        format!("No FP005-FP007 contradictions detected in {file_path}.")
    } else {
        let mut buf = format!(
            "Detected {} contradiction(s) in {file_path}:\n",
            findings.len()
        );
        for f in &findings {
            buf.push_str(&format!(
                "  [{}] {} vs {}: {}\n",
                f.rule_id, f.primary_id, f.peer_id, f.detail
            ));
        }
        buf
    };

    write_output(&output, out_path)
}

fn run_eval(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "usage: foliora eval <benchmark.json> [--k <usize>] [--rrf-k <f64>] [--format summary|markdown|json] [--out <file>]"
                .into(),
        );
    }
    let bench_path = &args[0];
    let mut cutoff_k: usize = 5;
    let mut config = RetrievalConfig::default();
    let mut format = "summary";
    let mut out_path: Option<&str> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--k" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --k".into());
                };
                cutoff_k = val
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --k integer: {val}"))?;
            }
            "--rrf-k" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --rrf-k".into());
                };
                config.rrf_k = val
                    .parse::<f64>()
                    .map_err(|_| format!("invalid --rrf-k float: {val}"))?;
            }
            "--format" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --format".into());
                };
                format = val.as_str();
            }
            "--out" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --out".into());
                };
                out_path = Some(val.as_str());
            }
            other => return Err(format!("unknown option for eval: {other}")),
        }
        i += 1;
    }

    let raw =
        fs::read_to_string(bench_path).map_err(|e| format!("cannot read {bench_path}: {e}"))?;
    let benchmark: RetrievalBenchmark = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid RetrievalBenchmark JSON in {bench_path}: {e}"))?;
    let report = evaluate_retrieval_benchmark(&benchmark, cutoff_k, &config)
        .map_err(|e| format!("retrieval evaluation failed: {e}"))?;

    let output = match format {
        "summary" => render_eval_summary(&report),
        "markdown" => render_eval_markdown(&report),
        "json" => serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?,
        other => {
            return Err(format!(
                "unsupported eval format '{other}'; expected summary, markdown, or json"
            ))
        }
    };

    write_output(&output, out_path)
}

fn run_search(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err(
            "usage: foliora search <bundle> <query> [--k <usize>] [--mode rrf|bm25|dense] [--format summary|json] [--out <file>]"
                .into(),
        );
    }
    let bundle_path = &args[0];
    let query = &args[1];
    let mut top_k: usize = 5;
    let mut mode = RetrievalMode::HybridRrf;
    let mut format = "summary";
    let mut out_path: Option<&str> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--k" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --k".into());
                };
                top_k = val
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --k integer: {val}"))?;
            }
            "--mode" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --mode".into());
                };
                mode = match val.as_str() {
                    "rrf" | "hybrid" => RetrievalMode::HybridRrf,
                    "bm25" => RetrievalMode::Bm25Only,
                    "dense" => RetrievalMode::DenseOnly,
                    other => {
                        return Err(format!(
                            "unsupported search mode '{other}'; expected rrf, bm25, or dense"
                        ))
                    }
                };
            }
            "--format" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --format".into());
                };
                format = val.as_str();
            }
            "--out" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    return Err("missing argument for --out".into());
                };
                out_path = Some(val.as_str());
            }
            other => return Err(format!("unknown option for search: {other}")),
        }
        i += 1;
    }

    let bundle = load_bundle(bundle_path)?;
    let hits = rank_bundle_claims(&bundle, query, mode, top_k, &RetrievalConfig::default())
        .map_err(|e| format!("bundle search failed: {e}"))?;

    let output = match format {
        "json" => serde_json::to_string_pretty(&hits).map_err(|e| e.to_string())?,
        "summary" => {
            if hits.is_empty() {
                format!("No matching claims in {} for query '{query}'.", bundle.id)
            } else {
                let mut buf = format!(
                    "Top {} claim(s) in {} for '{query}':\n",
                    hits.len(),
                    bundle.id
                );
                for h in &hits {
                    buf.push_str(&format!(
                        "  #{}: {} (score={:.6}, bm25={:.4}, dense={:.4})\n",
                        h.rank, h.id, h.fused_score, h.bm25_score, h.dense_cosine
                    ));
                }
                buf
            }
        }
        other => {
            return Err(format!(
                "unsupported search format '{other}'; expected summary or json"
            ))
        }
    };

    write_output(&output, out_path)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        return ExitCode::SUCCESS;
    }

    let res = match args[0].as_str() {
        "diff" => run_diff(&args[1..]),
        "graph" => run_graph(&args[1..]),
        "tables" => run_tables(&args[1..]),
        "keygen" => run_keygen(&args[1..]),
        "sign" => run_sign(&args[1..]),
        "verify-sig" => run_verify_sig(&args[1..]),
        "verify" => run_verify(&args[1..]),
        "contradictions" => run_contradictions(&args[1..]),
        "eval" => run_eval(&args[1..]),
        "search" => run_search(&args[1..]),
        "-v" | "--version" | "version" => {
            println!("foliora {VERSION}");
            Ok(())
        }
        "-h" | "--help" | "help" => {
            print_help();
            Ok(())
        }
        other => Err(format!(
            "unknown subcommand '{other}'. Run 'foliora --help' for usage."
        )),
    };

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
