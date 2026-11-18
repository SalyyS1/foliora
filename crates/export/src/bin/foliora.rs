use foliora_export::diff::{diff_reviewed_bundles, render_diff_markdown};
use foliora_export::graph::{export_citation_graph, render_dot, render_mermaid};
use foliora_export::verify_reviewed_bundle;
use foliora_export::ReviewedBundle;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::process::ExitCode;

const VERSION: &str = "0.4.0";

fn print_help() {
    println!(
        r#"foliora {VERSION} - Evidence-anchored Context Pack Toolkit

USAGE:
    foliora <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    diff <file_a> <file_b>   Compare two bundles (.json or .jsonl) by SHA-256 and citation overlap
    graph <file>             Export structured citation graph (.dot or .mermaid) tracing evidence chains
    verify <file>            Verify bundle schema, SHA-256 digests, and indirect prompt injection hazards
    help                     Print this help message
    version                  Print version information

DIFF OPTIONS:
    --format <fmt>           Output format: summary (default), markdown, json
    --out <path>             Write output to file instead of stdout

GRAPH OPTIONS:
    --format <fmt>           Graph format: dot (default), mermaid, json
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
        return Err("usage: foliora diff <bundle_a> <bundle_b> [--format summary|markdown|json] [--out <file>]".into());
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
                if i < args.len() {
                    format = args[i].as_str();
                } else {
                    return Err("missing argument for --format".into());
                }
            }
            "--out" => {
                i += 1;
                if i < args.len() {
                    out_path = Some(args[i].as_str());
                } else {
                    return Err("missing argument for --out".into());
                }
            }
            other => return Err(format!("unknown option for diff: {other}")),
        }
        i += 1;
    }

    let bundle_a = load_bundle(file_a)?;
    let bundle_b = load_bundle(file_b)?;

    let report = diff_reviewed_bundles(&bundle_a, &bundle_b);

    let output = match format {
        "json" => serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?,
        "markdown" => render_diff_markdown(&report),
        _ => report.summary.clone(),
    };

    write_output(&output, out_path)?;
    Ok(())
}

fn run_graph(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: foliora graph <bundle> [--format dot|mermaid|json] [--out <file>]".into());
    }

    let file_path = &args[0];
    let mut format = "dot";
    let mut out_path: Option<&str> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                i += 1;
                if i < args.len() {
                    format = args[i].as_str();
                } else {
                    return Err("missing argument for --format".into());
                }
            }
            "--out" => {
                i += 1;
                if i < args.len() {
                    out_path = Some(args[i].as_str());
                } else {
                    return Err("missing argument for --out".into());
                }
            }
            other => return Err(format!("unknown option for graph: {other}")),
        }
        i += 1;
    }

    let bundle = load_bundle(file_path)?;

    let output = match format {
        "mermaid" => render_mermaid(&bundle),
        "json" => {
            let export = export_citation_graph(&bundle).map_err(|e| e.to_string())?;
            serde_json::to_string_pretty(&export).map_err(|e| e.to_string())?
        }
        _ => render_dot(&bundle),
    };

    write_output(&output, out_path)?;
    Ok(())
}

fn run_verify(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: foliora verify <bundle>".into());
    }
    let file_path = &args[0];
    let bundle = load_bundle(file_path)?;
    let now = "2026-11-18T00:00:00Z";
    let report = verify_reviewed_bundle(&bundle, now, None)
        .map_err(|e| format!("verification failed: {e}"))?;

    println!("Bundle {} verified clean: {} claims, {} evidence sources, {} hazards detected.",
        report.bundle_id, report.claim_count, report.evidence_count, report.hazards.len()
    );
    Ok(())
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
        "verify" => run_verify(&args[1..]),
        "-v" | "--version" | "version" => {
            println!("foliora {VERSION}");
            Ok(())
        }
        "-h" | "--help" | "help" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown subcommand '{other}'. Run 'foliora --help' for usage.")),
    };

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
