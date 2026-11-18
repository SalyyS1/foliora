//! Reciprocal Rank Fusion (RRF) hybrid BM25+ and dense retrieval ranker and
//! offline IR benchmark evaluator (Recall@K, Precision@K, MRR@K, and nDCG@K).

use crate::ReviewedBundle;
use foliora_ingestion::DocumentChunk;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub const DEFAULT_BM25_K1: f64 = 1.2;
pub const DEFAULT_BM25_B: f64 = 0.75;
pub const DEFAULT_BM25_DELTA: f64 = 1.0;
pub const DEFAULT_RRF_K: f64 = 60.0;
pub const DEFAULT_FALLBACK_DENSE_DIM: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalMode {
    Bm25Only,
    DenseOnly,
    HybridRrf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalConfig {
    pub bm25_k1: f64,
    pub bm25_b: f64,
    pub bm25_delta: f64,
    pub rrf_k: f64,
    pub bm25_weight: f64,
    pub dense_weight: f64,
    pub fallback_dense_dim: usize,
}

impl Default for RetrievalConfig {
    fn default() -> Self {
        Self {
            bm25_k1: DEFAULT_BM25_K1,
            bm25_b: DEFAULT_BM25_B,
            bm25_delta: DEFAULT_BM25_DELTA,
            rrf_k: DEFAULT_RRF_K,
            bm25_weight: 1.0,
            dense_weight: 1.0,
            fallback_dense_dim: DEFAULT_FALLBACK_DENSE_DIM,
        }
    }
}

impl RetrievalConfig {
    pub fn validate(&self) -> Result<(), RetrievalError> {
        if !self.bm25_k1.is_finite() || self.bm25_k1 < 0.0 {
            return Err(RetrievalError::InvalidConfig(
                "bm25_k1 must be finite and non-negative",
            ));
        }
        if !self.bm25_b.is_finite() || !(0.0..=1.0).contains(&self.bm25_b) {
            return Err(RetrievalError::InvalidConfig(
                "bm25_b must be within [0.0, 1.0]",
            ));
        }
        if !self.bm25_delta.is_finite() || self.bm25_delta < 0.0 {
            return Err(RetrievalError::InvalidConfig(
                "bm25_delta must be finite and non-negative",
            ));
        }
        if !self.rrf_k.is_finite() || self.rrf_k <= 0.0 {
            return Err(RetrievalError::InvalidConfig(
                "rrf_k must be finite and strictly positive",
            ));
        }
        if !self.bm25_weight.is_finite()
            || !self.dense_weight.is_finite()
            || self.bm25_weight < 0.0
            || self.dense_weight < 0.0
            || (self.bm25_weight + self.dense_weight) <= 0.0
        {
            return Err(RetrievalError::InvalidConfig(
                "bm25_weight and dense_weight must be non-negative with positive sum",
            ));
        }
        if !(16..=4096).contains(&self.fallback_dense_dim) {
            return Err(RetrievalError::InvalidConfig(
                "fallback_dense_dim must be within [16, 4096]",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetrievalError {
    InvalidConfig(&'static str),
    EmptyCorpus,
    DuplicateDocumentId(String),
    DimensionMismatch {
        expected: usize,
        actual: usize,
        target_id: String,
    },
    NonFiniteEmbedding(String),
    EmptyBenchmarkQueries,
    EmptyRelevantSet(String),
    InvalidCutoff,
}

impl std::fmt::Display for RetrievalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid retrieval configuration: {msg}"),
            Self::EmptyCorpus => write!(f, "retrieval corpus contains zero documents"),
            Self::DuplicateDocumentId(id) => {
                write!(f, "retrieval corpus contains duplicate document id {id}")
            }
            Self::DimensionMismatch {
                expected,
                actual,
                target_id,
            } => write!(
                f,
                "embedding dimension mismatch on {target_id}: expected {expected}, got {actual}"
            ),
            Self::NonFiniteEmbedding(id) => {
                write!(f, "embedding contains NaN or infinite float on {id}")
            }
            Self::EmptyBenchmarkQueries => {
                write!(f, "retrieval benchmark contains zero evaluation queries")
            }
            Self::EmptyRelevantSet(qid) => {
                write!(f, "query {qid} defines zero ground-truth relevant ids")
            }
            Self::InvalidCutoff => write!(f, "top_k cutoff must be greater than zero"),
        }
    }
}

impl std::error::Error for RetrievalError {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalDocument {
    pub id: String,
    pub text: String,
    #[serde(default)]
    pub source_id: Option<String>,
    #[serde(default)]
    pub embedding: Option<Vec<f32>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalHit {
    pub id: String,
    pub source_id: Option<String>,
    pub rank: usize,
    pub fused_score: f64,
    pub bm25_score: f64,
    pub bm25_rank: Option<usize>,
    pub dense_cosine: f64,
    pub dense_rank: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalQueryCase {
    pub query_id: String,
    pub query: String,
    #[serde(default)]
    pub query_embedding: Option<Vec<f32>>,
    #[serde(default)]
    pub relevant_ids: BTreeSet<String>,
    #[serde(default)]
    pub graded_relevance: BTreeMap<String, u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalBenchmark {
    pub benchmark_id: String,
    pub documents: Vec<RetrievalDocument>,
    pub queries: Vec<RetrievalQueryCase>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModeMetrics {
    pub mode: RetrievalMode,
    pub cutoff_k: usize,
    pub query_count: usize,
    pub mean_recall_at_k: f64,
    pub mean_precision_at_k: f64,
    pub mrr_at_k: f64,
    pub ndcg_at_k: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerQueryEval {
    pub query_id: String,
    pub bm25_ndcg: f64,
    pub dense_ndcg: f64,
    pub hybrid_rrf_ndcg: f64,
    pub bm25_top_id: Option<String>,
    pub dense_top_id: Option<String>,
    pub hybrid_rrf_top_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalEvalReport {
    pub benchmark_id: String,
    pub cutoff_k: usize,
    pub rrf_k: f64,
    pub document_count: usize,
    pub query_count: usize,
    pub bm25: ModeMetrics,
    pub dense: ModeMetrics,
    pub hybrid_rrf: ModeMetrics,
    pub rrf_ndcg_gain_vs_bm25: f64,
    pub rrf_ndcg_gain_vs_dense: f64,
    pub per_query: Vec<PerQueryEval>,
}

/// Builds searchable `RetrievalDocument` items from a `ReviewedBundle`.
pub fn documents_from_bundle(bundle: &ReviewedBundle) -> Vec<RetrievalDocument> {
    bundle
        .claims
        .iter()
        .map(|claim| {
            let mut text = format!("{} {} ", claim.subject, claim.claim_type);
            append_json_text(&claim.value, &mut text);
            RetrievalDocument {
                id: claim.id.clone(),
                text,
                source_id: claim.provenance.source_id.clone(),
                embedding: None,
            }
        })
        .collect()
}

/// Builds searchable `RetrievalDocument` items from ingested `DocumentChunk` records.
pub fn documents_from_chunks(chunks: &[DocumentChunk]) -> Vec<RetrievalDocument> {
    chunks
        .iter()
        .map(|chunk| RetrievalDocument {
            id: chunk.id.clone(),
            text: chunk.text.clone(),
            source_id: Some(chunk.source_id.clone()),
            embedding: None,
        })
        .collect()
}

/// Computes a deterministic L2-normalized signed count-sketch projection over
/// character 3-grams, 4-grams, and word unigrams/bigrams for offline dense fallback.
pub fn project_subword_embedding(text: &str, dim: usize) -> Vec<f32> {
    let dim = dim.max(16);
    let mut vec = vec![0.0f32; dim];
    let normalized = normalize_for_subwords(text);
    if normalized.is_empty() {
        return vec;
    }

    let chars: Vec<char> = format!("^{normalized}$").chars().collect();
    for n in [3usize, 4usize] {
        if chars.len() >= n {
            for window in chars.windows(n) {
                let mut gram = String::with_capacity(n * 2);
                gram.push_str("cg:");
                for ch in window {
                    gram.push(*ch);
                }
                accumulate_hashed_feature(&mut vec, gram.as_bytes(), 1.0);
            }
        }
    }

    let tokens = tokenize_lexical(text);
    for tok in &tokens {
        let feat = format!("w1:{tok}");
        accumulate_hashed_feature(&mut vec, feat.as_bytes(), 1.5);
    }
    for pair in tokens.windows(2) {
        let feat = format!("w2:{}_{}", pair[0], pair[1]);
        accumulate_hashed_feature(&mut vec, feat.as_bytes(), 1.25);
    }

    l2_normalize(&mut vec);
    vec
}

/// Ranks `ReviewedBundle` claims using BM25+, dense cosine similarity, or weighted RRF.
pub fn rank_bundle_claims(
    bundle: &ReviewedBundle,
    query: &str,
    mode: RetrievalMode,
    top_k: usize,
    config: &RetrievalConfig,
) -> Result<Vec<RetrievalHit>, RetrievalError> {
    let docs = documents_from_bundle(bundle);
    rank_documents(&docs, query, None, mode, top_k, config)
}

/// Ranks a corpus of `RetrievalDocument` entries with Okapi BM25+, dense cosine
/// similarity (caller-supplied embeddings or deterministic subword projection),
/// and weighted Reciprocal Rank Fusion (RRF).
pub fn rank_documents(
    docs: &[RetrievalDocument],
    query: &str,
    query_embedding: Option<&[f32]>,
    mode: RetrievalMode,
    top_k: usize,
    config: &RetrievalConfig,
) -> Result<Vec<RetrievalHit>, RetrievalError> {
    config.validate()?;
    if top_k == 0 {
        return Err(RetrievalError::InvalidCutoff);
    }
    if docs.is_empty() {
        return Err(RetrievalError::EmptyCorpus);
    }

    let mut seen_ids = BTreeSet::new();
    for doc in docs {
        if !seen_ids.insert(doc.id.as_str()) {
            return Err(RetrievalError::DuplicateDocumentId(doc.id.clone()));
        }
    }

    let bm25_scores = compute_bm25_plus_scores(docs, query, config);
    let dense_scores = compute_dense_cosine_scores(docs, query, query_embedding, config)?;

    // Build 1-indexed BM25 rank map over documents with positive lexical match.
    let mut bm25_order: Vec<usize> = (0..docs.len())
        .filter(|&idx| bm25_scores[idx] > 0.0)
        .collect();
    bm25_order.sort_by(|&a, &b| {
        cmp_f64_desc(bm25_scores[a], bm25_scores[b]).then_with(|| docs[a].id.cmp(&docs[b].id))
    });
    let mut bm25_ranks = vec![None; docs.len()];
    for (pos, &doc_idx) in bm25_order.iter().enumerate() {
        bm25_ranks[doc_idx] = Some(pos + 1);
    }

    // Build 1-indexed Dense rank map over documents with positive cosine similarity.
    let mut dense_order: Vec<usize> = (0..docs.len())
        .filter(|&idx| dense_scores[idx] > 0.0)
        .collect();
    dense_order.sort_by(|&a, &b| {
        cmp_f64_desc(dense_scores[a], dense_scores[b]).then_with(|| docs[a].id.cmp(&docs[b].id))
    });
    let mut dense_ranks = vec![None; docs.len()];
    for (pos, &doc_idx) in dense_order.iter().enumerate() {
        dense_ranks[doc_idx] = Some(pos + 1);
    }

    let mut candidates: Vec<RetrievalHit> = Vec::with_capacity(docs.len());
    for idx in 0..docs.len() {
        let b_score = bm25_scores[idx];
        let d_score = dense_scores[idx];
        let b_rank = bm25_ranks[idx];
        let d_rank = dense_ranks[idx];

        let fused = match mode {
            RetrievalMode::Bm25Only => b_score,
            RetrievalMode::DenseOnly => d_score,
            RetrievalMode::HybridRrf => {
                let mut rrf = 0.0;
                if let Some(r) = b_rank {
                    rrf += config.bm25_weight / (config.rrf_k + r as f64);
                }
                if let Some(r) = d_rank {
                    rrf += config.dense_weight / (config.rrf_k + r as f64);
                }
                rrf
            }
        };

        if fused > 0.0 {
            candidates.push(RetrievalHit {
                id: docs[idx].id.clone(),
                source_id: docs[idx].source_id.clone(),
                rank: 0,
                fused_score: fused,
                bm25_score: b_score,
                bm25_rank: b_rank,
                dense_cosine: d_score,
                dense_rank: d_rank,
            });
        }
    }

    candidates.sort_by(|a, b| {
        cmp_f64_desc(a.fused_score, b.fused_score)
            .then_with(|| cmp_f64_desc(a.bm25_score, b.bm25_score))
            .then_with(|| cmp_f64_desc(a.dense_cosine, b.dense_cosine))
            .then_with(|| a.id.cmp(&b.id))
    });
    candidates.truncate(top_k);
    for (idx, hit) in candidates.iter_mut().enumerate() {
        hit.rank = idx + 1;
    }

    Ok(candidates)
}

/// Evaluates BM25+, Dense, and Hybrid RRF retrieval side-by-side on a labeled benchmark.
pub fn evaluate_retrieval_benchmark(
    benchmark: &RetrievalBenchmark,
    cutoff_k: usize,
    config: &RetrievalConfig,
) -> Result<RetrievalEvalReport, RetrievalError> {
    config.validate()?;
    if cutoff_k == 0 {
        return Err(RetrievalError::InvalidCutoff);
    }
    if benchmark.documents.is_empty() {
        return Err(RetrievalError::EmptyCorpus);
    }
    if benchmark.queries.is_empty() {
        return Err(RetrievalError::EmptyBenchmarkQueries);
    }

    let mut bm25_acc = MetricAccumulator::default();
    let mut dense_acc = MetricAccumulator::default();
    let mut rrf_acc = MetricAccumulator::default();
    let mut per_query = Vec::with_capacity(benchmark.queries.len());

    for qcase in &benchmark.queries {
        let grades = effective_relevance_grades(qcase)?;
        let q_emb = qcase.query_embedding.as_deref();

        let bm25_hits = rank_documents(
            &benchmark.documents,
            &qcase.query,
            q_emb,
            RetrievalMode::Bm25Only,
            cutoff_k,
            config,
        )?;
        let dense_hits = rank_documents(
            &benchmark.documents,
            &qcase.query,
            q_emb,
            RetrievalMode::DenseOnly,
            cutoff_k,
            config,
        )?;
        let rrf_hits = rank_documents(
            &benchmark.documents,
            &qcase.query,
            q_emb,
            RetrievalMode::HybridRrf,
            cutoff_k,
            config,
        )?;

        let b_q = bm25_acc.record(&bm25_hits, &grades, cutoff_k);
        let d_q = dense_acc.record(&dense_hits, &grades, cutoff_k);
        let r_q = rrf_acc.record(&rrf_hits, &grades, cutoff_k);

        per_query.push(PerQueryEval {
            query_id: qcase.query_id.clone(),
            bm25_ndcg: b_q,
            dense_ndcg: d_q,
            hybrid_rrf_ndcg: r_q,
            bm25_top_id: bm25_hits.first().map(|h| h.id.clone()),
            dense_top_id: dense_hits.first().map(|h| h.id.clone()),
            hybrid_rrf_top_id: rrf_hits.first().map(|h| h.id.clone()),
        });
    }

    let qcount = benchmark.queries.len();
    let bm25 = bm25_acc.finish(RetrievalMode::Bm25Only, cutoff_k, qcount);
    let dense = dense_acc.finish(RetrievalMode::DenseOnly, cutoff_k, qcount);
    let hybrid_rrf = rrf_acc.finish(RetrievalMode::HybridRrf, cutoff_k, qcount);

    Ok(RetrievalEvalReport {
        benchmark_id: benchmark.benchmark_id.clone(),
        cutoff_k,
        rrf_k: config.rrf_k,
        document_count: benchmark.documents.len(),
        query_count: qcount,
        rrf_ndcg_gain_vs_bm25: round6(hybrid_rrf.ndcg_at_k - bm25.ndcg_at_k),
        rrf_ndcg_gain_vs_dense: round6(hybrid_rrf.ndcg_at_k - dense.ndcg_at_k),
        bm25,
        dense,
        hybrid_rrf,
        per_query,
    })
}

pub fn render_eval_summary(report: &RetrievalEvalReport) -> String {
    format!(
        "Benchmark {} ({} docs, {} queries, @{}, rrf_k={:.1}): BM25+ nDCG={:.4} MRR={:.4} Recall={:.4} | Dense nDCG={:.4} MRR={:.4} Recall={:.4} | Hybrid RRF nDCG={:.4} MRR={:.4} Recall={:.4} (gain vs BM25={:+.4}, vs Dense={:+.4})",
        report.benchmark_id,
        report.document_count,
        report.query_count,
        report.cutoff_k,
        report.rrf_k,
        report.bm25.ndcg_at_k,
        report.bm25.mrr_at_k,
        report.bm25.mean_recall_at_k,
        report.dense.ndcg_at_k,
        report.dense.mrr_at_k,
        report.dense.mean_recall_at_k,
        report.hybrid_rrf.ndcg_at_k,
        report.hybrid_rrf.mrr_at_k,
        report.hybrid_rrf.mean_recall_at_k,
        report.rrf_ndcg_gain_vs_bm25,
        report.rrf_ndcg_gain_vs_dense,
    )
}

pub fn render_eval_markdown(report: &RetrievalEvalReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# Retrieval Evaluation: {}\n\n",
        report.benchmark_id
    ));
    out.push_str(&format!(
        "- Documents: `{}`\n- Queries: `{}`\n- Cutoff: `@{}`\n- RRF constant `k`: `{:.1}`\n\n",
        report.document_count, report.query_count, report.cutoff_k, report.rrf_k
    ));
    out.push_str("| Mode | Recall@K | Precision@K | MRR@K | nDCG@K |\n");
    out.push_str("| :--- | ---: | ---: | ---: | ---: |\n");
    for m in [&report.bm25, &report.dense, &report.hybrid_rrf] {
        let label = match m.mode {
            RetrievalMode::Bm25Only => "BM25+",
            RetrievalMode::DenseOnly => "Dense Cosine",
            RetrievalMode::HybridRrf => "Hybrid RRF",
        };
        out.push_str(&format!(
            "| {} | {:.4} | {:.4} | {:.4} | {:.4} |\n",
            label, m.mean_recall_at_k, m.mean_precision_at_k, m.mrr_at_k, m.ndcg_at_k
        ));
    }
    out.push_str(&format!(
        "\nHybrid RRF nDCG@{} delta: `{:+.4}` vs BM25+, `{:+.4}` vs Dense.\n",
        report.cutoff_k, report.rrf_ndcg_gain_vs_bm25, report.rrf_ndcg_gain_vs_dense
    ));
    out
}

#[derive(Default)]
struct MetricAccumulator {
    recall_sum: f64,
    precision_sum: f64,
    mrr_sum: f64,
    ndcg_sum: f64,
}

impl MetricAccumulator {
    fn record(
        &mut self,
        hits: &[RetrievalHit],
        grades: &BTreeMap<String, u8>,
        cutoff_k: usize,
    ) -> f64 {
        let total_relevant = grades.values().filter(|&&g| g > 0).count();
        let mut matched_relevant = 0usize;
        let mut rr = 0.0f64;
        let mut dcg = 0.0f64;

        for (idx, hit) in hits.iter().take(cutoff_k).enumerate() {
            let rel = grades.get(&hit.id).copied().unwrap_or(0);
            if rel > 0 {
                matched_relevant += 1;
                if rr == 0.0 {
                    rr = 1.0 / ((idx + 1) as f64);
                }
                let gain = ((1u32 << rel.min(15)) - 1) as f64;
                let discount = ((idx + 2) as f64).log2();
                dcg += gain / discount;
            }
        }

        let mut ideal_grades: Vec<u8> = grades.values().copied().filter(|&g| g > 0).collect();
        ideal_grades.sort_by(|a, b| b.cmp(a));
        let mut idcg = 0.0f64;
        for (idx, rel) in ideal_grades.into_iter().take(cutoff_k).enumerate() {
            let gain = ((1u32 << rel.min(15)) - 1) as f64;
            let discount = ((idx + 2) as f64).log2();
            idcg += gain / discount;
        }

        let recall = if total_relevant > 0 {
            (matched_relevant as f64) / (total_relevant as f64)
        } else {
            0.0
        };
        let precision = (matched_relevant as f64) / (cutoff_k as f64);
        let ndcg = if idcg > 0.0 { dcg / idcg } else { 0.0 };

        self.recall_sum += recall;
        self.precision_sum += precision;
        self.mrr_sum += rr;
        self.ndcg_sum += ndcg;
        round6(ndcg)
    }

    fn finish(self, mode: RetrievalMode, cutoff_k: usize, query_count: usize) -> ModeMetrics {
        let denom = (query_count.max(1)) as f64;
        ModeMetrics {
            mode,
            cutoff_k,
            query_count,
            mean_recall_at_k: round6(self.recall_sum / denom),
            mean_precision_at_k: round6(self.precision_sum / denom),
            mrr_at_k: round6(self.mrr_sum / denom),
            ndcg_at_k: round6(self.ndcg_sum / denom),
        }
    }
}

fn effective_relevance_grades(
    qcase: &RetrievalQueryCase,
) -> Result<BTreeMap<String, u8>, RetrievalError> {
    let mut grades = BTreeMap::new();
    for id in &qcase.relevant_ids {
        grades.insert(id.clone(), 1);
    }
    for (id, &grade) in &qcase.graded_relevance {
        if grade > 0 {
            grades.insert(id.clone(), grade);
        }
    }
    if grades.is_empty() {
        return Err(RetrievalError::EmptyRelevantSet(qcase.query_id.clone()));
    }
    Ok(grades)
}

fn compute_bm25_plus_scores(
    docs: &[RetrievalDocument],
    query: &str,
    config: &RetrievalConfig,
) -> Vec<f64> {
    let query_terms = unique_ordered_terms(&tokenize_lexical(query));
    if query_terms.is_empty() {
        return vec![0.0; docs.len()];
    }

    let mut doc_term_counts: Vec<BTreeMap<String, usize>> = Vec::with_capacity(docs.len());
    let mut doc_lengths: Vec<usize> = Vec::with_capacity(docs.len());
    let mut df: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_len = 0usize;

    for doc in docs {
        let tokens = tokenize_lexical(&doc.text);
        total_len += tokens.len();
        doc_lengths.push(tokens.len());

        let mut counts = BTreeMap::new();
        for tok in tokens {
            *counts.entry(tok).or_insert(0) += 1;
        }
        for unique_tok in counts.keys() {
            *df.entry(unique_tok.clone()).or_insert(0) += 1;
        }
        doc_term_counts.push(counts);
    }

    let n_docs = docs.len() as f64;
    let avgdl = if total_len > 0 {
        (total_len as f64) / n_docs
    } else {
        1.0
    };

    let mut scores = vec![0.0f64; docs.len()];
    for term in &query_terms {
        let n_qi = df.get(term).copied().unwrap_or(0) as f64;
        if n_qi == 0.0 {
            continue;
        }
        let idf = (1.0 + (n_docs - n_qi + 0.5) / (n_qi + 0.5)).ln();
        if idf <= 0.0 {
            continue;
        }
        for (idx, counts) in doc_term_counts.iter().enumerate() {
            let tf = counts.get(term).copied().unwrap_or(0) as f64;
            if tf <= 0.0 {
                continue;
            }
            let dl = doc_lengths[idx] as f64;
            let norm_denom =
                tf + config.bm25_k1 * (1.0 - config.bm25_b + config.bm25_b * (dl / avgdl));
            let tf_component = if norm_denom > 0.0 {
                (tf * (config.bm25_k1 + 1.0)) / norm_denom
            } else {
                0.0
            };
            scores[idx] += idf * (tf_component + config.bm25_delta);
        }
    }
    scores
}

fn compute_dense_cosine_scores(
    docs: &[RetrievalDocument],
    query: &str,
    query_embedding: Option<&[f32]>,
    config: &RetrievalConfig,
) -> Result<Vec<f64>, RetrievalError> {
    let any_explicit = query_embedding.is_some() || docs.iter().any(|d| d.embedding.is_some());

    if any_explicit {
        let q_raw = query_embedding.ok_or_else(|| RetrievalError::DimensionMismatch {
            expected: docs
                .iter()
                .find_map(|d| d.embedding.as_ref().map(Vec::len))
                .unwrap_or(0),
            actual: 0,
            target_id: "query".to_owned(),
        })?;
        if q_raw.is_empty() {
            return Err(RetrievalError::DimensionMismatch {
                expected: 1,
                actual: 0,
                target_id: "query".to_owned(),
            });
        }
        let q_vec = normalize_checked_embedding(q_raw, "query")?;
        let dim = q_vec.len();

        let mut scores = Vec::with_capacity(docs.len());
        for doc in docs {
            let d_raw =
                doc.embedding
                    .as_deref()
                    .ok_or_else(|| RetrievalError::DimensionMismatch {
                        expected: dim,
                        actual: 0,
                        target_id: doc.id.clone(),
                    })?;
            if d_raw.len() != dim {
                return Err(RetrievalError::DimensionMismatch {
                    expected: dim,
                    actual: d_raw.len(),
                    target_id: doc.id.clone(),
                });
            }
            let d_vec = normalize_checked_embedding(d_raw, &doc.id)?;
            scores.push(dot_f32(&q_vec, &d_vec).max(0.0));
        }
        Ok(scores)
    } else {
        let dim = config.fallback_dense_dim;
        let q_vec = project_subword_embedding(query, dim);
        let mut scores = Vec::with_capacity(docs.len());
        for doc in docs {
            let d_vec = project_subword_embedding(&doc.text, dim);
            scores.push(dot_f32(&q_vec, &d_vec).max(0.0));
        }
        Ok(scores)
    }
}

fn normalize_checked_embedding(raw: &[f32], id: &str) -> Result<Vec<f32>, RetrievalError> {
    let mut copy = Vec::with_capacity(raw.len());
    for &v in raw {
        if !v.is_finite() {
            return Err(RetrievalError::NonFiniteEmbedding(id.to_owned()));
        }
        copy.push(v);
    }
    l2_normalize(&mut copy);
    Ok(copy)
}

fn l2_normalize(vec: &mut [f32]) {
    let mut sum_sq = 0.0f64;
    for &v in vec.iter() {
        let vf = v as f64;
        sum_sq += vf * vf;
    }
    let norm = sum_sq.sqrt();
    if norm > 0.0 {
        for v in vec.iter_mut() {
            *v = ((*v as f64) / norm) as f32;
        }
    }
}

fn dot_f32(a: &[f32], b: &[f32]) -> f64 {
    let mut acc = 0.0f64;
    for (&x, &y) in a.iter().zip(b.iter()) {
        acc += (x as f64) * (y as f64);
    }
    acc.clamp(-1.0, 1.0)
}

fn accumulate_hashed_feature(vec: &mut [f32], bytes: &[u8], weight: f32) {
    // 64-bit FNV-1a with SplitMix64 finalizer for low-collision index + Rademacher sign.
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h ^= h >> 30;
    h = h.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^= h >> 27;
    h = h.wrapping_mul(0x94d049bb133111eb);
    h ^= h >> 31;

    let bucket = (h as usize) % vec.len();
    let sign = if (h >> 63) == 0 { 1.0f32 } else { -1.0f32 };
    vec[bucket] += sign * weight;
}

fn normalize_for_subwords(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev_space = true;
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            for lc in ch.to_lowercase() {
                out.push(lc);
            }
            prev_space = false;
        } else if !prev_space {
            out.push(' ');
            prev_space = true;
        }
    }
    out.trim().to_owned()
}

fn tokenize_lexical(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            for lc in ch.to_lowercase() {
                cur.push(lc);
            }
        } else if !cur.is_empty() {
            if cur.len() >= 2 && !is_stopword(&cur) {
                tokens.push(cur.clone());
            }
            cur.clear();
        }
    }
    if cur.len() >= 2 && !is_stopword(&cur) {
        tokens.push(cur);
    }
    tokens
}

fn unique_ordered_terms(tokens: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for t in tokens {
        if seen.insert(t.clone()) {
            out.push(t.clone());
        }
    }
    out
}

fn is_stopword(word: &str) -> bool {
    matches!(
        word,
        "the"
            | "and"
            | "for"
            | "with"
            | "that"
            | "this"
            | "from"
            | "are"
            | "was"
            | "were"
            | "into"
            | "onto"
    )
}

fn append_json_text(val: &Value, out: &mut String) {
    match val {
        Value::String(s) => {
            out.push_str(s);
            out.push(' ');
        }
        Value::Number(n) => {
            out.push_str(&n.to_string());
            out.push(' ');
        }
        Value::Bool(b) => {
            out.push_str(if *b { "true " } else { "false " });
        }
        Value::Array(items) => {
            for item in items {
                append_json_text(item, out);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                out.push_str(k);
                out.push(' ');
                append_json_text(v, out);
            }
        }
        Value::Null => {}
    }
}

fn cmp_f64_desc(a: f64, b: f64) -> Ordering {
    b.partial_cmp(&a).unwrap_or(Ordering::Equal)
}

fn round6(val: f64) -> f64 {
    (val * 1_000_000.0).round() / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_rrf_outperforms_single_modality_baselines_on_mixed_queries() {
        // Construct a realistic mixed retrieval benchmark:
        // - Query 1 relies on exact rare error/ticket identifier where lexical BM25 excels
        //   while dense embeddings place a generic distractor ahead.
        // - Query 2 uses semantic paraphrase / morphological phrasing where dense cosine excels
        //   while exact word overlap is zero.
        let docs = vec![
            RetrievalDocument {
                id: "doc:err-4091".into(),
                text: "Incident ticket ERR4091X replication manifest checksum mismatch".into(),
                source_id: Some("src:ops".into()),
                embedding: Some(vec![0.55, 0.80, 0.0, 0.0]),
            },
            RetrievalDocument {
                id: "doc:generic-ops".into(),
                text: "General operational runbook for routine service status".into(),
                source_id: Some("src:ops".into()),
                embedding: Some(vec![0.95, 0.30, 0.0, 0.0]),
            },
            RetrievalDocument {
                id: "doc:semantic-kms".into(),
                text: "Envelope key rotation schedule for customer vaults".into(),
                source_id: Some("src:sec".into()),
                embedding: Some(vec![0.0, 0.0, 0.98, 0.15]),
            },
            RetrievalDocument {
                id: "doc:distractor-kms".into(),
                text: "Quarterly compliance checklist overview".into(),
                source_id: Some("src:sec".into()),
                embedding: Some(vec![0.0, 0.10, 0.25, 0.96]),
            },
        ];

        let queries = vec![
            RetrievalQueryCase {
                query_id: "q:exact-code".into(),
                query: "ERR4091X".into(),
                query_embedding: Some(vec![0.98, 0.20, 0.0, 0.0]),
                relevant_ids: BTreeSet::from(["doc:err-4091".to_owned()]),
                graded_relevance: BTreeMap::new(),
            },
            RetrievalQueryCase {
                query_id: "q:paraphrase".into(),
                query: "cryptographic master secret rollover cadence".into(),
                query_embedding: Some(vec![0.0, 0.0, 0.99, 0.10]),
                relevant_ids: BTreeSet::from(["doc:semantic-kms".to_owned()]),
                graded_relevance: BTreeMap::new(),
            },
        ];

        let benchmark = RetrievalBenchmark {
            benchmark_id: "bench:hybrid-v1".into(),
            documents: docs,
            queries,
        };

        let report =
            evaluate_retrieval_benchmark(&benchmark, 3, &RetrievalConfig::default()).unwrap();
        assert!(
            report.hybrid_rrf.ndcg_at_k > report.bm25.ndcg_at_k,
            "expected Hybrid RRF nDCG ({}) > BM25 nDCG ({})",
            report.hybrid_rrf.ndcg_at_k,
            report.bm25.ndcg_at_k
        );
        assert!(
            report.hybrid_rrf.ndcg_at_k > report.dense.ndcg_at_k,
            "expected Hybrid RRF nDCG ({}) > Dense nDCG ({})",
            report.hybrid_rrf.ndcg_at_k,
            report.dense.ndcg_at_k
        );
        assert_eq!(report.hybrid_rrf.mean_recall_at_k, 1.0);
        assert_eq!(report.hybrid_rrf.mrr_at_k, 1.0);
    }

    #[test]
    fn offline_subword_projection_recovers_morphological_variants_without_external_vectors() {
        let docs = vec![
            RetrievalDocument {
                id: "doc:crypto".into(),
                text: "Cryptographic attestation verifies detached signatures offline".into(),
                source_id: None,
                embedding: None,
            },
            RetrievalDocument {
                id: "doc:billing".into(),
                text: "Monthly invoice reconciliation and seat accounting".into(),
                source_id: None,
                embedding: None,
            },
        ];

        let hits = rank_documents(
            &docs,
            "cryptography signature attesting",
            None,
            RetrievalMode::HybridRrf,
            2,
            &RetrievalConfig::default(),
        )
        .unwrap();
        assert_eq!(hits[0].id, "doc:crypto");
        assert_eq!(hits[0].rank, 1);
    }

    #[test]
    fn rejects_mismatched_or_non_finite_embeddings_fail_closed() {
        let docs = vec![RetrievalDocument {
            id: "doc:1".into(),
            text: "alpha beta".into(),
            source_id: None,
            embedding: Some(vec![1.0, 0.0, 0.0]),
        }];
        let err = rank_documents(
            &docs,
            "alpha",
            Some(&[1.0, 0.0]),
            RetrievalMode::DenseOnly,
            1,
            &RetrievalConfig::default(),
        )
        .unwrap_err();
        assert!(matches!(err, RetrievalError::DimensionMismatch { .. }));

        let nan_docs = vec![RetrievalDocument {
            id: "doc:nan".into(),
            text: "alpha beta".into(),
            source_id: None,
            embedding: Some(vec![f32::NAN, 1.0]),
        }];
        let nan_err = rank_documents(
            &nan_docs,
            "alpha",
            Some(&[0.5, 0.5]),
            RetrievalMode::DenseOnly,
            1,
            &RetrievalConfig::default(),
        )
        .unwrap_err();
        assert_eq!(
            nan_err,
            RetrievalError::NonFiniteEmbedding("doc:nan".into())
        );
    }
}
