use crate::{
    assess_completeness, validate_canonical_timestamp, BundleDraft, Claim, ClaimStatus,
    CompletenessReport, DomainError, RequiredField, Sensitivity, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const TEMPLATE_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowTemplate {
    WarrantyInsurance,
    MedicalVisit,
    ProjectHandoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalizedText {
    pub vi: &'static str,
    pub en: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateField {
    pub claim_type: &'static str,
    pub label: LocalizedText,
    pub question: LocalizedText,
    pub required: bool,
    pub priority: u8,
    pub default_sensitivity: Sensitivity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateManifest {
    pub schema_version: u16,
    pub id: &'static str,
    pub version: u16,
    pub title: LocalizedText,
    pub disclaimer: LocalizedText,
    pub fields: &'static [TemplateField],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingQuestion {
    pub claim_type: String,
    pub priority: u8,
    pub vi: String,
    pub en: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionScore {
    pub confirmed_required: usize,
    pub total_required: usize,
    pub percent: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionResult {
    pub template_id: String,
    pub template_version: u16,
    pub subject: String,
    pub draft: Option<BundleDraft>,
    pub completeness: CompletenessReport,
    pub score: CompositionScore,
    pub missing_questions: Vec<MissingQuestion>,
    pub expired_claim_ids: Vec<String>,
    pub candidate_claim_ids: Vec<String>,
}

pub fn manifest(workflow: WorkflowTemplate) -> &'static TemplateManifest {
    match workflow {
        WorkflowTemplate::WarrantyInsurance => &WARRANTY,
        WorkflowTemplate::MedicalVisit => &MEDICAL,
        WorkflowTemplate::ProjectHandoff => &PROJECT,
    }
}

pub fn compose(
    workflow: WorkflowTemplate,
    bundle_id: &str,
    subject: &str,
    claims: &[Claim],
    as_of: &str,
) -> Result<CompositionResult, DomainError> {
    validate_canonical_timestamp(as_of, "as_of")?;
    if bundle_id.trim().is_empty() {
        return Err(DomainError::EmptyField("bundle_id"));
    }
    if subject.trim().is_empty() {
        return Err(DomainError::EmptyField("subject"));
    }
    for claim in claims {
        claim.validate()?;
    }

    let template = manifest(workflow);
    let field_types: BTreeSet<_> = template
        .fields
        .iter()
        .map(|field| field.claim_type)
        .collect();
    let relevant: Vec<_> = claims
        .iter()
        .filter(|claim| claim.subject == subject && field_types.contains(claim.claim_type.as_str()))
        .cloned()
        .collect();
    let expired_claim_ids: Vec<_> = relevant
        .iter()
        .filter(|claim| is_expired(claim, as_of))
        .map(|claim| claim.id.clone())
        .collect();
    let usable: Vec<_> = relevant
        .iter()
        .filter(|claim| !is_expired(claim, as_of))
        .cloned()
        .collect();
    let required: Vec<_> = template
        .fields
        .iter()
        .filter(|field| field.required)
        .map(|field| RequiredField {
            claim_type: field.claim_type.to_owned(),
            subject: subject.to_owned(),
        })
        .collect();
    let completeness = assess_completeness(&required, &usable);
    let missing_types: BTreeSet<_> = completeness
        .missing
        .iter()
        .map(|field| field.claim_type.as_str())
        .collect();
    let mut missing_questions: Vec<_> = template
        .fields
        .iter()
        .filter(|field| field.required && missing_types.contains(field.claim_type))
        .map(|field| MissingQuestion {
            claim_type: field.claim_type.to_owned(),
            priority: field.priority,
            vi: field.question.vi.to_owned(),
            en: field.question.en.to_owned(),
        })
        .collect();
    missing_questions.sort_by_key(|question| question.priority);

    let selected_ids: Vec<_> = usable
        .iter()
        .filter(|claim| claim.status == ClaimStatus::Confirmed)
        .filter(|claim| {
            !completeness
                .conflicts
                .iter()
                .any(|conflict| conflict.claim_ids.contains(&claim.id))
        })
        .map(|claim| claim.id.clone())
        .collect();
    let candidate_claim_ids = usable
        .iter()
        .filter(|claim| claim.status == ClaimStatus::Candidate)
        .map(|claim| claim.id.clone())
        .collect();
    let total_required = required.len();
    let confirmed_required = total_required.saturating_sub(completeness.missing.len());
    let percent = (confirmed_required * 100)
        .checked_div(total_required)
        .unwrap_or(100) as u8;
    let draft = if selected_ids.is_empty() {
        None
    } else {
        Some(BundleDraft {
            schema_version: SCHEMA_VERSION,
            id: bundle_id.to_owned(),
            purpose: template.title.en.to_owned(),
            claim_ids: selected_ids,
            expires_at: None,
        })
    };
    Ok(CompositionResult {
        template_id: template.id.to_owned(),
        template_version: template.version,
        subject: subject.to_owned(),
        draft,
        completeness,
        score: CompositionScore {
            confirmed_required,
            total_required,
            percent,
        },
        missing_questions,
        expired_claim_ids,
        candidate_claim_ids,
    })
}

fn is_expired(claim: &Claim, as_of: &str) -> bool {
    claim
        .validity
        .valid_until
        .as_deref()
        .is_some_and(|until| until <= as_of)
}

const fn text(vi: &'static str, en: &'static str) -> LocalizedText {
    LocalizedText { vi, en }
}

const WARRANTY_FIELDS: [TemplateField; 6] = [
    TemplateField {
        claim_type: "product.name",
        label: text("Sản phẩm", "Product"),
        question: text("Sản phẩm cần hỗ trợ là gì?", "Which product needs support?"),
        required: true,
        priority: 1,
        default_sensitivity: Sensitivity::Internal,
    },
    TemplateField {
        claim_type: "purchase.date",
        label: text("Ngày mua", "Purchase date"),
        question: text(
            "Sản phẩm được mua ngày nào?",
            "When was the product purchased?",
        ),
        required: true,
        priority: 2,
        default_sensitivity: Sensitivity::Private,
    },
    TemplateField {
        claim_type: "issue.summary",
        label: text("Sự cố", "Issue"),
        question: text("Điều gì đã xảy ra?", "What happened?"),
        required: true,
        priority: 3,
        default_sensitivity: Sensitivity::Private,
    },
    TemplateField {
        claim_type: "seller.name",
        label: text("Nơi bán", "Seller"),
        question: text("Sản phẩm được mua ở đâu?", "Where was it purchased?"),
        required: false,
        priority: 5,
        default_sensitivity: Sensitivity::Internal,
    },
    TemplateField {
        claim_type: "product.serial",
        label: text("Số serial", "Serial number"),
        question: text("Số serial là gì?", "What is the serial number?"),
        required: false,
        priority: 6,
        default_sensitivity: Sensitivity::Private,
    },
    TemplateField {
        claim_type: "purchase.amount",
        label: text("Giá mua", "Purchase amount"),
        question: text("Giá mua là bao nhiêu?", "What was the purchase amount?"),
        required: false,
        priority: 7,
        default_sensitivity: Sensitivity::Private,
    },
];

const MEDICAL_FIELDS: [TemplateField; 6] = [
    TemplateField {
        claim_type: "person.name",
        label: text("Họ tên", "Name"),
        question: text("Hồ sơ này dành cho ai?", "Who is this pack for?"),
        required: true,
        priority: 1,
        default_sensitivity: Sensitivity::Private,
    },
    TemplateField {
        claim_type: "visit.reason",
        label: text("Lý do buổi khám", "Visit reason"),
        question: text(
            "Bạn muốn trao đổi điều gì trong buổi khám?",
            "What would you like to discuss at the visit?",
        ),
        required: true,
        priority: 2,
        default_sensitivity: Sensitivity::HighlySensitive,
    },
    TemplateField {
        claim_type: "medication.current",
        label: text("Thuốc đang dùng", "Current medications"),
        question: text(
            "Bạn đang dùng thuốc nào theo thông tin hiện có?",
            "Which medications are you currently taking, based on your records?",
        ),
        required: true,
        priority: 3,
        default_sensitivity: Sensitivity::HighlySensitive,
    },
    TemplateField {
        claim_type: "allergy.known",
        label: text("Dị ứng đã biết", "Known allergies"),
        question: text(
            "Hồ sơ hiện có ghi nhận dị ứng nào?",
            "Which allergies are recorded in your documents?",
        ),
        required: true,
        priority: 4,
        default_sensitivity: Sensitivity::HighlySensitive,
    },
    TemplateField {
        claim_type: "symptom.timeline",
        label: text("Diễn tiến", "Symptom timeline"),
        question: text(
            "Các mốc diễn tiến được ghi nhận là gì?",
            "Which timeline events are documented?",
        ),
        required: false,
        priority: 5,
        default_sensitivity: Sensitivity::HighlySensitive,
    },
    TemplateField {
        claim_type: "provider.contact",
        label: text("Nơi khám", "Provider"),
        question: text(
            "Thông tin liên hệ nơi khám là gì?",
            "What is the provider contact information?",
        ),
        required: false,
        priority: 6,
        default_sensitivity: Sensitivity::Private,
    },
];

const PROJECT_FIELDS: [TemplateField; 6] = [
    TemplateField {
        claim_type: "project.goal",
        label: text("Mục tiêu", "Goal"),
        question: text(
            "Mục tiêu hiện tại của dự án là gì?",
            "What is the current project goal?",
        ),
        required: true,
        priority: 1,
        default_sensitivity: Sensitivity::Internal,
    },
    TemplateField {
        claim_type: "project.status",
        label: text("Trạng thái", "Status"),
        question: text(
            "Trạng thái đã xác nhận gần nhất là gì?",
            "What is the latest confirmed status?",
        ),
        required: true,
        priority: 2,
        default_sensitivity: Sensitivity::Internal,
    },
    TemplateField {
        claim_type: "project.next_step",
        label: text("Bước tiếp theo", "Next step"),
        question: text(
            "Bước tiếp theo đã thống nhất là gì?",
            "What next step was agreed?",
        ),
        required: true,
        priority: 3,
        default_sensitivity: Sensitivity::Internal,
    },
    TemplateField {
        claim_type: "contact.primary",
        label: text("Đầu mối", "Primary contact"),
        question: text("Ai là đầu mối chính?", "Who is the primary contact?"),
        required: false,
        priority: 4,
        default_sensitivity: Sensitivity::Private,
    },
    TemplateField {
        claim_type: "deadline.next",
        label: text("Mốc tiếp theo", "Next deadline"),
        question: text(
            "Mốc thời gian tiếp theo là khi nào?",
            "When is the next deadline?",
        ),
        required: false,
        priority: 5,
        default_sensitivity: Sensitivity::Internal,
    },
    TemplateField {
        claim_type: "decision.open",
        label: text("Quyết định còn mở", "Open decision"),
        question: text(
            "Quyết định nào còn chờ xử lý?",
            "Which decisions remain open?",
        ),
        required: false,
        priority: 6,
        default_sensitivity: Sensitivity::Internal,
    },
];

static WARRANTY: TemplateManifest = TemplateManifest {
    schema_version: TEMPLATE_SCHEMA_VERSION,
    id: "warranty-insurance",
    version: 1,
    title: text("Hồ sơ bảo hành hoặc bảo hiểm", "Warranty or insurance pack"),
    disclaimer: text(
        "Hồ sơ tổng hợp thông tin, không xác nhận quyền được bồi thường.",
        "This pack organizes records; it does not determine coverage or eligibility.",
    ),
    fields: &WARRANTY_FIELDS,
};

static MEDICAL: TemplateManifest = TemplateManifest {
    schema_version: TEMPLATE_SCHEMA_VERSION,
    id: "medical-visit",
    version: 1,
    title: text(
        "Thông tin chuẩn bị cho buổi khám",
        "Medical visit information pack",
    ),
    disclaimer: text(
        "Hồ sơ không thay thế tư vấn, chẩn đoán hoặc hướng dẫn y khoa.",
        "This pack does not provide medical advice, diagnosis, or treatment guidance.",
    ),
    fields: &MEDICAL_FIELDS,
};

static PROJECT: TemplateManifest = TemplateManifest {
    schema_version: TEMPLATE_SCHEMA_VERSION,
    id: "project-handoff",
    version: 1,
    title: text("Hồ sơ bàn giao dự án", "Project handoff pack"),
    disclaimer: text(
        "Hồ sơ phản ánh dữ kiện đã chọn và nguồn của chúng.",
        "This pack reflects selected claims and their sources.",
    ),
    fields: &PROJECT_FIELDS,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Provenance, SourceLocator, SourceProvenance, ValidityWindow};
    use serde_json::Value;

    const NOW: &str = "2026-09-11T00:00:00Z";
    fn claim(id: &str, claim_type: &str, status: ClaimStatus) -> Claim {
        Claim {
            schema_version: SCHEMA_VERSION,
            id: id.into(),
            claim_type: claim_type.into(),
            subject: "project:1".into(),
            value: Value::String(id.into()),
            status,
            provenance: Provenance::Source(SourceProvenance {
                source_id: "source:1".into(),
                locator: SourceLocator::Span { start: 0, end: 1 },
                extractor: None,
            }),
            captured_at: NOW.into(),
            validity: ValidityWindow::default(),
            sensitivity: Sensitivity::Internal,
            revision: 1,
        }
    }

    #[test]
    fn all_three_templates_are_versioned_and_bilingual() {
        for workflow in [
            WorkflowTemplate::WarrantyInsurance,
            WorkflowTemplate::MedicalVisit,
            WorkflowTemplate::ProjectHandoff,
        ] {
            let value = manifest(workflow);
            assert_eq!(value.schema_version, TEMPLATE_SCHEMA_VERSION);
            assert!(!value.title.vi.is_empty() && !value.title.en.is_empty());
            assert!(!value.disclaimer.vi.is_empty() && !value.disclaimer.en.is_empty());
            assert!(value.fields.iter().any(|field| field.required));
        }
    }

    #[test]
    fn incomplete_project_pack_has_ranked_minimal_questions() {
        let result = compose(
            WorkflowTemplate::ProjectHandoff,
            "bundle:1",
            "project:1",
            &[],
            NOW,
        )
        .unwrap();
        assert_eq!(result.score.percent, 0);
        assert_eq!(result.missing_questions.len(), 3);
        assert!(result
            .missing_questions
            .windows(2)
            .all(|pair| pair[0].priority <= pair[1].priority));
        assert!(result.draft.is_none());
    }

    #[test]
    fn confirmed_fields_create_explainable_complete_draft() {
        let claims = [
            claim("goal", "project.goal", ClaimStatus::Confirmed),
            claim("status", "project.status", ClaimStatus::Confirmed),
            claim("next", "project.next_step", ClaimStatus::Confirmed),
        ];
        let result = compose(
            WorkflowTemplate::ProjectHandoff,
            "bundle:1",
            "project:1",
            &claims,
            NOW,
        )
        .unwrap();
        assert!(result.completeness.complete);
        assert_eq!(
            result.score,
            CompositionScore {
                confirmed_required: 3,
                total_required: 3,
                percent: 100
            }
        );
        assert_eq!(result.draft.unwrap().claim_ids.len(), 3);
    }

    #[test]
    fn candidates_and_expired_claims_are_never_selected() {
        let mut expired = claim("goal", "project.goal", ClaimStatus::Confirmed);
        expired.validity.valid_until = Some(NOW.into());
        let candidate = claim("status", "project.status", ClaimStatus::Candidate);
        let result = compose(
            WorkflowTemplate::ProjectHandoff,
            "bundle:1",
            "project:1",
            &[expired, candidate],
            NOW,
        )
        .unwrap();
        assert_eq!(result.expired_claim_ids, vec!["goal"]);
        assert_eq!(result.candidate_claim_ids, vec!["status"]);
        assert!(result.draft.is_none());
    }

    #[test]
    fn conflict_remains_visible_and_excluded() {
        let mut one = claim("status:1", "project.status", ClaimStatus::Confirmed);
        let mut two = claim("status:2", "project.status", ClaimStatus::Confirmed);
        one.value = Value::String("green".into());
        two.value = Value::String("red".into());
        let result = compose(
            WorkflowTemplate::ProjectHandoff,
            "bundle:1",
            "project:1",
            &[one, two],
            NOW,
        )
        .unwrap();
        assert_eq!(result.completeness.conflicts.len(), 1);
        assert!(result.draft.is_none());
    }
}
