pub mod parser;
pub mod rules;

pub use parser::parse;
pub use rules::{lint, Finding, Severity};

/// Renders findings as the plain-text report the CLI prints. Pulled out of
/// `main` so it's independently testable and reusable (e.g. from a test
/// harness that wants the exact string a run would have produced).
pub fn render(findings: &[Finding], path_label: &str) -> String {
    let mut out = String::new();
    if findings.is_empty() {
        out.push_str(&format!("{path_label}: clean, no findings\n"));
        return out;
    }

    out.push_str(&format!("{path_label}: {} finding(s)\n\n", findings.len()));
    for f in findings {
        out.push_str(&format!(
            "[{}] {} — {} ({})\n    {}\n",
            f.severity, f.rule, f.context, f.line, f.message
        ));
    }

    let errors = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    let warnings = findings.len() - errors;
    out.push_str(&format!("\n{errors} error(s), {warnings} warning(s)\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_clean_config_reports_clean() {
        let out = render(&[], "test.conf");
        assert!(out.contains("clean"));
    }

    #[test]
    fn render_counts_errors_and_warnings_separately() {
        let findings = vec![
            Finding {
                rule: "r1",
                severity: Severity::Error,
                line: 1,
                context: "ctx".into(),
                message: "msg".into(),
            },
            Finding {
                rule: "r2",
                severity: Severity::Warning,
                line: 2,
                context: "ctx".into(),
                message: "msg".into(),
            },
        ];
        let out = render(&findings, "test.conf");
        assert!(out.contains("1 error(s), 1 warning(s)"));
    }
}
