//! The five lint rules, each operating on a single `server` block (plus
//! everything nested under it — `location`s, mostly).

use crate::parser::{
    find_blocks_recursive, find_directives_direct, find_directives_recursive, Item,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warning,
    Error,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Warning => write!(f, "warning"),
            Severity::Error => write!(f, "error"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub line: usize,
    pub context: String,
    pub message: String,
}

const OLD_TLS_VERSIONS: [&str; 3] = ["SSLv2", "SSLv3", "TLSv1"];
const WEAK_TLS_VERSIONS: [&str; 4] = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"];

fn server_context(server_name_args: &[String], line: usize) -> String {
    if server_name_args.is_empty() {
        format!("server (line {line}, no server_name)")
    } else {
        format!("server {} (line {line})", server_name_args.join(" "))
    }
}

fn server_names(body: &[Item]) -> Vec<String> {
    find_directives_direct(body, "server_name")
        .into_iter()
        .flat_map(|d| d.args.clone())
        .collect()
}

fn server_listens_ssl(body: &[Item]) -> bool {
    find_directives_direct(body, "listen")
        .iter()
        .any(|d| d.args.iter().any(|a| a == "ssl"))
        || !find_directives_direct(body, "ssl_certificate").is_empty()
}

/// Rule 1: missing security-relevant `add_header` directives.
pub fn check_missing_security_headers(server_body: &[Item], line: usize) -> Vec<Finding> {
    let names = server_names(server_body);
    let ctx = server_context(&names, line);
    let headers_present: Vec<String> = find_directives_recursive(server_body, "add_header")
        .iter()
        .filter_map(|d| d.args.first())
        .map(|s| s.to_ascii_lowercase())
        .collect();

    let mut findings = Vec::new();
    for required in ["x-frame-options", "x-content-type-options"] {
        if !headers_present.iter().any(|h| h == required) {
            findings.push(Finding {
                rule: "missing-security-header",
                severity: Severity::Warning,
                line,
                context: ctx.clone(),
                message: format!(
                    "no `add_header {}` found anywhere in this server block or its locations",
                    match required {
                        "x-frame-options" => "X-Frame-Options",
                        _ => "X-Content-Type-Options",
                    }
                ),
            });
        }
    }
    findings
}

/// Rule 2: `server_tokens on;` (explicit), which leaks the nginx version
/// in error pages and the `Server` response header.
pub fn check_server_tokens(items: &[Item]) -> Vec<Finding> {
    find_directives_recursive(items, "server_tokens")
        .into_iter()
        .filter(|d| d.args.first().map(|a| a.eq_ignore_ascii_case("on")) == Some(true))
        .map(|d| Finding {
            rule: "server-tokens-on",
            severity: Severity::Warning,
            line: d.line,
            context: format!("server_tokens (line {})", d.line),
            message: "server_tokens on leaks the nginx version in error pages and the Server header — set it to off".to_string(),
        })
        .collect()
}

/// Rule 3: a server terminating TLS (`ssl_certificate` present) with no
/// `ssl_protocols` directive (falls back to nginx's compiled-in default,
/// which has historically included old versions) or one that explicitly
/// lists a version considered weak/deprecated today.
pub fn check_ssl_protocols(server_body: &[Item], line: usize) -> Vec<Finding> {
    let names = server_names(server_body);
    let ctx = server_context(&names, line);
    let has_cert = !find_directives_direct(server_body, "ssl_certificate").is_empty();
    if !has_cert {
        return Vec::new();
    }

    let protocol_directives = find_directives_direct(server_body, "ssl_protocols");
    if protocol_directives.is_empty() {
        return vec![Finding {
            rule: "missing-ssl-protocols",
            severity: Severity::Error,
            line,
            context: ctx,
            message: "ssl_certificate is set but ssl_protocols is not — falls back to nginx's compiled-in default, which may allow old TLS versions".to_string(),
        }];
    }

    let mut findings = Vec::new();
    for d in protocol_directives {
        let weak: Vec<&str> = d
            .args
            .iter()
            .filter(|a| {
                OLD_TLS_VERSIONS.contains(&a.as_str()) || WEAK_TLS_VERSIONS.contains(&a.as_str())
            })
            .map(|s| s.as_str())
            .collect();
        if !weak.is_empty() {
            findings.push(Finding {
                rule: "weak-ssl-protocol",
                severity: Severity::Error,
                line: d.line,
                context: ctx.clone(),
                message: format!(
                    "ssl_protocols enables deprecated version(s): {}",
                    weak.join(", ")
                ),
            });
        }
    }
    findings
}

const UPLOAD_CAPABLE_DIRECTIVES: [&str; 3] = ["proxy_pass", "fastcgi_pass", "uwsgi_pass"];

/// Rule 4: a `location` handing requests off to a backend (`proxy_pass`,
/// `fastcgi_pass`, `uwsgi_pass` — anything that can receive a POST body)
/// with no `client_max_body_size` set in that location or the enclosing
/// server, so it silently falls back to nginx's stock 1m default.
///
/// This is a heuristic, not a semantic understanding of which endpoints
/// actually accept uploads — documented plainly in the README.
pub fn check_missing_body_size_limit(server_body: &[Item], server_line: usize) -> Vec<Finding> {
    let names = server_names(server_body);
    let ctx = server_context(&names, server_line);
    let server_level_limit =
        !find_directives_direct(server_body, "client_max_body_size").is_empty();
    if server_level_limit {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for loc in find_blocks_recursive(server_body, "location") {
        let is_upload_capable = UPLOAD_CAPABLE_DIRECTIVES
            .iter()
            .any(|name| !find_directives_direct(&loc.body, name).is_empty());
        if !is_upload_capable {
            continue;
        }
        let has_local_limit = !find_directives_direct(&loc.body, "client_max_body_size").is_empty();
        if has_local_limit {
            continue;
        }
        let loc_desc = loc.args.first().cloned().unwrap_or_default();
        findings.push(Finding {
            rule: "missing-client-max-body-size",
            severity: Severity::Warning,
            line: loc.line,
            context: format!("{ctx} / location {loc_desc} (line {})", loc.line),
            message: "location proxies to a backend but sets no client_max_body_size (nor does the enclosing server) — falls back to nginx's 1m default, which will reject any larger upload".to_string(),
        });
    }
    findings
}

/// Rule 5: a wildcard `server_name` (e.g. `*.example.com`, `example.*`)
/// combined with SSL termination — a single certificate can't validly
/// cover an arbitrary wildcard match the way `server_name` allows, so this
/// is a near-guaranteed hostname mismatch at handshake time.
pub fn check_wildcard_server_name_with_ssl(server_body: &[Item], line: usize) -> Vec<Finding> {
    let names = server_names(server_body);
    let ctx = server_context(&names, line);
    if !server_listens_ssl(server_body) {
        return Vec::new();
    }
    let wildcard_names: Vec<&String> = names.iter().filter(|n| n.contains('*')).collect();
    if wildcard_names.is_empty() {
        return Vec::new();
    }
    vec![Finding {
        rule: "wildcard-server-name-with-ssl",
        severity: Severity::Error,
        line,
        context: ctx,
        message: format!(
            "server_name {} is a wildcard but this server terminates SSL — the certificate almost certainly won't match every host this could receive",
            wildcard_names
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        ),
    }]
}

/// Runs every rule against every `server` block found anywhere in the
/// parsed config (server-scoped rules), plus the config-wide rules
/// (`server_tokens`) once over the whole tree.
pub fn lint(items: &[Item]) -> Vec<Finding> {
    let mut findings = check_server_tokens(items);

    for server in find_blocks_recursive(items, "server") {
        findings.extend(check_missing_security_headers(&server.body, server.line));
        findings.extend(check_ssl_protocols(&server.body, server.line));
        findings.extend(check_missing_body_size_limit(&server.body, server.line));
        findings.extend(check_wildcard_server_name_with_ssl(
            &server.body,
            server.line,
        ));
    }

    findings.sort_by(|a, b| a.line.cmp(&b.line).then(a.rule.cmp(b.rule)));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    #[test]
    fn detects_missing_both_security_headers() {
        let items = parse("server { listen 80; server_name example.com; }");
        let findings = lint(&items);
        let rules: Vec<&str> = findings.iter().map(|f| f.rule).collect();
        assert_eq!(
            rules
                .iter()
                .filter(|r| **r == "missing-security-header")
                .count(),
            2
        );
    }

    #[test]
    fn present_headers_suppress_the_finding() {
        let items = parse(
            r#"server {
                listen 80;
                add_header X-Frame-Options DENY;
                add_header X-Content-Type-Options nosniff;
            }"#,
        );
        let findings = lint(&items);
        assert!(!findings.iter().any(|f| f.rule == "missing-security-header"));
    }

    #[test]
    fn headers_in_nested_location_still_count() {
        let items = parse(
            r#"server {
                listen 80;
                location / {
                    add_header X-Frame-Options DENY;
                    add_header X-Content-Type-Options nosniff;
                }
            }"#,
        );
        let findings = lint(&items);
        assert!(!findings.iter().any(|f| f.rule == "missing-security-header"));
    }

    #[test]
    fn server_tokens_on_is_flagged() {
        let items = parse("http { server_tokens on; server { listen 80; } }");
        let findings = lint(&items);
        assert!(findings.iter().any(|f| f.rule == "server-tokens-on"));
    }

    #[test]
    fn server_tokens_off_is_not_flagged() {
        let items = parse("http { server_tokens off; server { listen 80; } }");
        let findings = lint(&items);
        assert!(!findings.iter().any(|f| f.rule == "server-tokens-on"));
    }

    #[test]
    fn missing_ssl_protocols_flagged_when_cert_present() {
        let items = parse(
            r#"server {
                listen 443 ssl;
                server_name example.com;
                ssl_certificate /etc/ssl/cert.pem;
                ssl_certificate_key /etc/ssl/key.pem;
            }"#,
        );
        let findings = lint(&items);
        assert!(findings.iter().any(|f| f.rule == "missing-ssl-protocols"));
    }

    #[test]
    fn weak_ssl_protocol_flagged() {
        let items = parse(
            r#"server {
                listen 443 ssl;
                ssl_certificate /etc/ssl/cert.pem;
                ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
            }"#,
        );
        let findings = lint(&items);
        let f = findings
            .iter()
            .find(|f| f.rule == "weak-ssl-protocol")
            .unwrap();
        assert!(f.message.contains("TLSv1"));
        assert!(f.message.contains("TLSv1.1"));
    }

    #[test]
    fn modern_ssl_protocols_not_flagged() {
        let items = parse(
            r#"server {
                listen 443 ssl;
                ssl_certificate /etc/ssl/cert.pem;
                ssl_protocols TLSv1.2 TLSv1.3;
            }"#,
        );
        let findings = lint(&items);
        assert!(!findings
            .iter()
            .any(|f| f.rule == "weak-ssl-protocol" || f.rule == "missing-ssl-protocols"));
    }

    #[test]
    fn no_cert_means_no_ssl_protocol_findings_at_all() {
        let items = parse("server { listen 80; }");
        let findings = lint(&items);
        assert!(!findings.iter().any(|f| f.rule.contains("ssl-protocol")));
    }

    #[test]
    fn proxy_location_without_body_size_is_flagged() {
        let items = parse(
            r#"server {
                listen 80;
                location /upload {
                    proxy_pass http://backend;
                }
            }"#,
        );
        let findings = lint(&items);
        assert!(findings
            .iter()
            .any(|f| f.rule == "missing-client-max-body-size"));
    }

    #[test]
    fn body_size_set_on_location_suppresses_finding() {
        let items = parse(
            r#"server {
                listen 80;
                location /upload {
                    client_max_body_size 50m;
                    proxy_pass http://backend;
                }
            }"#,
        );
        let findings = lint(&items);
        assert!(!findings
            .iter()
            .any(|f| f.rule == "missing-client-max-body-size"));
    }

    #[test]
    fn body_size_set_on_server_suppresses_all_locations() {
        let items = parse(
            r#"server {
                listen 80;
                client_max_body_size 50m;
                location /upload {
                    proxy_pass http://backend;
                }
                location /api {
                    fastcgi_pass unix:/run/php.sock;
                }
            }"#,
        );
        let findings = lint(&items);
        assert!(!findings
            .iter()
            .any(|f| f.rule == "missing-client-max-body-size"));
    }

    #[test]
    fn static_only_location_is_not_flagged_for_body_size() {
        let items = parse(
            r#"server {
                listen 80;
                location / {
                    root /var/www;
                }
            }"#,
        );
        let findings = lint(&items);
        assert!(!findings
            .iter()
            .any(|f| f.rule == "missing-client-max-body-size"));
    }

    #[test]
    fn wildcard_server_name_with_ssl_is_flagged() {
        let items = parse(
            r#"server {
                listen 443 ssl;
                server_name *.example.com;
                ssl_certificate /etc/ssl/cert.pem;
                ssl_protocols TLSv1.2 TLSv1.3;
            }"#,
        );
        let findings = lint(&items);
        assert!(findings
            .iter()
            .any(|f| f.rule == "wildcard-server-name-with-ssl"));
    }

    #[test]
    fn wildcard_server_name_without_ssl_is_not_flagged() {
        let items = parse(
            r#"server {
                listen 80;
                server_name *.example.com;
            }"#,
        );
        let findings = lint(&items);
        assert!(!findings
            .iter()
            .any(|f| f.rule == "wildcard-server-name-with-ssl"));
    }

    #[test]
    fn exact_server_name_with_ssl_is_not_flagged() {
        let items = parse(
            r#"server {
                listen 443 ssl;
                server_name example.com;
                ssl_certificate /etc/ssl/cert.pem;
                ssl_protocols TLSv1.2 TLSv1.3;
            }"#,
        );
        let findings = lint(&items);
        assert!(!findings
            .iter()
            .any(|f| f.rule == "wildcard-server-name-with-ssl"));
    }

    #[test]
    fn fully_clean_server_produces_no_findings() {
        let items = parse(
            r#"http {
                server_tokens off;
                server {
                    listen 443 ssl;
                    server_name example.com;
                    ssl_certificate /etc/ssl/cert.pem;
                    ssl_certificate_key /etc/ssl/key.pem;
                    ssl_protocols TLSv1.2 TLSv1.3;
                    client_max_body_size 10m;
                    add_header X-Frame-Options DENY;
                    add_header X-Content-Type-Options nosniff;
                    location / {
                        proxy_pass http://backend;
                    }
                }
            }"#,
        );
        let findings = lint(&items);
        assert!(
            findings.is_empty(),
            "expected no findings, got {findings:?}"
        );
    }

    #[test]
    fn multiple_servers_are_each_checked_independently() {
        let items = parse(
            r#"http {
                server {
                    listen 80;
                    server_name a.example.com;
                }
                server {
                    listen 443 ssl;
                    server_name *.b.example.com;
                    ssl_certificate /etc/ssl/cert.pem;
                }
            }"#,
        );
        let findings = lint(&items);
        // The first server: 2 missing headers. The second: 2 missing
        // headers + missing ssl_protocols + wildcard-with-ssl.
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.rule == "missing-security-header")
                .count(),
            4
        );
        assert!(findings
            .iter()
            .any(|f| f.rule == "wildcard-server-name-with-ssl"));
        assert!(findings.iter().any(|f| f.rule == "missing-ssl-protocols"));
    }
}
