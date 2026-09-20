//! A deliberately small nginx config parser.
//!
//! nginx's real config grammar has corners this doesn't attempt (`if`,
//! embedded Lua blocks, map blocks with regex keys that contain `{`/`}` in
//! strings, etc.) — see the crate-level docs for what's in scope. What it
//! does handle is the shape that matters for linting: nested `block { ... }`
//! groups and `directive arg1 arg2;` statements, comments, and quoted
//! arguments, with a line number attached to every directive and block so
//! findings can point somewhere useful.

#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub name: String,
    pub args: Vec<String>,
    pub body: Vec<Item>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    Directive(Directive),
    Block(Block),
}

#[derive(Debug, Clone, PartialEq)]
struct Token {
    text: String,
    line: usize,
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    let mut line = 1usize;

    while let Some(&c) = chars.peek() {
        match c {
            '\n' => {
                line += 1;
                chars.next();
            }
            c if c.is_whitespace() => {
                chars.next();
            }
            '#' => {
                for c2 in chars.by_ref() {
                    if c2 == '\n' {
                        line += 1;
                        break;
                    }
                }
            }
            '{' | '}' | ';' => {
                tokens.push(Token {
                    text: c.to_string(),
                    line,
                });
                chars.next();
            }
            '"' | '\'' => {
                let quote = c;
                let start_line = line;
                chars.next();
                let mut s = String::new();
                for c2 in chars.by_ref() {
                    if c2 == quote {
                        break;
                    }
                    if c2 == '\n' {
                        line += 1;
                    }
                    s.push(c2);
                }
                tokens.push(Token {
                    text: s,
                    line: start_line,
                });
            }
            _ => {
                let start_line = line;
                let mut s = String::new();
                while let Some(&c2) = chars.peek() {
                    if c2.is_whitespace() || c2 == '{' || c2 == '}' || c2 == ';' || c2 == '#' {
                        break;
                    }
                    s.push(c2);
                    chars.next();
                }
                tokens.push(Token {
                    text: s,
                    line: start_line,
                });
            }
        }
    }
    tokens
}

/// Parses a full nginx config file's text into a flat list of top-level
/// items (directives and blocks), recursing into nested blocks.
pub fn parse(input: &str) -> Vec<Item> {
    let tokens = tokenize(input);
    let mut pos = 0;
    parse_items(&tokens, &mut pos)
}

fn parse_items(tokens: &[Token], pos: &mut usize) -> Vec<Item> {
    let mut items = Vec::new();
    while *pos < tokens.len() {
        if tokens[*pos].text == "}" {
            *pos += 1;
            break;
        }

        let mut words: Vec<Token> = Vec::new();
        while *pos < tokens.len() && tokens[*pos].text != ";" && tokens[*pos].text != "{" {
            words.push(tokens[*pos].clone());
            *pos += 1;
        }
        if *pos >= tokens.len() {
            // Trailing directive with no terminator — ignore rather than
            // fabricate a fake one.
            break;
        }

        if tokens[*pos].text == ";" {
            *pos += 1;
            if words.is_empty() {
                continue;
            }
            let line = words[0].line;
            let name = words[0].text.clone();
            let args = words[1..].iter().map(|t| t.text.clone()).collect();
            items.push(Item::Directive(Directive { name, args, line }));
        } else {
            // "{"
            let line = words.first().map(|t| t.line).unwrap_or(tokens[*pos].line);
            let name = words.first().map(|t| t.text.clone()).unwrap_or_default();
            let args = if words.len() > 1 {
                words[1..].iter().map(|t| t.text.clone()).collect()
            } else {
                Vec::new()
            };
            *pos += 1; // consume "{"
            let body = parse_items(tokens, pos);
            items.push(Item::Block(Block {
                name,
                args,
                body,
                line,
            }));
        }
    }
    items
}

/// Recursively finds every directive named `name` anywhere in `items`,
/// descending into nested blocks (e.g. finds `add_header` inside a
/// `location` nested under the `server` passed in).
pub fn find_directives_recursive<'a>(items: &'a [Item], name: &str) -> Vec<&'a Directive> {
    let mut found = Vec::new();
    for item in items {
        match item {
            Item::Directive(d) if d.name == name => found.push(d),
            Item::Block(b) => found.extend(find_directives_recursive(&b.body, name)),
            _ => {}
        }
    }
    found
}

/// Finds every directive named `name` at this level only (not descending
/// into nested blocks) — used when a directive's scope shouldn't leak from
/// a child `location` up to a rule checking the parent `server`, or vice
/// versa.
pub fn find_directives_direct<'a>(items: &'a [Item], name: &str) -> Vec<&'a Directive> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::Directive(d) if d.name == name => Some(d),
            _ => None,
        })
        .collect()
}

/// Recursively finds every block named `name` anywhere in `items`.
pub fn find_blocks_recursive<'a>(items: &'a [Item], name: &str) -> Vec<&'a Block> {
    let mut found = Vec::new();
    for item in items {
        if let Item::Block(b) = item {
            if b.name == name {
                found.push(b);
            }
            found.extend(find_blocks_recursive(&b.body, name));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_skips_comments_and_whitespace() {
        let toks = tokenize("# comment\nfoo bar;\n");
        let text: Vec<&str> = toks.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(text, vec!["foo", "bar", ";"]);
    }

    #[test]
    fn tokenize_handles_quoted_strings_with_spaces() {
        let toks = tokenize(r#"add_header X-Test "hello world";"#);
        let text: Vec<&str> = toks.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(text, vec!["add_header", "X-Test", "hello world", ";"]);
    }

    #[test]
    fn parse_flat_directive() {
        let items = parse("worker_processes auto;");
        assert_eq!(items.len(), 1);
        match &items[0] {
            Item::Directive(d) => {
                assert_eq!(d.name, "worker_processes");
                assert_eq!(d.args, vec!["auto".to_string()]);
            }
            _ => panic!("expected a directive"),
        }
    }

    #[test]
    fn parse_nested_blocks() {
        let cfg = r#"
            http {
                server {
                    listen 80;
                    location / {
                        proxy_pass http://backend;
                    }
                }
            }
        "#;
        let items = parse(cfg);
        let http = match &items[0] {
            Item::Block(b) => b,
            _ => panic!("expected http block"),
        };
        assert_eq!(http.name, "http");
        let server = match &http.body[0] {
            Item::Block(b) => b,
            _ => panic!("expected server block"),
        };
        assert_eq!(server.name, "server");
        assert_eq!(server.body.len(), 2);
    }

    #[test]
    fn parse_block_with_args() {
        let items = parse("location /api { proxy_pass http://backend; }");
        match &items[0] {
            Item::Block(b) => {
                assert_eq!(b.name, "location");
                assert_eq!(b.args, vec!["/api".to_string()]);
            }
            _ => panic!("expected a block"),
        }
    }

    #[test]
    fn line_numbers_track_across_multiple_lines() {
        let cfg = "server {\n  listen 80;\n  server_name example.com;\n}";
        let items = parse(cfg);
        let server = match &items[0] {
            Item::Block(b) => b,
            _ => panic!("expected server block"),
        };
        assert_eq!(server.line, 1);
        match &server.body[0] {
            Item::Directive(d) => assert_eq!(d.line, 2),
            _ => panic!("expected directive"),
        }
        match &server.body[1] {
            Item::Directive(d) => assert_eq!(d.line, 3),
            _ => panic!("expected directive"),
        }
    }

    #[test]
    fn find_directives_recursive_descends_into_locations() {
        let cfg = r#"
            server {
                location / {
                    add_header X-Frame-Options DENY;
                }
            }
        "#;
        let items = parse(cfg);
        let server = match &items[0] {
            Item::Block(b) => b,
            _ => panic!(),
        };
        let found = find_directives_recursive(&server.body, "add_header");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].args[0], "X-Frame-Options");
    }

    #[test]
    fn find_directives_direct_does_not_descend() {
        let cfg = r#"
            server {
                client_max_body_size 10m;
                location / {
                    client_max_body_size 20m;
                }
            }
        "#;
        let items = parse(cfg);
        let server = match &items[0] {
            Item::Block(b) => b,
            _ => panic!(),
        };
        let found = find_directives_direct(&server.body, "client_max_body_size");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].args[0], "10m");
    }

    #[test]
    fn find_blocks_recursive_finds_nested_servers() {
        let cfg = r#"
            http {
                server { listen 80; }
                server { listen 443 ssl; }
            }
        "#;
        let items = parse(cfg);
        let servers = find_blocks_recursive(&items, "server");
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn empty_input_parses_to_empty_list() {
        let items = parse("");
        assert!(items.is_empty());
    }

    #[test]
    fn unterminated_trailing_directive_is_dropped_not_fabricated() {
        // A config missing its final semicolon shouldn't panic or invent
        // a phantom directive.
        let items = parse("server { listen 80");
        let server = match &items[0] {
            Item::Block(b) => b,
            _ => panic!(),
        };
        assert!(server.body.is_empty());
    }
}
