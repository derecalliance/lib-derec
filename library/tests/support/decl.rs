// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Declaration-block readers for the parity guards.
//!
//! The SDKs are five languages the Rust compiler cannot see into, so the
//! guards read their declarations as text. Reading a whole file for a name is
//! not enough: a member required on one interface is satisfied by the same
//! name on any other interface in the file. Everything here therefore works on
//! one declaration *block* at a time — an interface, class, record, struct,
//! trait or object literal, located by its header and closed by brace
//! matching — and reports the members declared directly inside it.
//!
//! This is deliberately not a parser. Comments and string contents are blanked
//! first, so braces inside them cannot unbalance a block, and members are the
//! depth-zero statements of the block body.

#![allow(dead_code)]

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    Rust,
    CSharp,
    Go,
    Ts,
}

/// `src` with comments and the contents of string and character literals
/// replaced by spaces. Byte offsets and newlines are preserved, so a range
/// found in the masked text addresses the same text in the original.
pub fn mask(src: &str, lang: Lang) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in out.iter_mut().take(to).skip(from) {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == b'/' && next == Some(b'/') {
            let end = src[i..].find('\n').map_or(b.len(), |n| i + n);
            blank(&mut out, i, end);
            i = end;
            continue;
        }
        if c == b'/' && next == Some(b'*') {
            let end = src[i + 2..].find("*/").map_or(b.len(), |n| i + 2 + n + 2);
            blank(&mut out, i, end);
            i = end;
            continue;
        }
        // Rust raw strings: r"..." and r#"..."#.
        if lang == Lang::Rust
            && c == b'r'
            && matches!(next, Some(b'"') | Some(b'#'))
            && (i == 0 || !is_ident(b[i - 1]))
        {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < b.len() && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < b.len() && b[j] == b'"' {
                let close = format!("\"{}", "#".repeat(hashes));
                let end = src[j + 1..]
                    .find(&close)
                    .map_or(b.len(), |n| j + 1 + n + close.len());
                blank(&mut out, j + 1, end.saturating_sub(close.len()));
                i = end;
                continue;
            }
        }
        let quote = match (lang, c) {
            (_, b'"') => true,
            (Lang::Ts, b'\'') | (Lang::Ts, b'`') | (Lang::Go, b'`') => true,
            (Lang::CSharp, b'\'') | (Lang::Go, b'\'') => true,
            // A Rust `'` opens a char literal only when it closes within
            // three bytes or escapes; otherwise it is a lifetime.
            (Lang::Rust, b'\'') => {
                b.get(i + 2) == Some(&b'\'')
                    || (next == Some(b'\\'))
                    || src[i + 1..].chars().nth(1) == Some('\'')
            }
            _ => false,
        };
        if quote {
            let mut j = i + 1;
            while j < b.len() && b[j] != c {
                if b[j] == b'\\' && c != b'`' {
                    j += 1;
                }
                j += 1;
            }
            blank(&mut out, i + 1, j.min(b.len()));
            i = j + 1;
            continue;
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| src.to_owned())
}

pub fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$'
}

/// Index of the bracket closing the one opened at `open`, in masked text.
pub fn matching(masked: &str, open: usize) -> Option<usize> {
    let b = masked.as_bytes();
    let (o, c) = match b[open] {
        b'{' => (b'{', b'}'),
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        b'<' => (b'<', b'>'),
        _ => return None,
    };
    let mut depth = 0i32;
    for (i, &ch) in b.iter().enumerate().skip(open) {
        if ch == o {
            depth += 1;
        } else if ch == c && !(c == b'>' && i > 0 && matches!(b[i - 1], b'=' | b'-')) {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// Every position where `word` occurs as a whole identifier.
pub fn word_positions(masked: &str, word: &str) -> Vec<usize> {
    let b = masked.as_bytes();
    masked
        .match_indices(word)
        .map(|(i, _)| i)
        .filter(|&i| {
            (i == 0 || !is_ident(b[i - 1])) && b.get(i + word.len()).is_none_or(|&c| !is_ident(c))
        })
        .collect()
}

/// A located declaration: the header's text and the body range between its
/// braces (exclusive). `params` holds a positional parameter list — a C#
/// positional record's — when the header carries one.
#[derive(Clone, Debug)]
pub struct Block {
    pub header: String,
    pub body: std::ops::Range<usize>,
    pub params: Option<std::ops::Range<usize>>,
}

/// Find the declaration `<keyword> <name>` and its body.
///
/// `keywords` are the introducers to accept (`interface`, `class`, `record`,
/// `struct`, `trait`, …). Generic parameters, base lists and `where` clauses
/// between the name and the body are skipped. A declaration that ends in `;`
/// before any `{` has an empty body — a C# `record X(...);` or `record X;`.
pub fn find_block(masked: &str, keywords: &[&str], name: &str) -> Option<Block> {
    find_block_in(masked, 0..masked.len(), keywords, name)
}

/// [`find_block`] restricted to declarations that start inside `within` —
/// the members of one enclosing block.
pub fn find_block_in(
    masked: &str,
    within: std::ops::Range<usize>,
    keywords: &[&str],
    name: &str,
) -> Option<Block> {
    let b = masked.as_bytes();
    for kw in keywords {
        for at in word_positions(masked, kw)
            .into_iter()
            .filter(|at| within.contains(at))
        {
            let mut i = at + kw.len();
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if !masked[i..].starts_with(name) || b.get(i + name.len()).is_some_and(|&c| is_ident(c))
            {
                continue;
            }
            i += name.len();
            let header_start = at;
            let mut params = None;
            // Walk to the body, skipping balanced (), <> and [] groups.
            while i < b.len() {
                match b[i] {
                    b'{' => {
                        let close = matching(masked, i)?;
                        return Some(Block {
                            header: masked[header_start..i].to_owned(),
                            body: i + 1..close,
                            params,
                        });
                    }
                    b';' => {
                        return Some(Block {
                            header: masked[header_start..i].to_owned(),
                            body: i..i,
                            params,
                        });
                    }
                    b'(' => {
                        let close = matching(masked, i)?;
                        if params.is_none() {
                            params = Some(i + 1..close);
                        }
                        i = close + 1;
                    }
                    b'<' | b'[' => {
                        i = matching(masked, i)? + 1;
                    }
                    _ => i += 1,
                }
            }
        }
    }
    None
}

/// The depth-zero statements of a body, as byte ranges into it.
///
/// A statement ends at `;` (or `,` when `commas` is set, for object literals
/// and Rust struct bodies), at a newline when `newlines` is set (Go), or when
/// a `{...}` block it opened closes.
pub fn statements(
    masked: &str,
    range: std::ops::Range<usize>,
    commas: bool,
    newlines: bool,
) -> Vec<std::ops::Range<usize>> {
    let b = masked.as_bytes();
    let mut out = Vec::new();
    let mut start = range.start;
    let mut i = range.start;
    let push = |s: usize, e: usize, out: &mut Vec<std::ops::Range<usize>>| {
        if !masked[s..e].trim().is_empty() {
            out.push(s..e);
        }
    };
    while i < range.end {
        match b[i] {
            b'(' | b'[' => {
                i = matching(masked, i).map_or(range.end, |c| c + 1);
                continue;
            }
            b'{' => {
                let close = matching(masked, i).unwrap_or(range.end);
                i = close + 1;
                // A `{}` that ends a member (a method or accessor body) ends the
                // statement; one followed by a continuation (`= value`, `| T`,
                // a directly adjacent `[]`) is part of a longer declaration that
                // ends at `;`. Go statements end at the newline instead.
                let rest = masked[i..range.end].trim_start();
                let continues = newlines
                    || masked[i..range.end].starts_with(['[', '.'])
                    || rest.starts_with(['|', '&', '=', '?', ':', '>', '{'])
                    || rest.starts_with("as ");
                if !continues {
                    push(start, i, &mut out);
                    start = i;
                }
                continue;
            }
            b';' => {
                push(start, i, &mut out);
                start = i + 1;
            }
            b',' if commas => {
                push(start, i, &mut out);
                start = i + 1;
            }
            b'\n' if newlines => {
                push(start, i, &mut out);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    push(start, range.end, &mut out);
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Method,
    Field,
    Constructor,
}

/// One member declared directly in a block.
#[derive(Clone, Debug)]
pub struct Member {
    pub name: String,
    pub kind: Kind,
    pub params: Vec<String>,
    pub public: bool,
    pub is_static: bool,
    /// The statement's original text, for checks on what a member forwards to.
    pub text: String,
}

/// Split a parameter list on depth-zero commas.
pub fn split_params(masked: &str, range: std::ops::Range<usize>) -> Vec<std::ops::Range<usize>> {
    let b = masked.as_bytes();
    let mut out = Vec::new();
    let mut start = range.start;
    let mut i = range.start;
    while i < range.end {
        match b[i] {
            b'(' | b'[' | b'{' => {
                i = matching(masked, i).map_or(range.end, |c| c + 1);
                continue;
            }
            b'<' => {
                // A generic argument list, never a comparison, in a signature.
                if let Some(c) = matching(masked, i).filter(|&c| c < range.end) {
                    i = c + 1;
                    continue;
                }
            }
            b',' => {
                if !masked[start..i].trim().is_empty() {
                    out.push(start..i);
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if !masked[start..range.end].trim().is_empty() {
        out.push(start..range.end);
    }
    out
}

fn leading_ident(s: &str) -> &str {
    let end = s.bytes().position(|c| !is_ident(c)).unwrap_or(s.len());
    &s[..end]
}

fn trailing_ident(s: &str) -> &str {
    let s = s.trim_end();
    let start = s.bytes().rposition(|c| !is_ident(c)).map_or(0, |p| p + 1);
    &s[start..]
}

/// Strip leading `[...]` attribute groups (C#) or `#[...]` (Rust).
fn strip_attributes(masked: &str, mut s: usize, e: usize) -> usize {
    loop {
        while s < e && masked.as_bytes()[s].is_ascii_whitespace() {
            s += 1;
        }
        let at = if masked[s..e].starts_with("#[") {
            s + 1
        } else if masked[s..e].starts_with('[') {
            s
        } else {
            return s;
        };
        match matching(masked, at) {
            Some(c) if c < e => s = c + 1,
            _ => return s,
        }
    }
}

/// Parameter names of a parameter list, per the language's declaration form.
pub fn param_names(masked: &str, range: std::ops::Range<usize>, lang: Lang) -> Vec<String> {
    let pieces = split_params(masked, range);
    let mut names: Vec<String> = Vec::new();
    for p in pieces {
        let s = strip_attributes(masked, p.start, p.end);
        let text = masked[s..p.end].trim();
        let name = match lang {
            Lang::Rust => {
                let head = text.split(':').next().unwrap_or("").trim();
                let head = head.trim_start_matches("mut ").trim();
                if head.ends_with("self") || head.is_empty() {
                    continue;
                }
                trailing_ident(head).to_owned()
            }
            Lang::Ts => {
                let t = text.trim_start_matches("...");
                let t = t
                    .trim_start_matches("readonly ")
                    .trim_start_matches("public ")
                    .trim_start_matches("private ");
                leading_ident(t).to_owned()
            }
            Lang::CSharp => {
                let t = text.split('=').next().unwrap_or("");
                trailing_ident(t).to_owned()
            }
            // `a, b uint64` reaches here as `a` and `b uint64`: the name
            // always leads.
            Lang::Go => leading_ident(text).to_owned(),
        };
        if !name.is_empty() {
            names.push(name);
        }
    }
    names
}

const CS_TYPE_KEYWORDS: &[&str] = &["class", "record", "struct", "interface", "enum", "delegate"];

/// Parse one depth-zero statement of a block into a member.
///
/// `owner` is the declaring type's name, to recognise constructors.
/// `implicit_public` marks members public without a modifier — interface
/// members, and anything in a TypeScript declaration.
pub fn parse_member(
    masked: &str,
    src: &str,
    stmt: std::ops::Range<usize>,
    lang: Lang,
    owner: &str,
    implicit_public: bool,
) -> Option<Member> {
    let s = match lang {
        Lang::CSharp | Lang::Rust => strip_attributes(masked, stmt.start, stmt.end),
        _ => {
            let mut s = stmt.start;
            while s < stmt.end && masked.as_bytes()[s].is_ascii_whitespace() {
                s += 1;
            }
            s
        }
    };
    let original = src[s..stmt.end].to_owned();
    match lang {
        Lang::Ts => parse_ts(masked, s, stmt.end, owner, original),
        Lang::CSharp => parse_cs(masked, s, stmt.end, owner, implicit_public, original),
        Lang::Go => parse_go(masked, s, stmt.end, original),
        Lang::Rust => parse_rust(masked, s, stmt.end, original),
    }
}

fn parse_ts(masked: &str, s: usize, e: usize, owner: &str, text: String) -> Option<Member> {
    let mut t = s;
    let mut public = true;
    let mut is_static = false;
    loop {
        let rest = &masked[t..e];
        let word = leading_ident(rest);
        let after = rest[word.len()..].trim_start();
        let is_modifier = matches!(
            word,
            "export"
                | "declare"
                | "public"
                | "readonly"
                | "async"
                | "static"
                | "abstract"
                | "override"
                | "function"
                | "const"
                | "let"
                | "private"
                | "protected"
                | "get"
                | "set"
        ) && !after.starts_with(['(', ':', '?', '=', '<', ','])
            && !after.is_empty();
        if !is_modifier {
            break;
        }
        if word == "private" || word == "protected" {
            public = false;
        }
        if word == "static" {
            is_static = true;
        }
        t += word.len();
        while t < e && masked.as_bytes()[t].is_ascii_whitespace() {
            t += 1;
        }
    }
    let rest = &masked[t..e];
    if rest.starts_with('#') {
        return None;
    }
    let (name, after_name) = if rest.starts_with('[') {
        let close = matching(masked, t)?;
        let inner = &masked[t..=close];
        if inner.contains(':') {
            return None; // index signature
        }
        (inner.to_owned(), close + 1)
    } else {
        let w = leading_ident(rest);
        if w.is_empty() {
            return None;
        }
        (w.to_owned(), t + w.len())
    };
    let tail = masked[after_name..e].trim_start_matches('?').trim_start();
    if name == "constructor" {
        let open = after_name + masked[after_name..e].find('(')?;
        let close = matching(masked, open)?;
        return Some(Member {
            name: owner.to_owned(),
            kind: Kind::Constructor,
            params: param_names(masked, open + 1..close, Lang::Ts),
            public,
            is_static,
            text,
        });
    }
    let kind;
    let mut params = Vec::new();
    if tail.starts_with('(') || tail.starts_with('<') {
        let open = after_name + masked[after_name..e].find('(')?;
        let close = matching(masked, open)?;
        params = param_names(masked, open + 1..close, Lang::Ts);
        kind = Kind::Method;
    } else if tail.starts_with(':') || tail.starts_with('=') || tail.is_empty() {
        // `name: (a) => T` is a function-typed property; treat it as a method
        // so its parameters are compared too.
        let value = tail.trim_start_matches([':', '=']).trim_start();
        if value.starts_with('(') && masked[after_name..e].contains("=>") {
            let open = after_name + masked[after_name..e].find('(')?;
            let close = matching(masked, open)?;
            params = param_names(masked, open + 1..close, Lang::Ts);
            kind = Kind::Method;
        } else {
            kind = Kind::Field;
        }
    } else {
        return None;
    }
    Some(Member {
        name,
        kind,
        params,
        public,
        is_static,
        text,
    })
}

fn parse_cs(
    masked: &str,
    s: usize,
    e: usize,
    owner: &str,
    implicit_public: bool,
    text: String,
) -> Option<Member> {
    let rest = &masked[s..e];
    // The first delimiter that ends the declaration's head.
    let mut delim = None;
    let b = rest.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'<' => {
                if let Some(c) = matching(masked, s + i).filter(|&c| c < e) {
                    i = c - s + 1;
                    continue;
                }
            }
            b'(' | b'{' | b';' => {
                delim = Some(i);
                break;
            }
            b'=' => {
                delim = Some(i);
                break;
            }
            _ => {}
        }
        i += 1;
    }
    let d = delim.unwrap_or(b.len());
    let head = &rest[..d];
    let words: Vec<&str> = head.split_whitespace().collect();
    if words.iter().any(|w| CS_TYPE_KEYWORDS.contains(w)) || words.contains(&"operator") {
        return None;
    }
    let public = implicit_public || words.contains(&"public");
    let is_static = words.contains(&"static") || words.contains(&"const");
    let mut name = trailing_ident(head.trim_end().trim_end_matches('>')).to_owned();
    if head.trim_end().ends_with('>') {
        // `Method<T>(`: the name precedes the generic list.
        let lt = head.rfind('<')?;
        name = trailing_ident(&head[..lt]).to_owned();
    }
    if name.is_empty() {
        return None;
    }
    let delim_char = b.get(d).copied();
    let (kind, params) = if delim_char == Some(b'(') {
        let open = s + d;
        let close = matching(masked, open)?;
        let params = param_names(masked, open + 1..close, Lang::CSharp);
        if name == owner {
            (Kind::Constructor, params)
        } else {
            (Kind::Method, params)
        }
    } else {
        (Kind::Field, Vec::new())
    };
    // `=> expr` without parameters is a computed property, not a field.
    let computed = kind == Kind::Field && rest[d..].starts_with("=>");
    if computed {
        return Some(Member {
            name,
            kind: Kind::Method,
            params,
            public,
            is_static,
            text,
        });
    }
    Some(Member {
        name,
        kind,
        params,
        public,
        is_static,
        text,
    })
}

fn parse_go(masked: &str, s: usize, e: usize, text: String) -> Option<Member> {
    let rest = &masked[s..e];
    let name = leading_ident(rest);
    if name.is_empty() {
        return None;
    }
    let after = &rest[name.len()..];
    if after.starts_with('(') {
        let open = s + name.len();
        let close = matching(masked, open)?;
        return Some(Member {
            name: name.to_owned(),
            kind: Kind::Method,
            params: param_names(masked, open + 1..close, Lang::Go),
            public: name.as_bytes()[0].is_ascii_uppercase(),
            is_static: false,
            text,
        });
    }
    // A field list `A, B Type`, or an embedded type.
    let mut names = vec![name.to_owned()];
    let mut tail = after.trim_start();
    while let Some(r) = tail.strip_prefix(',') {
        let n = leading_ident(r.trim_start());
        names.push(n.to_owned());
        tail = r.trim_start()[n.len()..].trim_start();
    }
    if tail.is_empty() || tail.starts_with('`') || tail.starts_with('.') {
        // Embedded: `ChannelFilter` or `pkg.Type`.
        return Some(Member {
            name: format!(
                "embedded:{}",
                trailing_ident(rest.split('`').next().unwrap_or(rest))
            ),
            kind: Kind::Field,
            params: Vec::new(),
            public: true,
            is_static: false,
            text,
        });
    }
    // A grouped `A, B Type` declaration is returned as one member named
    // `A,B`; `go_fields` splits it.
    Some(Member {
        name: names.join(","),
        kind: Kind::Field,
        params: Vec::new(),
        public: name.as_bytes()[0].is_ascii_uppercase(),
        is_static: false,
        text,
    })
}

fn parse_rust(masked: &str, s: usize, e: usize, text: String) -> Option<Member> {
    let rest = &masked[s..e];
    let words: Vec<&str> = rest.split_whitespace().take(4).collect();
    let public = words.first() == Some(&"pub");
    if let Some(fn_at) = word_positions(rest, "fn").first().copied() {
        let after = rest[fn_at + 2..].trim_start();
        let name = leading_ident(after);
        let name_at = s + fn_at + 2 + (rest[fn_at + 2..].len() - after.len());
        let open = name_at + masked[name_at..e].find('(')?;
        let close = matching(masked, open)?;
        return Some(Member {
            name: name.to_owned(),
            kind: Kind::Method,
            params: param_names(masked, open + 1..close, Lang::Rust),
            public,
            is_static: false,
            text,
        });
    }
    // A struct field: `[pub] name: Type`.
    let t = rest
        .trim_start_matches("pub(crate) ")
        .trim_start_matches("pub ")
        .trim_start();
    let name = leading_ident(t);
    if name.is_empty() || !t[name.len()..].trim_start().starts_with(':') {
        return None;
    }
    Some(Member {
        name: name.to_owned(),
        kind: Kind::Field,
        params: Vec::new(),
        public,
        is_static: false,
        text,
    })
}

/// Members declared directly in a block body.
///
/// `commas` separates statements on `,` as well as `;` — for object literals,
/// and for Rust struct bodies.
pub fn members(
    src: &str,
    masked: &str,
    body: std::ops::Range<usize>,
    lang: Lang,
    owner: &str,
    implicit_public: bool,
    commas: bool,
) -> Vec<Member> {
    let newlines = lang == Lang::Go;
    statements(masked, body, commas, newlines)
        .into_iter()
        .filter_map(|st| parse_member(masked, src, st, lang, owner, implicit_public))
        .collect()
}

/// The fields of a Go struct, expanding grouped `A, B Type` declarations and
/// following embedded structs declared in `files`.
pub fn go_fields(files: &[(String, String)], name: &str) -> Option<Vec<String>> {
    let (src, masked, block) = go_type_block(files, name, "struct")?;
    let mut out = Vec::new();
    for m in members(&src, &masked, block.body, Lang::Go, name, false, false) {
        if let Some(embedded) = m.name.strip_prefix("embedded:") {
            out.extend(go_fields(files, embedded).unwrap_or_default());
        } else if m.public {
            out.extend(m.name.split(',').map(str::to_owned));
        }
    }
    Some(out)
}

/// Locate `type <name> struct|interface {` in any of `files`, following a
/// `type <name> = pkg.<Target>` alias to its target.
pub fn go_type_block(
    files: &[(String, String)],
    name: &str,
    keyword: &str,
) -> Option<(String, String, Block)> {
    for (_, src) in files {
        let masked = mask(src, Lang::Go);
        for at in word_positions(&masked, name) {
            let line_start = masked[..at].rfind('\n').map_or(0, |i| i + 1);
            let line = masked[line_start..].lines().next().unwrap_or("");
            let decl = line.trim_start();
            let in_group = decl.starts_with(name);
            let direct = decl.starts_with(&format!("type {name} "));
            if !(direct || in_group) {
                continue;
            }
            let after = masked[at + name.len()..].trim_start();
            if let Some(rest) = after.strip_prefix('=') {
                let target = rest.split_whitespace().next().unwrap_or("");
                let target = target.rsplit('.').next().unwrap_or(target);
                // `type Share = native.Share` names the same identifier in
                // another package: keep searching for the declaration itself.
                if target == name {
                    continue;
                }
                return go_type_block(files, target, keyword);
            }
            if let Some(rest) = after.strip_prefix(keyword) {
                let open = masked.len() - rest.len() + rest.find('{')?;
                let close = matching(&masked, open)?;
                return Some((
                    src.clone(),
                    masked.clone(),
                    Block {
                        header: line.to_owned(),
                        body: open + 1..close,
                        params: None,
                    },
                ));
            }
        }
    }
    None
}

/// Exported methods declared on Go type `recv` (value or pointer receiver),
/// across `files`.
pub fn go_methods(files: &[(String, String)], recv: &str) -> Vec<Member> {
    let mut out = Vec::new();
    for (_, src) in files {
        let masked = mask(src, Lang::Go);
        for at in word_positions(&masked, "func") {
            let rest = &masked[at + 4..];
            let t = rest.trim_start();
            if !t.starts_with('(') {
                continue;
            }
            let open = masked.len() - t.len();
            let Some(close) = matching(&masked, open) else {
                continue;
            };
            let receiver = &masked[open + 1..close];
            let ty = receiver
                .split_whitespace()
                .last()
                .unwrap_or("")
                .trim_start_matches('*');
            if ty != recv {
                continue;
            }
            let after = masked[close + 1..].trim_start();
            let name = leading_ident(after);
            let name_at = masked.len() - after.len();
            let Some(popen) = masked[name_at..].find('(').map(|i| name_at + i) else {
                continue;
            };
            let Some(pclose) = matching(&masked, popen) else {
                continue;
            };
            let body_end = masked[pclose..]
                .find('{')
                .and_then(|i| matching(&masked, pclose + i))
                .unwrap_or(pclose);
            out.push(Member {
                name: name.to_owned(),
                kind: Kind::Method,
                params: param_names(&masked, popen + 1..pclose, Lang::Go),
                public: name.as_bytes().first().is_some_and(u8::is_ascii_uppercase),
                is_static: false,
                text: src[at..=body_end.min(src.len() - 1)].to_owned(),
            });
        }
    }
    out
}

/// Exported package-level Go functions in `files`, with their parameters.
pub fn go_funcs(files: &[(String, String)]) -> Vec<Member> {
    let mut out = Vec::new();
    for (_, src) in files {
        let masked = mask(src, Lang::Go);
        for at in word_positions(&masked, "func") {
            if at != 0 && masked.as_bytes()[at - 1] != b'\n' {
                continue;
            }
            let after = masked[at + 4..].trim_start();
            let name = leading_ident(after);
            if name.is_empty() || !name.as_bytes()[0].is_ascii_uppercase() {
                continue;
            }
            let name_at = masked.len() - after.len();
            let Some(popen) = masked[name_at..].find('(').map(|i| name_at + i) else {
                continue;
            };
            let Some(pclose) = matching(&masked, popen) else {
                continue;
            };
            out.push(Member {
                name: name.to_owned(),
                kind: Kind::Method,
                params: param_names(&masked, popen + 1..pclose, Lang::Go),
                public: true,
                is_static: true,
                text: String::new(),
            });
        }
    }
    out
}

/// Case- and separator-insensitive form of an identifier, so `secret_id`,
/// `secretId`, `SecretId` and `SecretID` compare equal.
pub fn norm(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '_')
        .flat_map(char::to_lowercase)
        .collect()
}
