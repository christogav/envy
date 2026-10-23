//! Project identity: what a project's secrets are filed under.
//!
//! The git remote is read by parsing `.git/config` directly. Nothing is
//! executed: no `git`, no hooks, no includes, no `core.*` settings. Accepted
//! parsing limits: only `[remote "x"]` headers on their own line followed by
//! `url = ...` lines (no `[remote "x"] url = ...` one-liners, no line
//! continuations). For a worktree the git directory's config is read before
//! the common directory's config, and the first `url` seen for a remote wins.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Files read from a repository (`.git`, `commondir`, `config`) must be
/// regular files no larger than this.
const MAX_READ: u64 = 1 << 20;

/// Normalises a git remote URL to `org/project` (no host, lowercase).
///
/// Only the path after the host is used, so userinfo (credentials) can never
/// reach the result: a URL whose path part still contains `@` or `:` is
/// refused, and every path segment must be made of ASCII letters, digits and
/// `-_.+`. Local paths and URLs with fewer than two segments give `None`.
pub fn identity_from_url(url: &str) -> Option<String> {
    let url = url.trim();
    let path = if let Some((scheme, rest)) = url.split_once("://") {
        if scheme.eq_ignore_ascii_case("file") {
            return None;
        }
        // `rest` is `[userinfo@]host[:port]/path`; the authority is everything
        // up to the first `/` and is discarded. A password containing `/`
        // leaves an `@` in the path, which is refused below.
        let (authority, path) = rest.split_once('/')?;
        if authority.rsplit('@').next().is_none_or(str::is_empty) {
            return None;
        }
        path
    } else {
        // scp-like `[user@]host:path`; the colon must precede any slash.
        let (host, path) = url.split_once(':')?;
        if host.is_empty() || host.contains('/') {
            return None;
        }
        path
    };
    // Checked on the raw text, before any query/fragment is stripped: an `@`
    // here is a credential that leaked past the authority (or a query that
    // cannot be told apart from one), so the URL is refused.
    if path.contains('@') {
        return None;
    }
    let path = path.split(['?', '#']).next().unwrap_or("");
    let mut segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let last = segments.pop()?;
    segments.push(last);
    let valid = |s: &&str| {
        !s.is_empty()
            && *s != "."
            && *s != ".."
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+'))
    };
    if segments.len() < 2 || !segments.iter().all(valid) {
        return None;
    }
    let id = segments.join("/").to_lowercase();
    // Lowercased first so `.GIT` and `.Git` are stripped too.
    let id = id.strip_suffix(".git").unwrap_or(&id);
    // The last segment must not have been only `.git`.
    (id.rsplit('/').next().is_some_and(|l| !l.is_empty()) && id.contains('/'))
        .then(|| id.to_string())
}

/// The identity of the project whose `.envy/` folder is in `root`: `org/project`
/// from the git remote (`upstream`, else `origin`). Otherwise the path: `~/rel`
/// inside the canonical `home` (`~` for home itself), or the absolute canonical
/// path outside it, with unusual bytes percent-encoded. A remote identity can
/// never contain `~` or start with `/`, so the two kinds cannot collide.
pub fn identity_for_root(root: &Path, home: &Path) -> String {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if let Some(id) = remote_identity(&root) {
        return id;
    }
    let home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    match root.strip_prefix(&home) {
        Ok(rel) if rel.as_os_str().is_empty() => "~".to_string(),
        Ok(rel) => format!("~/{}", encode_path(rel)),
        Err(_) => encode_path(&root),
    }
}

/// Percent-encodes every byte except ASCII letters, digits, `-_.+`, space and
/// the `/` separator, so distinct paths always give distinct strings.
fn encode_path(path: &Path) -> String {
    let mut out = String::new();
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+' | b' ' | b'/') {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn remote_identity(root: &Path) -> Option<String> {
    let remotes = remote_urls(&find_git_dirs(root)?);
    ["upstream", "origin"].iter().find_map(|name| {
        remotes
            .get(*name)
            .and_then(|url| url.as_deref())
            .and_then(identity_from_url)
    })
}

/// Reads a small regular file. Anything else (missing, directory, FIFO,
/// device, oversize, not UTF-8) is `None`, so a hostile `.git` can neither
/// block envy nor exhaust its memory.
fn read_small(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_READ {
        return None;
    }
    let mut buf = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_READ)
        .read_to_end(&mut buf)
        .ok()?;
    String::from_utf8(buf).ok()
}

/// Walks up from `start` to the nearest `.git` and returns the directories
/// whose `config` files apply, the git directory first and then the common
/// directory. The nearest `.git` wins even if it is unusable (then there is no
/// remote), matching the spec. `None` when there is no repository.
fn find_git_dirs(start: &Path) -> Option<Vec<PathBuf>> {
    let dir = start.ancestors().find(|d| d.join(".git").exists())?;
    let dot_git = dir.join(".git");
    let git_dir = if dot_git.is_dir() {
        dot_git
    } else {
        let text = read_small(&dot_git)?;
        let target = text.lines().next()?.trim().strip_prefix("gitdir:")?.trim();
        if target.is_empty() {
            return None;
        }
        dir.join(target)
    };
    let mut dirs = vec![git_dir.clone()];
    if let Some(text) = read_small(&git_dir.join("commondir")) {
        let common = text.trim();
        if !common.is_empty() {
            dirs.push(git_dir.join(common));
        }
    }
    Some(dirs)
}

/// Reads `[remote "<name>"] url = ...` from each directory's `config`. Only
/// that one key is looked at; includes and every other setting are ignored.
/// The first `url` per remote wins (an unusable one stays unusable).
fn remote_urls(git_dirs: &[PathBuf]) -> HashMap<String, Option<String>> {
    let mut remotes = HashMap::new();
    for dir in git_dirs {
        let Some(text) = read_small(&dir.join("config")) else {
            continue;
        };
        let mut current: Option<String> = None;
        for line in text.lines() {
            let line = line.trim();
            if let Some(header) = line.strip_prefix('[') {
                current = remote_section_name(header);
            } else if let (Some(name), Some((key, value))) = (&current, line.split_once('='))
                && key.trim().eq_ignore_ascii_case("url")
            {
                remotes
                    .entry(name.clone())
                    .or_insert_with(|| config_value(value));
            }
        }
    }
    remotes
}

/// A config value: surrounding whitespace trimmed, double quotes removed,
/// and an unquoted `#` or `;` starts a comment. `None` for an unterminated quote.
fn config_value(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut in_quote = false;
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => in_quote = !in_quote,
            '\\' if in_quote => out.push(chars.next()?),
            '#' | ';' if !in_quote => break,
            _ => out.push(c),
        }
    }
    (!in_quote).then(|| out.trim().to_string())
}

/// The remote name from the inside of a `[remote "name"]` header, if it is one.
/// The section name is case-insensitive; the remote name is not.
fn remote_section_name(header: &str) -> Option<String> {
    let inner = header.split_once(']')?.0.trim();
    let (section, rest) = inner.split_once(char::is_whitespace)?;
    if !section.eq_ignore_ascii_case("remote") {
        return None;
    }
    let name = rest.trim().strip_prefix('"')?.strip_suffix('"')?;
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use tempfile::TempDir;

    fn write_git_config(repo: &Path, body: &str) {
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join(".git/config"), body).unwrap();
    }

    fn canon(p: &Path) -> String {
        p.canonicalize().unwrap().to_string_lossy().into_owned()
    }

    fn home_with(rel: &str) -> (TempDir, PathBuf, PathBuf) {
        let dir = TempDir::new().unwrap();
        let home = dir.path().join("home");
        let root = home.join(rel);
        fs::create_dir_all(&root).unwrap();
        (dir, home, root)
    }

    fn origin(url: &str) -> String {
        format!("[remote \"origin\"]\n\turl = {url}\n")
    }

    #[test]
    fn identity_from_url_handles_common_forms() {
        assert_eq!(
            identity_from_url("git@github.com:Christogav/Envy.git"),
            Some("christogav/envy".to_string())
        );
        for url in [
            "ssh://git@github.com:22/acme/api",
            "https://github.com/acme/api.git",
            "https://github.com/acme/api/",
        ] {
            assert_eq!(
                identity_from_url(url),
                Some("acme/api".to_string()),
                "{url}"
            );
        }
        assert_eq!(
            identity_from_url("https://u:p@gitlab.com/acme/team/api.git"),
            Some("acme/team/api".to_string())
        );
        for url in ["/srv/git/api.git", "../api", "https://github.com/acme", ""] {
            assert_eq!(identity_from_url(url), None, "{url:?}");
        }
    }

    #[test]
    fn credentials_never_appear_in_identity() {
        let id = identity_from_url("https://user:t0ken@github.com/acme/api.git").unwrap();
        assert_eq!(id, "acme/api");
        assert!(!id.contains("t0ken") && !id.contains("user"));
    }

    #[test]
    fn credential_shaped_urls_never_leak_userinfo() {
        let cases: [(&str, Option<&str>); 6] = [
            ("user:pw@host:org/proj", None),
            ("https://user:pa/ss@host/a/b", None),
            ("https://user:p%40ss@host/a/b.git", Some("a/b")),
            ("ssh://user:pw@host:2222/a/b", Some("a/b")),
            ("git@[::1]:a/b", None),
            ("https://user:pw@host/a/b?token=pw#pw", Some("a/b")),
        ];
        for (url, want) in cases {
            let got = identity_from_url(url);
            assert_eq!(got.as_deref(), want, "{url}");
            if let Some(id) = got {
                assert!(!id.contains('@') && !id.contains(':'), "{url}");
                assert!(!id.contains("pw") && !id.contains("pa"), "{url}");
            }
        }
    }

    #[test]
    fn an_at_sign_anywhere_after_the_authority_is_refused() {
        for url in [
            "https://user:pw/sec/ret?x@host/a/b",
            "https://user:pa/ss/word#x@host/a/b",
            "u:pa/ss/w?x@h:a/b",
            "https://user:pw?x/y@host/a/b",
            "https://host/a/b?token=x@y",
            "git@host:a/b#frag@x",
        ] {
            assert_eq!(identity_from_url(url), None, "{url}");
        }
        assert_eq!(
            identity_from_url("https://host/a/b?x=1#f"),
            Some("a/b".to_string())
        );
        assert_eq!(
            identity_from_url("ssh://git@host/a/b"),
            Some("a/b".to_string())
        );
    }

    #[test]
    fn the_git_suffix_is_stripped_case_insensitively() {
        for url in [
            "https://host/A/B.GIT",
            "https://host/a/b.Git",
            "https://host/a/b.git",
        ] {
            assert_eq!(identity_from_url(url), Some("a/b".to_string()), "{url}");
        }
        assert_eq!(
            identity_from_url("https://host/a/git"),
            Some("a/git".to_string())
        );
    }

    #[test]
    fn identity_from_url_rejects_unsafe_characters() {
        for bad in [
            "a b",
            "a\tb",
            "a\nb",
            "a\0b",
            "a\\b",
            "%2e%2e",
            "~x",
            "caf\u{e9}",
            "a:b",
            "a@b",
            "..",
            ".",
        ] {
            let url = format!("https://host/org/{bad}");
            assert_eq!(identity_from_url(&url), None, "{url:?}");
            let url = format!("git@host:{bad}/proj");
            assert_eq!(identity_from_url(&url), None, "{url:?}");
        }
        assert_eq!(
            identity_from_url("https://host/a/b?x=1#f"),
            Some("a/b".to_string())
        );
        assert_eq!(
            identity_from_url("https://host/My_Org/a-b.c+d.git"),
            Some("my_org/a-b.c+d".to_string())
        );
        assert_eq!(identity_from_url("https://host/a/.git"), None);
    }

    #[test]
    fn identity_prefers_upstream_over_origin() {
        let (_d, home, root) = home_with("Source/app");
        write_git_config(
            &root,
            "[remote \"origin\"]\n\turl = git@github.com:me/app.git\n[remote \"upstream\"]\n\turl = https://github.com/Acme/App.git\n",
        );
        assert_eq!(identity_for_root(&root, &home), "acme/app");
    }

    #[test]
    fn identity_uses_origin_without_upstream() {
        let (_d, home, root) = home_with("Source/app");
        write_git_config(
            &root,
            "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = git@github.com:me/app.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
        );
        assert_eq!(identity_for_root(&root, &home), "me/app");
    }

    #[test]
    fn upstream_unparseable_falls_back_to_origin() {
        let (_d, home, root) = home_with("Source/app");
        write_git_config(
            &root,
            "[remote \"upstream\"]\n\turl = ../elsewhere\n[remote \"origin\"]\n\turl = git@github.com:me/app.git\n",
        );
        assert_eq!(identity_for_root(&root, &home), "me/app");
    }

    #[test]
    fn identity_finds_the_repository_above_the_folder() {
        let (_d, home, repo) = home_with("Source/app");
        let sub = repo.join("sub");
        fs::create_dir_all(sub.join(".envy")).unwrap();
        write_git_config(&repo, &origin("git@github.com:me/app.git"));
        assert_eq!(identity_for_root(&sub, &home), "me/app");
    }

    #[test]
    fn identity_follows_a_gitdir_file_to_the_common_dir() {
        let (d, home, root) = home_with("Source/wt");
        let main = d.path().join("main/.git");
        let gitdir = main.join("worktrees/wt");
        fs::create_dir_all(&gitdir).unwrap();
        fs::write(gitdir.join("commondir"), "../..\n").unwrap();
        fs::write(main.join("config"), origin("git@github.com:me/app.git")).unwrap();
        fs::write(root.join(".git"), format!("gitdir: {}\n", gitdir.display())).unwrap();
        assert_eq!(identity_for_root(&root, &home), "me/app");
    }

    #[test]
    fn fallback_without_git_is_the_home_relative_path() {
        let (_d, home, root) = home_with("Source/app");
        assert_eq!(identity_for_root(&root, &home), "~/Source/app");
    }

    #[test]
    fn fallback_with_git_but_no_remote() {
        let (_d, home, root) = home_with("Source/app");
        write_git_config(&root, "[core]\n\tbare = false\n");
        assert_eq!(identity_for_root(&root, &home), "~/Source/app");
    }

    #[test]
    fn fallback_with_an_unparseable_url() {
        let (_d, home, root) = home_with("Source/app");
        write_git_config(&root, &origin("../elsewhere"));
        assert_eq!(identity_for_root(&root, &home), "~/Source/app");
    }

    #[test]
    fn fallback_with_a_broken_gitdir_file() {
        let (_d, home, root) = home_with("Source/app");
        fs::write(root.join(".git"), "gitdir: /nonexistent/x\n").unwrap();
        assert_eq!(identity_for_root(&root, &home), "~/Source/app");
    }

    #[test]
    fn folder_equal_to_home_is_a_tilde() {
        let (_d, home, _) = home_with("Source/app");
        assert_eq!(identity_for_root(&home, &home), "~");
    }

    #[test]
    fn outside_home_uses_the_absolute_canonical_path() {
        let (_d, home, _) = home_with("Source/app");
        let other = TempDir::new().unwrap();
        let root = other.path().join("proj");
        fs::create_dir_all(&root).unwrap();
        let id = identity_for_root(&root, &home);
        assert_eq!(id, canon(&root));
        assert!(id.starts_with('/'));
    }

    #[test]
    fn symlinked_home_is_resolved() {
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real");
        fs::create_dir_all(real.join("Source/app")).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(
            identity_for_root(&link.join("Source/app"), &link),
            "~/Source/app"
        );
        assert_eq!(
            identity_for_root(&real.join("Source/app"), &link),
            "~/Source/app"
        );
    }

    #[test]
    fn a_remote_identity_never_equals_a_path_identity() {
        let (_d, home, root) = home_with("acme/api");
        let path_id = identity_for_root(&root, &home);
        assert_eq!(path_id, "~/acme/api");
        write_git_config(&root, &origin("https://github.com/acme/api.git"));
        let remote_id = identity_for_root(&root, &home);
        assert_eq!(remote_id, "acme/api");
        assert_ne!(path_id, remote_id);
    }

    #[test]
    fn path_identities_encode_odd_bytes() {
        let dir = TempDir::new().unwrap();
        let home = dir.path().canonicalize().unwrap().join("home");
        fs::create_dir_all(&home).unwrap();
        let mk = |name: &[u8]| {
            let p = home.join(OsStr::from_bytes(name));
            // APFS refuses non-UTF-8 names; the path is then used as given.
            let _ = fs::create_dir_all(&p);
            identity_for_root(&p, &home)
        };
        let non_utf8 = mk(b"bad\xff\xfe");
        let other_non_utf8 = mk(b"bad\xfe\xff");
        let newline = mk(b"a\nb");
        let tab = mk(b"a\tb");
        let percent = mk(b"100%");
        let encoded_lookalike = mk(b"100%25");
        let tilde = mk(b"~x");
        let space = mk(b"my app");
        assert_eq!(non_utf8, "~/bad%FF%FE");
        assert_eq!(other_non_utf8, "~/bad%FE%FF");
        assert_eq!(newline, "~/a%0Ab");
        assert_eq!(tab, "~/a%09b");
        assert_eq!(percent, "~/100%25");
        assert_eq!(encoded_lookalike, "~/100%2525");
        assert_eq!(tilde, "~/%7Ex");
        assert_eq!(space, "~/my app");
        let all = [
            non_utf8,
            other_non_utf8,
            newline,
            tab,
            percent,
            encoded_lookalike,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn comments_and_quotes_in_url_values() {
        let cases = [
            ("git@h:me/app.git # mirror", Some("me/app")),
            ("git@h:me/app.git ; mirror", Some("me/app")),
            ("\"git@h:me/app.git\" ; mirror", Some("me/app")),
            ("\"git@h:me/app.git\"", Some("me/app")),
            ("\"git@h:me/app.git", None),
            ("git@h:me/app.git\" ", None),
        ];
        for (value, want) in cases {
            let (_d, home, root) = home_with("Source/app");
            write_git_config(&root, &origin(value));
            let got = identity_for_root(&root, &home);
            let want = want.map_or("~/Source/app".to_string(), str::to_string);
            assert_eq!(got, want, "{value}");
        }
    }

    #[test]
    fn section_header_variants_and_ignored_keys() {
        let ok = [
            "[REMOTE \"origin\"]\n\turl = git@h:me/app.git\n",
            "[remote  \"origin\"]\n\turl = git@h:me/app.git\n",
            "[remote \"origin\"]\n\tURL = git@h:me/app.git\n",
        ];
        for body in ok {
            let (_d, home, root) = home_with("Source/app");
            write_git_config(&root, body);
            assert_eq!(identity_for_root(&root, &home), "me/app", "{body}");
        }
        let ignored = [
            "[remote \"Origin\"]\n\turl = git@h:me/app.git\n",
            "[remote \"origin\"]\n\tpushurl = git@h:me/app.git\n",
            "[url \"git@h:me/\"]\n\tinsteadOf = origin:\n",
            "[remote]\n\turl = git@h:me/app.git\n",
        ];
        for body in ignored {
            let (_d, home, root) = home_with("Source/app");
            write_git_config(&root, body);
            assert_eq!(identity_for_root(&root, &home), "~/Source/app", "{body}");
        }
    }

    #[test]
    fn a_repeated_url_key_first_wins() {
        let (_d, home, root) = home_with("Source/app");
        write_git_config(
            &root,
            "[remote \"origin\"]\n\turl = git@h:first/one.git\n\turl = git@h:second/two.git\n",
        );
        assert_eq!(identity_for_root(&root, &home), "first/one");
    }

    #[test]
    fn insteadof_does_not_rewrite_the_url() {
        let (_d, home, root) = home_with("Source/app");
        write_git_config(
            &root,
            "[url \"git@h:evil/\"]\n\tinsteadOf = git@h:me/\n[remote \"origin\"]\n\turl = git@h:me/app.git\n",
        );
        assert_eq!(identity_for_root(&root, &home), "me/app");
    }

    #[test]
    fn reading_the_remote_executes_nothing() {
        let (d, home, root) = home_with("Source/app");
        let sentinel = d.path().join("sentinel");
        let cmd = format!("sh -c 'touch {}'", sentinel.display());
        write_git_config(
            &root,
            &format!(
                "[core]\n\tfsmonitor = {cmd}\n\tsshCommand = {cmd}\n\thooksPath = {cmd}\n{}",
                origin("git@github.com:me/app.git")
            ),
        );
        assert_eq!(identity_for_root(&root, &home), "me/app");
        assert!(!sentinel.exists());
    }

    #[test]
    fn includes_are_not_followed() {
        let (_d, home, root) = home_with("Source/app");
        let git = root.join(".git");
        write_git_config(
            &root,
            &format!(
                "[include]\n\tpath = other\n[includeIf \"gitdir:/\"]\n\tpath = other\n{}",
                origin("git@github.com:me/app.git")
            ),
        );
        fs::write(
            git.join("other"),
            "[remote \"upstream\"]\n\turl = https://github.com/evil/repo.git\n",
        )
        .unwrap();
        assert_eq!(identity_for_root(&root, &home), "me/app");
    }

    #[test]
    fn a_directory_in_place_of_the_config_is_no_remote() {
        let (_d, home, root) = home_with("Source/app");
        fs::create_dir_all(root.join(".git/config")).unwrap();
        assert_eq!(identity_for_root(&root, &home), "~/Source/app");
    }

    #[test]
    fn an_oversize_config_is_no_remote() {
        let (_d, home, root) = home_with("Source/app");
        let url = origin("git@h:me/app.git");
        let pad = "# x\n".repeat(MAX_READ as usize / 4);
        write_git_config(&root, &format!("{pad}{url}"));
        assert_eq!(identity_for_root(&root, &home), "~/Source/app");
        // Just under the limit still works.
        let pad = "#".repeat(MAX_READ as usize - url.len() - 1);
        write_git_config(&root, &format!("{pad}\n{url}"));
        assert_eq!(identity_for_root(&root, &home), "me/app");
    }

    #[test]
    fn a_fifo_in_place_of_the_config_does_not_hang() {
        let (_d, home, root) = home_with("Source/app");
        fs::create_dir_all(root.join(".git")).unwrap();
        let path = std::ffi::CString::new(root.join(".git/config").as_os_str().as_bytes()).unwrap();
        // SAFETY: `path` is a valid NUL-terminated string.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert_eq!(identity_for_root(&root, &home), "~/Source/app");
    }
}
