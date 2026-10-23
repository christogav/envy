//! Project identity: what a project's secrets are filed under.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Normalises a git remote URL to `org/project` (no host, lowercase).
///
/// Only the path after the host is used, so userinfo (credentials) in the URL
/// can never reach the result. Local paths and URLs with fewer than two path
/// segments give `None`.
pub fn identity_from_url(url: &str) -> Option<String> {
    let url = url.trim();
    let path = if let Some((scheme, rest)) = url.split_once("://") {
        if scheme.eq_ignore_ascii_case("file") {
            return None;
        }
        // `rest` is `[userinfo@]host[:port]/path`; everything up to the first
        // `/` is the authority and is discarded.
        let (authority, path) = rest.split_once('/')?;
        if authority.is_empty() {
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
    let path = path.split(['?', '#']).next().unwrap_or("");
    let mut segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let last = segments.pop()?;
    let last = last.strip_suffix(".git").unwrap_or(last);
    segments.push(last);
    if segments.len() < 2
        || segments
            .iter()
            .any(|s| s.is_empty() || *s == "." || *s == "..")
    {
        return None;
    }
    Some(segments.join("/").to_lowercase())
}

/// The identity of the project whose `.envy/` folder is in `root`: `org/project`
/// from the git remote (`upstream`, else `origin`), otherwise `root` relative
/// to `home` (both canonicalised), or the full canonical path outside `home`.
pub fn identity_for_root(root: &Path, home: &Path) -> String {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if let Some(id) = remote_identity(&root) {
        return id;
    }
    let home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    match root.strip_prefix(&home) {
        Ok(rel) if !rel.as_os_str().is_empty() => rel.to_string_lossy().into_owned(),
        _ => root.to_string_lossy().into_owned(),
    }
}

fn remote_identity(root: &Path) -> Option<String> {
    let remotes = remote_urls(&find_git_dirs(root)?);
    ["upstream", "origin"]
        .iter()
        .find_map(|name| remotes.get(*name).and_then(|url| identity_from_url(url)))
}

/// Walks up from `start` to the nearest `.git` and returns the directories
/// whose `config` files apply: the common directory first, then the git
/// directory itself. `None` when there is no repository or it is unreadable.
fn find_git_dirs(start: &Path) -> Option<Vec<PathBuf>> {
    let dir = start.ancestors().find(|d| d.join(".git").exists())?;
    let dot_git = dir.join(".git");
    let git_dir = if dot_git.is_dir() {
        dot_git
    } else {
        let text = fs::read_to_string(&dot_git).ok()?;
        let target = text.lines().next()?.trim().strip_prefix("gitdir:")?.trim();
        if target.is_empty() {
            return None;
        }
        dir.join(target)
    };
    let mut dirs = Vec::new();
    if let Ok(text) = fs::read_to_string(git_dir.join("commondir")) {
        let common = text.trim();
        if !common.is_empty() {
            dirs.push(git_dir.join(common));
        }
    }
    dirs.push(git_dir);
    Some(dirs)
}

/// Reads `[remote "<name>"] url = ...` from each directory's `config`. Only
/// that one key is looked at; includes and every other setting are ignored.
fn remote_urls(git_dirs: &[PathBuf]) -> HashMap<String, String> {
    let mut remotes = HashMap::new();
    for dir in git_dirs {
        let Ok(text) = fs::read_to_string(dir.join("config")) else {
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
                    .or_insert_with(|| value.trim().trim_matches('"').to_string());
            }
        }
    }
    remotes
}

/// The remote name from the inside of a `[remote "name"]` header, if it is one.
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
    use std::fs;
    use std::path::PathBuf;
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
        let id = identity_from_url("ssh://user:pw@host.example/acme/api.git").unwrap();
        assert_eq!(id, "acme/api");
        let id = identity_from_url("https://user:p@ss@github.com/acme/api.git").unwrap();
        assert_eq!(id, "acme/api");
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
    fn identity_finds_the_repository_above_the_folder() {
        let (_d, home, repo) = home_with("Source/app");
        let sub = repo.join("sub");
        fs::create_dir_all(sub.join(".envy")).unwrap();
        write_git_config(
            &repo,
            "[remote \"origin\"]\n\turl = git@github.com:me/app.git\n",
        );
        assert_eq!(identity_for_root(&sub, &home), "me/app");
    }

    #[test]
    fn identity_follows_a_gitdir_file_to_the_common_dir() {
        let (d, home, root) = home_with("Source/wt");
        let main = d.path().join("main/.git");
        let gitdir = main.join("worktrees/wt");
        fs::create_dir_all(&gitdir).unwrap();
        fs::write(gitdir.join("commondir"), "../..\n").unwrap();
        fs::write(
            main.join("config"),
            "[remote \"origin\"]\n\turl = git@github.com:me/app.git\n",
        )
        .unwrap();
        fs::write(root.join(".git"), format!("gitdir: {}\n", gitdir.display())).unwrap();
        assert_eq!(identity_for_root(&root, &home), "me/app");
    }

    #[test]
    fn identity_falls_back_to_the_path_under_home() {
        // No .git at all.
        let (_d, home, root) = home_with("Source/app");
        assert_eq!(identity_for_root(&root, &home), "Source/app");
        // .git with no remote.
        write_git_config(&root, "[core]\n\tbare = false\n");
        assert_eq!(identity_for_root(&root, &home), "Source/app");
        // Unparseable URL.
        write_git_config(&root, "[remote \"origin\"]\n\turl = ../elsewhere\n");
        assert_eq!(identity_for_root(&root, &home), "Source/app");
        // Broken gitdir file.
        let (_d2, home2, root2) = home_with("Source/app");
        fs::write(root2.join(".git"), "gitdir: /nonexistent/x\n").unwrap();
        assert_eq!(identity_for_root(&root2, &home2), "Source/app");
    }

    #[test]
    fn identity_outside_home_uses_the_full_canonical_path() {
        let (_d, home, _) = home_with("Source/app");
        let other = TempDir::new().unwrap();
        let root = other.path().join("proj");
        fs::create_dir_all(&root).unwrap();
        assert_eq!(identity_for_root(&root, &home), canon(&root));
    }

    #[test]
    fn identity_resolves_a_symlinked_home() {
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real");
        fs::create_dir_all(real.join("Source/app")).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(
            identity_for_root(&link.join("Source/app"), &link),
            "Source/app"
        );
        assert_eq!(
            identity_for_root(&real.join("Source/app"), &link),
            "Source/app"
        );
    }

    #[test]
    fn reading_the_remote_executes_nothing() {
        let (d, home, root) = home_with("Source/app");
        let sentinel = d.path().join("sentinel");
        let cmd = format!("touch {}", sentinel.display());
        write_git_config(
            &root,
            &format!(
                "[core]\n\tfsmonitor = {cmd}\n\tsshCommand = {cmd}\n[include]\n\tpath = {cmd}\n[includeIf \"gitdir:{}\"]\n\tpath = {cmd}\n[remote \"origin\"]\n\turl = git@github.com:me/app.git\n",
                root.display()
            ),
        );
        assert_eq!(identity_for_root(&root, &home), "me/app");
        assert!(!sentinel.exists());
    }
}
