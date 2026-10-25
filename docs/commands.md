# Command reference

Part of the [envy README](../README.md).

The namespace comes first and every action is a flag, so a namespace can have
any name (even `off` or `new`).

| Command | What it does |
|---|---|
| `envy`, `envy --list` (`--ls`) | List namespaces and mark every active one with `*` (names only). With more than one active, a last line `active (oldest first): a, b` gives the order. Inside a project, each level is listed: the project's first, then yours, with names a nearer level hides marked `(shadowed)`. |
| `envy <ns> --list` (`--ls`) | Show the variables in `<ns>`: a `source:` line (`project (<file>)` or `user`), its link group, and each variable's value: plain values quoted (control characters escaped), secrets as `@keychain`, never their value. Nothing is read from the Keychain. |
| `envy <ns>` | Add `<ns>` to what is already loaded (see [Stacking](stacking.md)). A namespace linked to an active one replaces it; one that is already active is reloaded and moved to the top. |
| `envy --off` | Remove every active namespace: unset all the variables envy set. |
| `envy --off <ns>`, `envy <ns> --off` | Remove just `<ns>`. A variable it was winning gets its value back from the next namespace that sets it. An error if `<ns>` is not active. |
| `envy <ns> --new` | Create an empty namespace: in the nearest project `.envy/` folder if there is one, otherwise your own. |
| `envy <ns> --new --project` | Create the namespace in a project `.envy/` folder, making the folder if needed: at the git repository root inside a repository, otherwise in the current directory. Refused in your home directory or above it. |
| `envy <ns> --user`, `envy <ns> ... --user` | Use your own `<ns>` even when the project has one with the same name. Works with every command that takes a namespace. |
| `envy <ns> --like <other>` | Create `<ns>` as a copy of `<other>`: copies its names and plain values, then prompts for each secret. One-time copy. |
| `envy <ns> --secret NAME [NAME ...]` | Add or change secrets. Each value is typed at a hidden prompt and stored in the Keychain; a secret value is never accepted on the command line. |
| `envy <ns> --plain NAME[=value] [...]` | Add or change non-secret variables, stored in the file. `NAME=value` sets the value with no prompt; a bare `NAME` asks at a visible prompt. An inline value is written to the file in plain text and also stays in your shell history, so for anything sensitive use a bare `--plain NAME` or `--secret NAME`. |
| `envy <ns> --edit` | Open the namespace file in `$VISUAL`/`$EDITOR` (then `vi`). |
| `envy <ns> --rm` | Delete the namespace and its Keychain items (asks first). For a project namespace the shared Keychain items are kept unless you say otherwise. |
| `envy <ns> --link <group>` | Link `<ns>` into a group (see [Linked namespaces](namespace-files.md#linked-namespaces)). `--new --link <group>` links at creation. |
| `envy <ns> --unlink` | Leave the group; variables are kept. |
| `envy --init zsh` | Print the shell function for `~/.zshrc`. |
| `envy --help`, `--version` | Help and version. |

`envy <ns> --list` shows plain values and marks secrets, never revealing them:

```console
$ envy work --list
namespace: work

GITHUB_TOKEN           @keychain
AWS_SECRET_ACCESS_KEY  @keychain
AWS_REGION             "eu-west-1"
AWS_PROFILE            "prod"
```

`--secret` and `--plain` each take one or more names and can be combined:

```console
$ envy work --secret GITHUB_TOKEN OPENAI_KEY --plain AWS_REGION=eu-west-1 AWS_PROFILE
```

Everything is asked first and then saved in one go, so cancelling any prompt
changes nothing.

An unknown namespace is an error, never an automatic create, so a typo can't
make a new namespace.
