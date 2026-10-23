<h1 align="center">envy</h1>

<p align="center">
  <b>Your secrets in the Keychain. Your shell, one command away from any persona.</b><br>
  Load a named set of credentials and variables into your <i>current</i> zsh shell,<br>
  and flip to another set without leaving a trace of the first.
</p>

```console
$ envy work         # GITHUB_TOKEN, AWS_PROFILE, ... are now set in this shell
$ envy personal     # work's variables are gone, personal's are set
$ envy --off        # nothing from envy is left in your environment
```

<p align="center"><sub>macOS &middot; zsh &middot; written in Rust</sub></p>

---

## The problem

Your shell needs credentials: a GitHub token, cloud keys, API keys. Where do
they live today?

- **In plain text.** `export GITHUB_TOKEN=...` in `~/.zshrc`, or a `.env` file,
  or a dotfiles repo. Anything that reads your disk, your backups or your
  screen share gets them, and it is one careless `git add .` from being public.
- **Everywhere, all the time.** Every terminal and every project gets every
  secret whether it needs it or not.
- **Awkward to switch.** Work account today, personal account tonight? You
  hand-edit exports, or keep several `.env` files and remember to `source` the
  right one and to unset the last one.

Tools like [envchain](https://github.com/sorah/envchain) fix the first part by
keeping secrets in the Keychain, but they run **one command at a time**
(`envchain work some-command`). That is great for scripts. It is awkward when
you want your whole interactive shell to *be* "work" for the afternoon.

## What envy does

envy keeps your variables in named sets called **namespaces**. Secrets are stored
in the macOS Keychain, never in a file. You load a namespace into the shell
you are already in, and loading another one **cleanly replaces** the first.

```console
$ envy work --new
$ envy work --secret GITHUB_TOKEN AWS_SECRET_ACCESS_KEY    # hidden prompts, stored in the Keychain
$ envy work --plain AWS_REGION=eu-west-1 AWS_PROFILE=prod  # no prompt, stored in a readable file

$ envy work --list
namespace: work

GITHUB_TOKEN           @keychain
AWS_SECRET_ACCESS_KEY  @keychain
AWS_REGION             "eu-west-1"
AWS_PROFILE            "prod"

$ envy work                  # load it
$ echo $AWS_REGION
eu-west-1
$ envy personal              # switch: everything work set is removed first
$ envy --off                 # unload
```

|  | Dotfiles / `.env` | envchain | **envy** |
|---|---|---|---|
| Secrets at rest | plain text | Keychain | **Keychain** |
| Scope | every shell, always | one command | **the current shell, until you switch** |
| Switching personas | edit and `source` by hand | pick per command | **`envy other`: the old set is removed** |
| Non-secret values (region, org) | in the file | no, everything is a secret | **yes, in a readable TOML file** |
| Keeping accounts consistent | by hand | by hand | **linked namespaces** |

## How it works

A program can't change its parent shell's environment, so envy is two small
pieces: a binary that prints `export` and `unset` lines, and a shell function
that `eval`s them.

```text
            envy work
                │
                ▼
   ┌─────────────────────┐       ┌───────────────────────────────┐
   │  zsh function       │ ────▶ │  envy binary                  │
   │  (from --init zsh)  │       │   reads  ~/.config/envy/      │
   └─────────────────────┘       │          work.toml            │
                ▲                │   reads  macOS Keychain       │
                │                │          (secrets only)       │
                │                └───────────────┬───────────────┘
                │                                │
                └──── export A='…'  export B='…' ┘
                      (unset the previous namespace's names first)
```

Plain values and variable names live in `~/.config/envy/<namespace>.toml`.
Secret values live only in the Keychain.

## Install

You need macOS, zsh and a Rust toolchain.

```console
$ cargo install --git https://github.com/christogav/envy
```

or, from a clone of this repository:

```console
$ cargo install --path .
```

If `envy` isn't found afterwards, make sure cargo's bin directory is on your
`PATH`, or install somewhere that already is, for example
`cargo install --path . --root ~/.local`.

Then add this line to `~/.zshrc` and open a new shell:

```zsh
eval "$(envy --init zsh)"
```

The line is required: it defines the shell function above. If you run the
binary directly it refuses to print anything that could expose secrets.

## Usage

The namespace comes first and every action is a flag, so a namespace can have
any name (even `off` or `new`).

| Command | What it does |
|---|---|
| `envy`, `envy --list` (`--ls`) | List namespaces and show which one is active (names only). |
| `envy <ns> --list` (`--ls`) | Show the variables in `<ns>`: its link group, and each variable's value: plain values quoted (control characters escaped), secrets as `@keychain`, never their value. Nothing is read from the Keychain. |
| `envy <ns>` | Load `<ns>`, first removing what the previous namespace set. |
| `envy --off` | Remove what the active namespace set. |
| `envy <ns> --new` | Create an empty namespace. |
| `envy <ns> --like <other>` | Create `<ns>` as a copy of `<other>`: copies its names and plain values, then prompts for each secret. One-time copy. |
| `envy <ns> --secret NAME [NAME ...]` | Add or change secrets. Each value is typed at a hidden prompt and stored in the Keychain; a secret value is never accepted on the command line. |
| `envy <ns> --plain NAME[=value] [...]` | Add or change non-secret variables, stored in the file. `NAME=value` sets the value with no prompt; a bare `NAME` asks at a visible prompt. An inline value is written to the file in plain text and also stays in your shell history, so for anything sensitive use a bare `--plain NAME` or `--secret NAME`. |
| `envy <ns> --edit` | Open the namespace file in `$VISUAL`/`$EDITOR` (then `vi`). |
| `envy <ns> --rm` | Delete the namespace and its Keychain items (asks first). |
| `envy <ns> --link <group>` | Link `<ns>` into a group (see below). `--new --link <group>` links at creation. |
| `envy <ns> --unlink` | Leave the group; variables are kept. |
| `envy --init zsh` | Print the shell function for `~/.zshrc`. |
| `envy --help`, `--version` | Help and version. |

`--secret` and `--plain` each take one or more names and can be combined:

```console
$ envy work --secret GITHUB_TOKEN OPENAI_KEY --plain AWS_REGION=eu-west-1 AWS_PROFILE
```

Everything is asked first and then saved in one go, so cancelling any prompt
changes nothing.

An unknown namespace is an error, never an automatic create, so a typo can't
make a new namespace.

## Namespace files

Each namespace is a TOML file at `~/.config/envy/<namespace>.toml` (or under
`$ENVY_CONFIG_DIR`, which must be an absolute path):

```toml
link = "aws"                # optional link group, see below

[vars]
AWS_REGION = "eu-west-1"    # plain value, stored right here
GITHUB_TOKEN = "@keychain"  # secret: the value is in the Keychain
```

- The value `@keychain` marks a secret. The file never contains a secret
  value, so it is safe to open, diff or share.
- In `--edit`, change a line from `@keychain` to a real value to make it
  plain, or the other way round to make it secret (you are prompted for the
  value). A plain value that is literally `@keychain` is not possible.
- Secrets are stored as generic passwords in your login Keychain: service
  `envy.<namespace>`, account = the variable name. Look for `envy.` in
  Keychain Access if you ever need to find them.
- envy edits these files with comments and ordering preserved, and values are
  used literally (no `$VAR` expansion).
- Variable names must be valid shell identifiers. Names that zsh treats
  specially (`PATH`, `HOME`, `IFS`, `SECONDS`, `UID`, the `PS*` prompts, ...),
  plus `SHELL`, `USER` and anything starting `DYLD_` or `LD_`, are refused,
  because exporting them would break or hijack your shell.

## Linked namespaces

Namespaces are independent by default. If you want several to always have the
same variable names (say `work-aws` and `personal-aws`), link them:

```console
$ envy work-aws --link aws
$ envy personal-aws --link aws   # prompts for any names it is missing
```

Members of a group always have the same names and the same secret/plain
flag for each name; values stay per namespace. Adding a name to one member
prompts for its value in the others, and removing a name removes it from the
others (after one confirmation that lists what will be deleted, including
Keychain items). A linked namespace that has drifted out of line (for example
after a hand edit) refuses to load and tells you what is missing.

## Security model

**What envy protects**

- **At rest.** Secrets are only in the Keychain. The config files contain no
  secret values, so they are safe to open, diff, commit or screen-share.
- **In transit.** Secret values leave envy only as the `export` lines your shell
  evaluates. They are never put in command arguments, logs, status output or
  error messages, and core dumps are disabled.
- **By accident.** The binary refuses to print `export` lines to a terminal, or
  when it wasn't called by the shell function, so running it directly (or in a
  script that redirects output to a log) can't spill secrets.
- **At the prompt.** Secrets are typed at a hidden prompt on the terminal
  (`/dev/tty`) and are never accepted as command-line arguments. A pasted
  secret loses tabs and other control characters.

**What it does not protect**

- Once a namespace is loaded, its variables are in your shell's environment, so
  `env`, `printenv` and every child process can see them. That is the point of
  loading them, but know it.
- Anything that can use your unlocked login session can ask the Keychain for
  your secrets. Reading a secret needs only an unlocked login Keychain.
- Plain values are plain: they live in a readable file, and an inline
  `--plain NAME=value` also lands in your shell history.
- envy is unsigned, so macOS may ask you to "allow access" the first time, and
  again after you rebuild or upgrade it.

## Known limitations

- macOS and zsh only. No bash or fish, no syncing between machines, no
  stacking of several namespaces at once.
- The list of refused variable names is not complete yet. `KEYTIMEOUT`,
  `LISTMAX`, `MAILCHECK`, `signals`, `ERRNO` and `ZLE_RPROMPT_INDENT` are
  still accepted, and using one as a variable name makes zsh misread its value
  (it can print part of the value in an error and stop loading midway).
  Don't use those names.
- If you decline the cleanup question in `--edit` after deleting a secret, the
  old Keychain item stays behind with nothing pointing to it. Remove it in
  Keychain Access (search `envy.`).
- Renaming a namespace or variable isn't supported: copy with `--like`,
  `--secret` or `--plain`, then remove the old one.

## Development

```console
$ cargo test
$ cargo clippy --all-targets -- -D warnings
```

One test talks to your real login Keychain, so it is ignored by default. Run it
once with `cargo test -- --ignored mac_keychain_roundtrip`.

## License

[MIT](LICENSE)
