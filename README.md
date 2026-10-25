<h1 align="center">envy</h1>

<p align="center">
  <b>Switch between work and personal credentials in your current zsh shell,<br>
  with the secrets kept in the macOS Keychain.</b><br>
  One command loads a named set into the shell you are already in;<br>
  one command takes out exactly what it set.
</p>

<p align="center">
  <a href="https://github.com/christogav/envy/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/christogav/envy/ci.yml?branch=main&label=CI"></a>
  <a href="https://github.com/christogav/envy/actions/workflows/deny.yml"><img alt="Dependency checks" src="https://img.shields.io/github/actions/workflow/status/christogav/envy/deny.yml?branch=main&label=dependencies"></a>
  <a href="https://github.com/christogav/envy/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/christogav/envy"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/github/license/christogav/envy"></a>
  <img alt="Platform: macOS, zsh" src="https://img.shields.io/badge/platform-macOS%20%C2%B7%20zsh-lightgrey">
</p>

```console
$ envy work         # GITHUB_TOKEN, AWS_PROFILE, ... are now set in this shell
$ envy personal     # personal's variables are added to work's
$ envy --off work   # work's are gone, personal's stay
$ envy --off        # nothing from envy is left in your environment
```

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
- **Rebuilt by every teammate.** A project needs the same ten variables on every
  machine. The list lives in a wiki or in people's heads, and everyone's first
  day starts with "which variables do I need?"

envy keeps secrets in the Keychain, never in a file. It loads a named set of
them (a **namespace**) into the shell you are already in, and removes exactly
what it set when you are done. A project can commit its list of variables so a
teammate only has to supply their own secrets.

### How it compares

| | Dotfiles / `.env` | [envchain](https://github.com/sorah/envchain) | [direnv](https://direnv.net) | **envy** |
|---|---|---|---|---|
| Where secrets live | plain text | Keychain | wherever your `.envrc` fetches them from; direnv stores none | **Keychain** |
| When variables load | when you `source` the file | for one command | automatically when you enter a directory | **when you ask, by name** |
| Switching accounts | edit and `source` by hand | pick one per command | by directory | **`envy other`** |
| Sharing with a team | copy the file around | no | commit an `.envrc` that fetches them | **commit `.envy/`; teammates supply only their secrets** |

If you want variables to follow the directory you are in automatically, direnv
is the better fit. envy loads by name, when you ask.

## Install

You need macOS (Apple Silicon or Intel) and zsh.

```console
$ brew install christogav/tap/envy
```

Then add this line to `~/.zshrc` and open a new shell:

```zsh
eval "$(envy --init zsh)"
```

The line is required: it defines the shell function that makes loading work.
[Other ways to install, and upgrade notes.](docs/install.md)

## Quick start

```console
$ envy work --new                              # create a namespace called "work"
$ envy work --secret GITHUB_TOKEN              # hidden prompt, stored in the Keychain
$ envy work --plain AWS_REGION=eu-west-1       # no prompt, stored in a readable file
$ envy work                                    # load it into this shell
$ echo $AWS_REGION
eu-west-1
$ envy --off                                   # take everything back out
```

## Everyday commands

| Command | What it does |
|---|---|
| `envy <ns>` | Load `<ns>`, adding it to whatever is already loaded. |
| `envy --off <ns>` | Remove just `<ns>`. |
| `envy --off` | Remove everything envy set. |
| `envy` | List your namespaces and mark the loaded ones with `*`. |
| `envy <ns> --list` | Show a namespace's variables (secrets are never shown). |
| `envy <ns> --secret NAME` / `--plain NAME=value` | Add a secret (hidden prompt) or a plain value. |
| `envy <ns> --new` / `--edit` / `--rm` | Create, edit or delete a namespace. |

Every command, with the details: [command reference](docs/commands.md).

## Stacking

Several namespaces can be loaded at once, so a standing set of credentials and
the ones for the project in front of you can sit side by side:

```console
$ envy common       # your everyday credentials
$ envy web          # the project's, on top
$ envy --off web    # take just the project's off again
```

If two loaded namespaces set the same variable, the one loaded last wins and
envy warns you, naming both. Namespaces you [link](docs/namespace-files.md#linked-namespaces)
(say `work-aws` and `personal-aws`) are alternatives, so loading one swaps out
the other. [All the rules.](docs/stacking.md)

## Project config

A project can commit the namespaces it needs:

```console
$ cd ~/src/api
$ envy dev --new --project                      # creates .envy/dev.toml in the repository
$ envy dev --plain AWS_REGION=eu-west-1 --secret API_TOKEN
$ git add .envy && git commit -m "Describe the dev environment"
```

The file lists the variables and holds the plain values; every secret is just a
marker. A teammate who clones the repository runs `envy dev`, reads what it
will load and says yes, then types their own secrets once. Nothing from a
cloned repository loads without that confirmation.
[How project config works.](docs/project-config.md)

## How it works

A program can't change its parent shell's environment, so envy is two small
pieces: a binary that prints `export` and `unset` lines, and a shell function
that `eval`s them. Plain values live in `~/.config/envy/<namespace>.toml`;
secret values live only in the Keychain. [More detail and a diagram.](docs/how-it-works.md)

## Is it safe?

- Secrets are stored only in the Keychain. The config files contain markers,
  never values, so they are safe to diff, commit or screen-share.
- A secret is typed at a hidden prompt and never accepted on the command line.
  It leaves envy only as the `export` lines your shell evaluates, and never
  appears in arguments, logs, status output or error messages.
- The binary refuses to print those lines to a terminal or a file, so running it
  directly can't spill them.
- A project namespace never loads without a confirmation that shows every
  variable and value.

What it does not do: once a namespace is loaded, its variables are in your
shell's environment, so every child process can see them. And the binaries are
not signed with an Apple Developer ID. [The full security model, and known
limitations.](docs/security.md)

## Documentation

- [Command reference](docs/commands.md)
- [Stacking](docs/stacking.md)
- [Namespace files and linked namespaces](docs/namespace-files.md)
- [Project config](docs/project-config.md)
- [How it works](docs/how-it-works.md)
- [Security model and known limitations](docs/security.md)
- [Installing, and upgrade notes](docs/install.md)
- [Releases](https://github.com/christogav/envy/releases)

## Development

```console
$ cargo test
$ cargo clippy --all-targets -- -D warnings
```

One test talks to your real login Keychain, so it is ignored by default. Run it
once with `cargo test -- --ignored mac_keychain_roundtrip`.

## License

[MIT](LICENSE)
