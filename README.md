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

You need macOS (Apple Silicon or Intel) and zsh.

```console
$ brew install christogav/tap/envy
```

Then add this line to `~/.zshrc` and open a new shell:

```zsh
eval "$(envy --init zsh)"
```

The line is required: it defines the shell function above. If you run the
binary directly it refuses to print anything that could expose secrets.

The binaries aren't signed with an Apple Developer ID, so after an upgrade
macOS may ask once whether `envy` can read your Keychain items again. That is
expected.

### From source

You need a Rust toolchain.

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

## Usage

The namespace comes first and every action is a flag, so a namespace can have
any name (even `off` or `new`).

| Command | What it does |
|---|---|
| `envy`, `envy --list` (`--ls`) | List namespaces and show which one is active (names only). Inside a project, each level is listed: the project's first, then yours, with names a nearer level hides marked `(shadowed)`. |
| `envy <ns> --list` (`--ls`) | Show the variables in `<ns>`: a `source:` line (`project (<file>)` or `user`), its link group, and each variable's value: plain values quoted (control characters escaped), secrets as `@keychain`, never their value. Nothing is read from the Keychain. |
| `envy <ns>` | Load `<ns>`, first removing what the previous namespace set. |
| `envy --off` | Remove what the active namespace set. |
| `envy <ns> --new` | Create an empty namespace: in the nearest project `.envy/` folder if there is one, otherwise your own. |
| `envy <ns> --new --project` | Create the namespace in a project `.envy/` folder, making the folder if needed: at the git repository root inside a repository, otherwise in the current directory. Refused in your home directory or above it. |
| `envy <ns> --user`, `envy <ns> ... --user` | Use your own `<ns>` even when the project has one with the same name. Works with every command that takes a namespace. |
| `envy <ns> --like <other>` | Create `<ns>` as a copy of `<other>`: copies its names and plain values, then prompts for each secret. One-time copy. |
| `envy <ns> --secret NAME [NAME ...]` | Add or change secrets. Each value is typed at a hidden prompt and stored in the Keychain; a secret value is never accepted on the command line. |
| `envy <ns> --plain NAME[=value] [...]` | Add or change non-secret variables, stored in the file. `NAME=value` sets the value with no prompt; a bare `NAME` asks at a visible prompt. An inline value is written to the file in plain text and also stays in your shell history, so for anything sensitive use a bare `--plain NAME` or `--secret NAME`. |
| `envy <ns> --edit` | Open the namespace file in `$VISUAL`/`$EDITOR` (then `vi`). |
| `envy <ns> --rm` | Delete the namespace and its Keychain items (asks first). For a project namespace the shared Keychain items are kept unless you say otherwise. |
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
  because exporting them would break or hijack your shell. Every name
  starting `ENVY_` is refused too: that prefix is reserved for envy's own
  settings (`ENVY_CONFIG_DIR`, `ENVY_EVAL`) and shell state.

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

## Project config

A project can commit the namespaces it needs, so a teammate who clones it only
has to supply their own secrets. The files say which variables exist and hold
the plain values; every secret is `@keychain`, and each person types their own
value once.

```text
api/
├── .git/
└── .envy/
    ├── dev.toml      # same format as ~/.config/envy/dev.toml
    └── ci.toml
```

```console
$ cd ~/src/api
$ envy dev --new --project              # makes .envy/dev.toml at the repository root
$ envy dev --plain AWS_REGION=eu-west-1 --secret API_TOKEN
$ git add .envy && git commit -m "Describe the dev environment"
```

**Where envy looks.** envy finds the nearest `.envy/` folder by walking up from
the current directory, the way git finds a repository, and stops before your
home directory (your home is never a project; `~/.config/envy` is your own
level). From `~/src/api/web/src` it finds `~/src/api/web/.envy` and
`~/src/api/.envy` (nearest first) if they exist. A name resolves to exactly one
file: the nearest project folder that has it, otherwise your own.

**When both have it, the project wins**, with a note on stderr:

```console
$ envy dev
note: project namespace "dev" shadows your user-level "dev"; use --user for yours
$ envy dev --user                       # yours instead
```

Every command follows the same rule (`--secret`, `--plain`, `--edit`, `--list`,
`--rm`, `--like`, `--link`, `--unlink`), and `--user` forces your own. `--new`
creates in the nearest `.envy/` folder when there is one and in your own level
otherwise; `--new --user` always creates your own, and `--new --project`
creates the project's first file: at the git repository root inside a
repository, otherwise in the current directory, and never in your home
directory or a folder above it. Link groups stay within one level.

- `--user` also applies to the `--like` source: `envy copy --new --like dev
  --user` copies *your* `dev` into your own level. So a project namespace can't
  be copied into your own level that way; to copy the project's, leave out
  `--user` (the copy then goes where `--new` puts it).
- `--new` says nothing about the other level: a name you create can shadow, or
  be shadowed by, the same name at the other level. `envy --list` shows it.

```console
$ envy --list
project: /Users/you/src/api/.envy
  ci
* dev
user:
  dev (shadowed)
  personal
$ envy dev --list
note: project namespace "dev" shadows your user-level "dev"; use --user for yours
namespace: dev (active)
source: project (/Users/you/src/api/.envy/dev.toml)

AWS_REGION  "eu-west-1"
API_TOKEN   @keychain
```

**The first load.** The first time you load a project namespace, envy shows
what it will do and asks:

```text
Project namespace "dev" from acme/api
file: /Users/you/src/api/.envy/dev.toml

AWS_REGION  "eu-west-1"
API_TOKEN   @keychain
secret API_TOKEN: you will be asked for it

Allow envy to load these variables into your current shell [y/N]:
```

Say yes, and envy asks at a hidden prompt for each secret you don't have yet,
saves them in the Keychain, and loads the namespace, all in one command.
Cancel anything and nothing is saved or loaded. After that, `envy dev` just
loads. This first load needs a terminal: run without one (in a script, say),
an untrusted project namespace is an error and nothing is printed on stdout.

**What the confirmation protects.** A project file can set any variable envy
does not refuse, `NODE_OPTIONS` or `GIT_SSH_COMMAND` included, so loading one
from a repository you didn't write is like running its code. The question shows
every variable and value before anything happens. Your yes is recorded for
those exact file contents **and** that checkout's path, outside the repository:

- a changed file (a `git pull`, a hand edit) asks again, and says it changed;
- a new clone, a copied folder or a moved checkout asks once, even if its
  remote names a project you already use;
- commands that change a project namespace (`--secret`, `--plain`, `--edit`,
  `--link`, `--unlink`) first ask about the file as it is now if you haven't
  trusted it, so a line slipped in by a pull is never trusted silently. A file
  you create with `--new` is trusted directly. Your own namespaces are never
  asked about.

**Which secrets a project uses.** Secrets are filed under a project identity:

- in a git repository, `org/project` from the `upstream` remote if there is one,
  else `origin` (`git@github.com:acme/api.git` and
  `https://github.com/acme/api` are both `acme/api`). No host, no username or
  token from the URL, lowercased, subgroups kept (`group/sub/project`);
- otherwise (no git, no remote, a URL envy can't read), the folder's path,
  `~/...` relative to your home (the full path outside it).

So every clone of a project on your machine, and every fork (with `upstream`
pointing at the original), shares one set of secrets: that is the point, and
you are not asked for them again. The confirmation shows the identity and
which secrets are already in your Keychain, so you can see when that happens.
The identity comes from the folder's own **local** git configuration
(`.git/config`), not from any file the repository commits. But a folder you
copied or unzipped that includes its own `.git/` brings its remotes with it,
so it can claim any `org/project`, and once you say yes its namespace reads
that project's secrets you already have. The confirmation shows the identity
and which secrets already exist (with a caution line when they were saved
from another checkout): say yes only if this folder really is that project.
A dotfiles repository in your home directory does not lend its identity to
folders under it, and a `.git` owned by another account is ignored.

Project secrets are Keychain items with service `envy.project/<identity>/<ns>`
(for example `envy.project/acme/api/dev`), account = the variable name. Every
envy item still starts with `envy.`.

**Which one is loaded.** Besides `ENVY_ACTIVE` (the name) and `ENVY_VARS` (the
variables it set), envy records `ENVY_SOURCE` in your shell: `user`, or the
project's `.envy` folder. `envy --list` uses it to star the level you loaded
(even when it is shadowed, after `--user`), or says `(from another folder)` when
you loaded it in another project. It is only compared, never run or used as a
path, and a namespace file can't set any of the three.

**Removing.** `envy dev --rm` on a project namespace deletes the file from the
working tree (git status shows it). Its Keychain items are shared with every
other checkout and fork, so they are kept unless you answer yes to a second
question; envy then tells you which ones it kept.

**Limits.**

- `HOME` must be set: it is where the search stops.
- A `.envy` that is a symlink is ignored, so a repository can't point envy at
  another folder, and so is a `.envy` owned by another account (someone could
  plant one in a shared folder such as `/tmp` or `/Users/Shared`). Each one
  ignored gets a note on stderr, for example
  `note: ignoring /Users/Shared/.envy: it is not owned by you` or
  `note: ignoring /Users/you/src/api/.envy: it is a symlink`. A `.envy` folder
  that is your own config directory (`ENVY_CONFIG_DIR`) is your level, never a
  project level.
- A project file must be a regular file of at most 1 MiB; a FIFO, a device
  or a bigger file is an error.
- A project file that doesn't parse (or isn't a regular file) is an error, never
  a silent fallback to your own namespace of the same name; use `--user` to
  reach yours.

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
- **From a project you cloned.** A project namespace never loads, and is never
  trusted, without a confirmation that shows every variable and value; a
  changed file or a new checkout asks again, and with no terminal it is an
  error (see [Project config](#project-config)). Until you agree, envy only
  checks which secrets exist and reads none of them, so macOS's own Keychain
  access dialog never comes before envy's question.
- **From its own settings.** A namespace file can't set any variable starting
  `ENVY_`, so a project file can't redirect your config directory or trust
  records, or switch off the guard that keeps exports away from a terminal.

**What it does not protect**

- Once a namespace is loaded, its variables are in your shell's environment, so
  `env`, `printenv` and every child process can see them. That is the point of
  loading them, but know it.
- Anything that can use your unlocked login session can ask the Keychain for
  your secrets. Reading a secret needs only an unlocked login Keychain.
- Plain values are plain: they live in a readable file, and an inline
  `--plain NAME=value` also lands in your shell history.
- A project file can set any variable that isn't refused, and its values are
  exported as written. The first-load confirmation is the defence: read it
  before you say yes.
- A project's secrets are shared by every checkout and fork of it on your
  machine (they share an identity), and two projects with the same
  `org/project` on different hosts share them too. The confirmation shows the
  identity and which secrets you already have.
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
- Renaming or transferring a project's git remote changes its identity, so
  you are asked for its secrets again; the old items stay in the Keychain
  (search `envy.project/`).
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
