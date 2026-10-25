# Project config

Part of the [envy README](../README.md).

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

**Which ones are loaded.** envy records its state in your shell:
`ENVY_ACTIVE` lists the active namespaces, space separated, oldest first (handy
in a prompt), `ENVY_VARS` is the flat list of variable names they set, and
`ENVY_STACK` holds the per-namespace data: each one's name, level (`user`, or
the project's `.envy` folder) and variables, never a value. `envy --list` uses
the level to star the one you loaded (even when it is shadowed, after
`--user`), or says `(from another folder)` when you loaded it in another
project. Levels are only compared, never run or used as a path, and a
namespace file can't set any of these. An older envy's `ENVY_SOURCE` is no
longer set; a value left in a running shell is read as before and cleared the
next time you load or remove a namespace.

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
