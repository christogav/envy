# Security model

Part of the [envy README](../README.md).

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
  error (see [Project config](project-config.md)). Until you agree, envy only
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

- macOS and zsh only. No bash or fish, no syncing between machines. One
  `envy` command loads one namespace; there is no `envy a b`.
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
