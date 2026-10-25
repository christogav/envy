# How it works

Part of the [envy README](../README.md).

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
                      (`--off` unsets a namespace's names)
```

Plain values and variable names live in `~/.config/envy/<namespace>.toml`.
Secret values live only in the Keychain.
