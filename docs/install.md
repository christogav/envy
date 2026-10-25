# Installing envy

Part of the [envy README](../README.md).

The quickest way is Homebrew, as in the README:

```console
$ brew install christogav/tap/envy
```

Then add this line to `~/.zshrc` and open a new shell:

```zsh
eval "$(envy --init zsh)"
```

The line is required: it defines the shell function that makes loading work. If
you run the binary directly it refuses to print anything that could expose
secrets.

## Upgrading

The binaries are not signed with an Apple Developer ID, so after an upgrade
macOS may ask once whether `envy` can read your Keychain items again. That is
expected.

## From source

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
