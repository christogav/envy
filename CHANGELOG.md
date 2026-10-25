# Changelog

## 0.2.0

### Added

- **Stacking.** Several namespaces can be loaded at once: `envy <ns>` adds to
  what is already loaded instead of replacing it, so a standing set of
  credentials and a project's can sit side by side.
- `envy --off <name>` (or `envy <name> --off`) removes one namespace. A variable
  it was winning gets its value back from the next namespace that sets it.
  Plain `envy --off` still removes everything.
- If two loaded namespaces set the same variable, the one loaded last wins and
  envy warns on stderr, naming the variable and both namespaces.
- `envy` lists every loaded namespace and, when more than one is loaded, the
  order they were loaded in.

### Changed

- **Loading a second namespace now adds it** rather than replacing the first.
  Namespaces in the same [link group](https://github.com/christogav/envy/blob/main/docs/namespace-files.md#linked-namespaces)
  still replace each other; to drop an unlinked one, use `envy --off <name>`.
- `ENVY_ACTIVE` is now a space-separated list of the loaded namespaces, oldest
  first. `ENVY_STACK` is new and holds per-namespace data. `ENVY_SOURCE` is no
  longer set. A shell opened before the upgrade keeps working.
- The README is shorter, with the detail moved into `docs/`.

Existing Homebrew users may see a one-off macOS Keychain prompt after upgrading,
because the binaries are not signed with an Apple Developer ID.

## 0.1.0

First release: namespaces of secrets (in the macOS Keychain) and plain values,
loaded into the current zsh shell, linked namespaces, and project config.
