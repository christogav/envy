# Namespace files

Part of the [envy README](../README.md).

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
