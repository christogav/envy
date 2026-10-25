# Stacking

Part of the [envy README](../README.md).

Several namespaces can be active at once, each added with `envy <ns>`. Say you
keep a standing `common` namespace and a `web` one for the project you are in:

```console
$ envy common
$ envy web                  # both are active; web was added last
$ envy --off common         # only web's variables are left
$ envy --off                # nothing is left
```

- **Later wins.** If a namespace you add sets a variable that an active one
  already sets, the one activated last wins, and envy warns on stderr, naming
  the variable (never its value) and both namespaces:

  ```console
  $ envy web
  warning: AWS_REGION is set by both "common" and "web"; "web" wins (it was activated last)
  ```

- **Removing one.** `envy --off <ns>` unsets the variables only `<ns>` set. A
  variable it was winning is set again to the value from the next namespace
  that defines it (the Keychain is read again for that, as when loading); a
  variable another namespace was winning is left as it was.
- **Linked namespaces replace each other.** Namespaces in one [link
  group](namespace-files.md#linked-namespaces) define the same variables, so they are
  alternatives: `envy personal-aws` while `work-aws` is loaded swaps one for the
  other, as before. Anything not linked to an active namespace is added.
- **A name appears once.** Loading a namespace that is already active (also the
  same name from the other level, as with `--user`) replaces that entry and
  moves it to the top.
- **Status.** `envy` marks every active namespace with `*`, and when more than
  one is active adds a line giving the order, so the winner of a collision can
  be read off:

  ```console
  $ envy
  * common
  * web
  active (oldest first): common, web
  ```

**Restoring.** To give a variable the removed namespace was winning its value
back, `--off <ns>` reads the remaining namespaces again; envy never keeps secret
values in your shell's state. So a restore never prompts, and never exports from
a project file that is not trusted (changed since you confirmed it, or never
confirmed for this checkout): those variables stay unset, and envy says which on
stderr. A namespace loaded from a project folder you have since left cannot be
read again either: the variables it was winning stay unset, and the message says
to run `envy <name>` in that project to load it again (or `envy --off <name>`
there to remove it), where `<name>` is the namespace that was loaded from it.
Plain `envy --off` always unsets everything.
