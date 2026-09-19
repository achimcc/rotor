# rotor

Who reads a secret on a NixOS host — and does a rotation reach them?

A rotated secret is only rotated where it arrives. On a host with a hundred
sops-nix secrets, a dozen containers and services that copy values into their
own databases, nobody knows every reader, and the dangerous ones look harmless:
a service that takes an admin password on first start and never reads it
again, or a setup unit that writes a password only "if it is not there yet".
The deploy is green, the service answers, and the old value lives on.

`rotor` reads a **built** NixOS system (and every container in it) and names,
for every secret, each unit that reads it and how a new value gets there:

| class | recognised by | does a rotation arrive? |
|---|---|---|
| `neustart` | the secret's or template's `restartUnits` names this unit, or its container | yes, with the deploy |
| `uebergabe` | a [converge](https://github.com/achimcc/converge) spec hands the credential over, and a timer runs it | yes, at the next run (the schedule is shown) |
| `einmalig` | **declared**: the service takes the value once | no — the declaration names the manual step |
| `gegenstelle` | **declared**: the value's other half lives elsewhere | only together with the other side |
| `ungedeckt` | found, and none of the above | **no — a finding** |

Whether a service reads a value only on first start is a property of the
service, not of its unit. rotor cannot see it; it can insist that every reader
it finds is either covered or declared.

## It never opens a secret

rotor reads the sops-nix manifest (names, paths, `restartUnits`, template
contents with placeholders), unit files, the store files they run and converge
specs. It never opens anything under `/run/secrets`, `/run/credentials` or
`/run/host`, and no output contains a line of a file or a template's content —
only names and paths. A test puts a bait value into a script and a template and
checks that no output of `check` or `show`, text or JSON, contains it.

## Usage

```
rotor check [--declarations FILE] [--json] LABEL=TOPLEVEL...
rotor show SECRET [--declarations FILE] [--json] LABEL=TOPLEVEL...
```

```
server=$(nix build --no-link --print-out-paths .#nixosConfigurations.server.config.system.build.toplevel)
rotor check --declarations decl.json "server=$server"
rotor show grafana-admin-password --declarations decl.json "server=$server"
```

`check` lists every `ungedeckt` reader and every declaration that matches no
reader. `show` lists all readers of one secret with what to do after rotating
it. Every run prints how many secrets, templates, units, containers and files
it saw.

| exit | meaning |
|---|---|
| 0 | every reader is covered |
| 1 | an `ungedeckt` reader, or a declaration without a reader |
| 2 | a measurement error: unreadable file, missing manifest, broken JSON — or **no reader at all although there are secrets** (a scan that sees nothing is broken, not clean) |

## Declarations

A JSON list; each entry names one secret and one reader:

```json
[
  { "secret": "grafana-admin-password", "leser": "obs-01:grafana.service",
    "klasse": "einmalig", "grund": "Grafana applies it only when it creates its database",
    "handgriff": "grafana cli admin reset-admin-password" },
  { "secret": "ntfy-token-alarme", "leser": "obs-01:alertmanager-ntfy.service",
    "klasse": "gegenstelle", "grund": "token and hash belong together",
    "gegenseite": "ntfy-alarm-hash" }
]
```

`leser` is `<machine>:<unit>`, the machine being a host label or a container
name. `grund` is required; `einmalig` requires `handgriff`, `gegenstelle`
requires `gegenseite`. A declaration beats a recognised class. One that matches
no reader fails the run, so the list cannot go stale silently.

## How readers are found

- **On the host:** a unit whose settings, or a store file it runs, mention the
  secret's path or a template's path.
- **Into a container:** `--load-credential=<id>:<path>` in
  `etc/nixos-containers/<name>.conf`.
- **In the container:** `LoadCredential=<id>`, `LoadCredential=<local>:<id>`,
  or a mention of `/run/host/credentials/<id>`. A guest unit gets its
  container's class: a restarted container restarts everything in it.
- **converge:** a unit whose `Exec*` names a `…-converge-*.json` spec that
  lists the credential under `secret_fields` or `secrets` is a hand-over if a
  timer starts it.

Limits, on purpose: store files are read line by line, text only, to depth 3
(the unit's own settings are depth 0). Binaries are skipped and counted; a
service that reads a credential in its own code is found through its
`LoadCredential=`.

## License

AGPL-3.0-only.
