# opsec-dashboard

A terminal dashboard for a Linux host's security posture. Twenty checks covering
tunnels and leaks, firewall and egress, data at rest, kernel hardening, exposed
services and auth logs — refreshed live, with trend lines, regression alerts,
confirm-then-run remediation, and a headless mode for scripts and CI.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ OPSEC Health Dashboard                    2026-07-31 00:19:14 -03:00  (0s ago)│
└──────────────────────────────────────────────────────────────────────────────┘
┌ 6 fail  4 warn  0 unknown  10 pass  1 accepted  ─────────────────────────────┐
│ FAIL  MAC randomization    exposed: enp4s0 (64:1c:67:f5:65:e5)  ▁▁▇▇▇▇▇▇▇▇▇▇ │
│ FAIL  Listening (TCP)      3 exposed: 7654, 5900, 5355          ▁▁▇▇▇▇▇▇▇▇▇▇ │
│ WARN  nftables             service inactive, ruleset needs sudo ▅▅▅▅▅▅▅▅▅▅▅▅ │
│ PASS  Disk encryption      / on LVM over dm-crypt (cryptlvm)    ▁▁▁▁▁▁▁▁▁▁▁▁ │
│ PASS  Swap encryption      swap protected: zram0                ▁▁▁▁▁▁▁▁▁▁▁▁ │
└──────────────────────────────────────────────────────────────────────────────┘
┌ Details ─────────────────────────────────────────────────────────────────────┐
│ USBGuard  FAIL                                                               │
│ service inactive                                                             │
│ → USB devices are unrestricted.                                              │
│ [x] $ sudo systemctl enable --now usbguard                                   │
└──────────────────────────────────────────────────────────────────────────────┘
 [j/k] move  [r] refresh  [a] auto 5s  [s] sort:order  [f] all  [?] help  [q] quit
```

The bars on the right are each check's recent history. Colour and height both
carry the severity, so the trend is legible without relying on colour alone.

## Usage

```sh
cargo build --release
./target/release/opsec-dashboard            # interactive dashboard
./target/release/opsec-dashboard --once     # one-shot text report
./target/release/opsec-dashboard --json     # machine-readable
./target/release/opsec-dashboard --list     # what gets checked
```

| Flag | Effect |
| --- | --- |
| `-1`, `--once` | run every check once, print a report, exit |
| `--json` | same, as JSON |
| `-i`, `--interval SECS` | auto-refresh interval (1–300, default 5) |
| `-o`, `--only SELECTOR` | restrict to check ids or categories, comma-separated |
| `--no-sudo` | never attempt `sudo -n` for privileged checks |
| `-c`, `--config PATH` | config file (default `$XDG_CONFIG_HOME/opsec-dashboard/config.toml`) |
| `-p`, `--profile NAME` | apply a `[profiles.NAME]` block |
| `--write-config` | print a commented starter config |
| `-l`, `--list` | list available checks |

### Keys

`j`/`k` move · `g`/`G` first/last · `r` refresh · `a` toggle auto-refresh ·
`+`/`-` interval · `s` sort by order or severity · `f` all/problems only ·
`x` run the selected check's fix · `?` help · `q` or `Ctrl-C` quit.

### Exit codes

Headless mode exits `0` when everything passes, `1` on warnings or undetermined
checks, `2` on failures — so `opsec-dashboard --once || notify-send 'opsec'`
does something useful.

## Reading the results

| Status | Meaning |
| --- | --- |
| `PASS` | verified good |
| `WARN` | degraded, or verified only partially |
| `FAIL` | verified bad |
| `????` | **could not be determined** — absence of evidence, not evidence of safety |

`????` is deliberately not folded into `PASS`, and it is not a clean exit code.
A check that cannot see the system journal, or whose helper binary is missing,
says so instead of guessing.

A check listed under `[exceptions]` keeps its real status on screen — the
finding is never hidden — but stops counting towards the exit code, the header
colour and alerts, and its reason is shown alongside it. Accepting a risk is
recorded, not erased.

Two checks need root to be conclusive: `nftables` (reading the ruleset) and
`usbguard` (the device list). Both try `sudo -n`, which never prompts, and
degrade to a warning rather than a false verdict when it is unavailable. Pass
`--no-sudo` to skip the attempt entirely.

## Configuration

`opsec-dashboard --write-config > ~/.config/opsec-dashboard/config.toml` writes
a commented starter file. Everything is optional.

```toml
[general]
interval = 10

[checks]
disabled = ["updates"]        # or: enabled = [...] as an allowlist

[thresholds]
failed_logins_fail_above = 10 # more than ten failed logins is a FAIL

[exceptions]
listening-tcp = "5900 is VNC on the LAN, accepted"

[alerts]
enabled = true
command = "notify-send 'OPSEC: {label}' '{status} — {message}'"
on      = "regression"        # or "any-problem"

[profiles.travel]             # opsec-dashboard --profile travel
interval = 3
[profiles.travel.thresholds]
failed_logins_fail_above = 0
```

A profile layers over the base settings; keys it does not mention are inherited.

**Alerts** fire on a *regression* by default — a check that was fine and now is
not. Alerting on every non-passing result would mean a notification storm on
every refresh for a machine with a known gap, and an alert channel that is
always shouting is one nobody reads. Placeholder values are shell-quoted, since
a check message contains whatever the system printed.

**History** is appended to `$XDG_STATE_HOME/opsec-dashboard/history`, one line
per refresh, capped at `history.retain`:

```
1785007719 vpn=pass mac=fail nftables=warn
```

Plain text on purpose — it is `grep`- and `awk`-able, and it avoids carrying a
parser for a format only this program writes.

## Fixing things from the dashboard

Checks that can state their remediation exactly carry a command. Pressing `x`
on such a row shows it in full and waits:

```
┌ Run fix? ────────────────────────────────────────────┐
│ USBGuard                                             │
│                                                      │
│ $ sudo systemctl enable --now usbguard               │
│                                                      │
│ [y] run   [d] dry run   [n] cancel                   │
└──────────────────────────────────────────────────────┘
```

Nothing runs without that keystroke, the command is never hidden, `d` shows
what would happen without doing it, and a successful run triggers an immediate
recheck so the board cannot keep showing a pre-fix verdict. Passing checks are
never given a fix — there is nothing to repair.

## Design

```
exec      subprocess execution with timeouts — the only module that shells out
checks    the catalogue: one orchestrator + one pure interpreter per check
config    the config file and its own small TOML-subset parser
history   per-check trend storage      ·  alerts   regression notifications
app       dashboard state, the async refresh engine, the action flow
ui        rendering  ·  report  headless rendering  ·  cli  argument parsing
```

Two properties are worth knowing about:

**Checks never block the UI.** Each one runs on its own worker thread and
reports back over a channel; the previous value stays on screen, dimmed, until
the new one lands. A 24-hour journal scan does not freeze the dashboard.

**Every check is split in two.** An orchestrator gathers raw material from the
system, and a pure interpreter turns that material into a result. The
interpreters take plain `&str` and `Outcome` values and never touch the host,
which is what makes the security-relevant logic testable — including the failure
paths, where the dangerous bugs live.

## Adding a check

One function and one registry entry:

```rust
// src/checks/system.rs
pub fn my_check() -> CheckResult {
    parse_my_check(exec::read_trimmed("/proc/sys/...").as_deref())
}

pub fn parse_my_check(value: Option<&str>) -> CheckResult {
    match value {
        Some("1") => CheckResult::pass("my-check", "My check", "enabled"),
        _ => CheckResult::fail("my-check", "My check", "disabled")
            .with_hint("How to turn it on."),
    }
}
```

```rust
// src/checks/mod.rs — REGISTRY
Check {
    id: "my-check",
    label: "My check",
    category: Category::System,
    about: "What this inspects.",
    run: my_check,
},
```

The id then works with `--only`, appears in `--json`, and the check gets its own
row, worker thread and detail pane for free.

## Tests

```sh
cargo test
```

Around 260 tests, mostly against the pure interpreters using real captured
output from `ip`, `ss`, `nft`, `lsblk`, `timedatectl` and `journalctl`.
Regressions carry a comment explaining what the old behaviour got wrong.

Two are worth knowing about because they assert on behaviour rather than
strings: the alert-placeholder test builds a command from a hostile check
message, runs it, and verifies the payload stayed inert data; the dry-run test
verifies that a fix whose command would create a file leaves no file behind.
