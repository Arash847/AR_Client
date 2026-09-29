# ARClient

A Windows client that routes the domains and applications you choose through
**xray-core**'s `finalmask` fragmentation or through **Aether**'s tunnel, and
leaves everything else alone.

Built for networks where deep packet inspection, SNI filtering and endpoint
blocking are the norm. The immediate target is Discord, and the point of the
design is that Discord is not the hard case — it needs fragmentation and keeps
your real address. Telegram-style targets whose IP addresses are blocked
outright need the tunnel, and are a different problem with a different answer.

## The two paths, and why both exist

| | **frag** | **tunnel** |
|---|---|---|
| Engine | xray `finalmask` | Aether (MASQUE / gool / WireGuard / Psiphon) |
| Defeats | SNI and DPI inspection | full IP blocks and blackholes |
| Exit address | **yours** | the tunnel's, measured not assumed |
| Cannot reach | targets whose IP is blocked | nothing, but at the cost of your address |

This is why one engine cannot do the job. A target blocked at the IP layer is
unreachable no matter how the TLS handshake is shaped, and a target blocked only
by inspection is better served by fragmentation than by a tunnel, because
fragmentation keeps the source address that services geo-fence.

## Start here

```powershell
ARClient-selftest.exe
```

Run it before anything else. It reports:

- whether the core starts and what config it was actually given
- the exit address, country and WARP status seen **through each route**
- whether the tunnel will carry UDP at all
- whether UDP leaves the machine directly

Those are the questions that decide how the rest is configured, and they cannot
be answered from CI, which has no access to the target network. **Paste its
output into any issue** — it is written to be read.

## Building

Nothing is built on your machine.

```
push  ->  .github/workflows/ci.yml       tests, plus a selftest binary artifact
tag v* -> .github/workflows/release.yml  a Windows x64 zip
```

`./scripts/fetch-cores.ps1` stages the two supervised binaries and verifies
their checksums.

### The xray-core pin matters

The newest **tagged** xray-core release predates the fragment `lengths`/`delays`
arrays that the working FragB profile depends on. Those arrays arrived in
[PR #6334](https://github.com/XTLS/Xray-core/pull/6334) and exist only on `main`.

The core's JSON loader **drops a field it does not recognise without
complaining**, so a tagged core produces a binary that starts, accepts the
config, and fragments by a different rule than the one that works on your
network. There is no error. The symptom is a client that loads and cannot
connect.

So `go.mod` pins a commit, and `internal/engine.TestCorePreservesFragBFragmentLengths`
walks the protobuf the core actually built and asserts the fragment lengths are
still `[0, 104, 1]`. A dependency bump fails in CI instead of on a user's
machine.

## Why FragB

The two reference profiles differ in one place that decides the outcome:

```jsonc
// FragA
"lengths": ["6", "98", "1"]
// FragB
"lengths": ["0", "104", "1"]
```

FragB opens with a **zero-length** fragment, so the split lands before a usable
SNI-bearing record reaches the wire. On the network this was built for, a split
6 bytes in is detectable and a split at zero is not. FragB is therefore the only
shipped profile; FragA is kept as an editable variant for when the filtering
changes and neither works.

`104` is not a constant to tune on its own. The pairing of both layers is the
unit that is known to work.

## Configuration

`%AppData%\ARClient\config.json`, meant to be edited by hand. It holds the rules
and the fragmentation parameters, and a corrupt file is reported rather than
overwritten — those offsets cannot be regenerated.

A rule is a set of domains plus a **mode**:

```json
{ "name": "Discord", "mode": "frag", "transport": "both",
  "enabled": true, "domains": ["discord.com", "discordapp.net"] }
```

`mode` is one of:

- `frag` — direct socket, ClientHello fragmented, your address preserved
- `tunnel` — through Aether
- `auto` — direct until a probe fails, then tunnel. Used for voice, where direct
  probably works and costs nothing.
- `direct` — untouched

Unlisted traffic goes **direct**, not blocked. That is a deliberate departure
from the reference profiles, which end in a catch-all block: the requirement here
is that unselected traffic is bypassed, and a direct outbound leaves with your
real address either way.

## Domain discovery

A partial domain list does not fail loudly. It produces a client where messages
work, avatars do not, and video will not play.

The app therefore logs every routed connection with the outbound tag it matched,
and reports any destination that reached a direct outbound. That is how a
missing CDN suffix gets found by name instead of by guesswork. See
`internal/discovery`.

## TUN and selective capture

TUN mode routes **only the fake address pool** into the tunnel, where the pool
is the range the core answers from for selected domains. Two consequences worth
stating plainly:

- Unselected traffic never enters userspace, so "bypass" stays literally true.
- The core's direct outbound is not exempted by zeptun's WFP filters — it permits
  exactly one process by application id, itself, with no option to add another.
  With a blanket default route that produces a loop. Selective routing makes the
  loop impossible rather than detecting it, and a WFP permit for the core is
  still staged as a safety net.

## Status

Phase 1. The rule model, the configuration generator, the embedded core, the
Aether supervisor, the health probes and domain discovery are complete and
tested. The graphical interface is not built yet; `ARClient.exe` and
`ARClient-selftest.exe` are command-line entry points for now. TUN capture is
Phase 3.

## Credits

- [XTLS/Xray-core](https://github.com/xtls/xray-core) — the core, and the
  `finalmask` camouflage chain this is built on
- [@patterniha/Serverless-for-Iran](https://github.com/patterniha/Serverless-for-Iran)
  — the reference profiles whose tuned values are seeded here verbatim, and
  PR #6334 which made the arrays available
- [CluvexStudio/Aether](https://github.com/CluvexStudio/Aether) — the tunnel core
- [Noisemux/zeptun](https://github.com/Noisemux/zeptun) — the tunnelling engine
