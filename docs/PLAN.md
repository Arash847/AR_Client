# ARClient — plan

Windows app combining **xray-core** (`finalmask` fragmentation) and **Aether**
(Cloudflare WARP/MASQUE/gool/WireGuard/Psiphon) so that user-chosen domains and apps
are routed through one of them, and **everything else is left untouched**.

Target network: Iran. Primary target: Discord, working completely — text, media,
and voice.

> Authored in Plan mode, so it lives outside the repo. Move to `docs/PLAN.md` as the
> first commit of implementation.

---

## 1. Headline decision — build order is inverted on purpose

Four decisions are **empirically gated** and cannot be resolved without hardware on
the target network:

| # | Open question | Blocks | Status |
|---|---|---|---|
| **G1** | Does Aether's SOCKS5 support UDP ASSOCIATE? | voice over tunnel | open — needs a tunnel rule configured |
| **G2** | Are Discord's voice server IPs reachable directly? | whether voice needs TUN at all | **answered: yes, UDP egress works (745 ms round trip). Voice very likely needs nothing.** |
| **G3** | What exit IP does Aether present? | routing defaults, real-IP badge | **partly answered: the frag path presents the local address, as designed. Aether untested.** |
| **G4** | What is the complete set of domains Discord contacts? | rule completeness | open — needs a live Discord session with access logging on |

```
Phase 1  engine + selftest CLI          (no UI)   -> answers G1..G4 on real hardware
Phase 2  Wails UI over the proven engine
Phase 3  TUN selective capture + WFP safety net
Phase 4  CI release + installer
```

A CI-built `ARClient-selftest.exe` is the instrument. The user runs it, it prints
answers, and Phase 2 onward is built on facts. **Do not build the UI before Phase 1
produces output.**

### 1a. What building Phase 1 already settled

Three findings changed the design, and none were visible from reading the source
configs. All three are now asserted in tests.

1. **The newest *tagged* xray-core cannot run these configs.** `v1.260327.0`'s
   fragment settings carry a single `length_min`/`length_max` pair. The
   `lengths`/`delays` **arrays** FragB depends on arrived in PR #6334 and exist
   only on `main`, untagged. The core's JSON loader drops an unrecognised field
   silently, so a tagged core starts, accepts the config, and fragments by a
   different rule — with no error. `go.mod` therefore pins commit `e5e85ca`, and
   `TestCorePreservesFragBFragmentLengths` walks the built protobuf to prove the
   lengths are still `[0, 104, 1]`.

2. **fakedns must contain `full:challenges.cloudflare.com`.** The resolver is DoH
   to `cloudflare-dns.com`, fronted onto `challenges.cloudflare.com`; resolving
   the fronting target needs a resolver, which is the DoH client, which needs to
   resolve `cloudflare-dns.com`. Only a fake answer for the fronting target
   breaks the loop. Without it, *selected* domains still work (answered locally
   from the fake pool) while every unselected destination hangs — a partial
   outage that is really a dead resolver. Found by running the generated config
   and verbatim FragB side by side: FragB answered for unlisted names, the
   generator did not.

3. **The catch-all routing rule must be unconditioned.** A proxy client hands the
   core a hostname, and with `domainStrategy: AsIs` the core does not resolve
   it, so `ip: ["0.0.0.0/0"]` on the final rule matches nothing. Traffic then
   fell through to the first outbound, which is `block` — "everything else is
   blocked", the exact inverse of the requirement, and silent because the listed
   rules kept working.

Also worth recording: the generator's routing ladder is now

```
dns-out (53)
domestic-dns  -> direct        (tcp, udp)
no-filter-dns -> frag-tls      (the fronted DoH request is itself inspected)
tunnel (tcp, udp)              (resolved from the effective mode)
block udp quic  + block udp 443, scoped to frag domains
frag (udp, then tcp)
direct ip private[/geoip:ir]
direct                          (no condition: the bypass default)
```

---

## 2. Decisions taken

| Decision | Choice | Rationale |
|---|---|---|
| Build order | Engine + selftest CLI before UI | §1 — four gates are empirical |
| Frag profile | **FragB only**; FragA demoted to an Advanced variant | FragB is the only one that works on this network (§3) |
| Voice mode | **`auto`** — probe direct, escalate to tunnel only on failure | G2: UDP is throttled, not blocked; voice uses high ports, not 443 |
| Capture | TUN with **selective include** as the target; PAC / WinINET / off also available | TUN is required for voice; selective include keeps "bypass" literally true |
| Aether in TUN | **Not a TUN front end.** Aether is a SOCKS5 server; it runs *behind* a TUN | Its own docs give `--mark 0xff` for tun front ends |
| Per-app | Launch wrapper, no WFP callout driver | Reliable for Discord, no driver, no signing |
| UI | Wails v2, vanilla HTML/CSS/JS | WebView2 ships with Win10/11; no Node in CI |
| Builds | **GitHub Actions only** | Explicit requirement; user installs nothing |
| xray-core | Embedded Go library (`core.New`) | No subprocess |
| Aether | Child process, `AETHER_*` env | Fully non-interactive; avoids Rust/CMake/quiche |
| zeptun | Child process, generated TOML | `include`/`exclude` are CLI/TOML-only, absent from the C struct |
| Unlisted traffic | **`direct`, never `block`** | Requirement is bypass, not deny. Deviates deliberately from fragA/fragB |

---

## 3. Why FragB, and what must be preserved

```jsonc
// FragA  —  outbounds[tcp-fragment-tls].finalmask.tcp[0]
{ "packets": "tlshello", "lengths": ["6", "98", "1"], "delays": ["0"], "maxSplit": "0" }

// FragB  —  outbounds[tcp-fragment-tls].finalmask.tcp[0]
{ "packets": "tlshello", "lengths": ["0", "104", "1"], "delays": ["0"], "maxSplit": "0" }
```

FragB opens with a **zero-length** fragment, so the split lands before a usable
SNI-bearing record reaches the wire. On this network the 6-byte offset is detectable
and the 0-byte offset is not.

- `tcp-fragment-tls` is seeded with FragB's arrays **verbatim**.
- FragA is retained only as a preset inside Advanced, never as a peer profile.
- Arrays stay **user-editable** and visible — the working offset is network-specific
  and will drift as the filter changes.
- Do not treat `104` as a magic constant. The pairing is what is known to work.

Also carried over, and **load-bearing**:

| Setting | Why it matters |
|---|---|
| inbound `tcpKeepAliveInterval: 1`, `tcpKeepAliveIdle: 11` | Discord's gateway is a **persistent** WebSocket. Iran's NAT drops idle TCP. Strip these and Discord connects, then randomly reports "Disconnected" minutes later — a bug that gets blamed on the app. **Asserted in generator tests.** |
| `happyEyeballs { prioritizeIPv6: false, interleave: 4, maxConcurrentTry: 20 }` | Broken half-IPv6 makes Chromium stall ~30s before fallback. Reads as "Discord is slow". |
| `policy.levels` `connIdle: 12` | Long-lived gateway connections. |

`finalmask` is **upstream xray-core** — `transport/internet/finalmask/` with
`fragment` (TCP) and `noise` (UDP). The `lengths`/`delays` arrays the configs need
came from XTLS/Xray-core PR #6334, authored by @patterniha.
**Pin `github.com/xtls/xray-core` at >= v26.6.27.**

---

## 4. Core model

One ordered rule list. Each entry has a target and a **mode**.

| Mode | Engine | Defeats | Exit IP | Default for |
|---|---|---|---|---|
| `frag` | xray `finalmask` | SNI / DPI inspection | **yours (IR)** | Discord UI, CDN, most web |
| `tunnel` | Aether | full IP blocks, blackholes | measured — see G3 | Telegram, IP-level blocks |
| `auto` | probe, then pick | — | varies | **voice** |
| `direct` | plain outbound | nothing — untouched | yours | everything unlisted |

`frag` keeps the real source IP but only beats *inspection*. `tunnel` reaches
destinations whose IPs are blocked outright, but the exit is not Iranian. That split
is the entire reason one engine cannot do this job.

Per rule, an explicit and **measured** property:

```
rule.preserve_real_ip  bool   // true for frag by construction; measured for tunnel
```

surfaced as a UI badge. Any rule whose measured exit is not IR is bad for payments,
banks and Iran-sanctioned services — the badge is how the user finds out.

**Capture, routing and transport are separate layers.** Only capture changes with TUN:

| Layer | Decides | Changes with TUN? |
|---|---|---|
| Capture | how packets reach us | **yes** |
| Routing | `frag` / `tunnel` / `auto` / `direct` | no |
| Transport | fragmented direct socket vs. Aether MASQUE | no |

---

## 5. Architecture

```
                    ┌───────────────────────────────────────────┐
                    │            ARClient  (Go + Wails)         │
   WebView2 UI  <-->│  rules · generator · supervisor · health   │
                    └───────────────┬───────────────────────────┘
                                    │
        ┌───────────────────────────┼────────────────────────────┐
        │                           │                            │
  xray-core                  aether.exe                   zeptun.exe
  embedded, core.New()       child process                 child process
        │                    SOCKS5 127.0.0.1:<rand>        Wintun, selective include
        │ routing                   │                            │
        ├── frag   ──> direct + finalmask.fragment               │
        ├── auto   ──> probe: direct, else tunnel                │
        ├── tunnel ──> socks5 ──────────────────────────>  :rand │
        └── all    ──> direct (untouched)                        │
                                                                     │
  ┌──────────────────────────────────────────────────────────────────┘
  │ capture:  off  |  PAC  |  WinINET  |  TUN(selective include)
  └──────────────────────────────────────────────────────────────────
```

Ordering is deliberate: **xray stays in front of Aether.** xray's `mixed` inbound
sniffs SNI / fakedns from a connection that may carry only an IP, so domain rules
still match. Reversing the chain loses that.

---

## 6. TUN capture — the part that needs care

### 6.1 The anti-loop problem

`zeptun/src/route/wfp.zig` installs exactly four strict-route filters:

| Weight | Condition | Action |
|---|---|---|
| 13 | `app_id` = **zeptun's own exe** | permit |
| 12 | *(if no v6)* all v6 | block |
| 11 | `local_interface_index` = the TUN | permit |
| 10 | `remote_port` = 53 | block |

`app_id` comes from `GetModuleFileNameW(nullptr, …)` — its own binary. **There is no
option to exempt a third-party core.** With a blanket default route, xray's `direct`
sockets are not exempted, the default route points at the TUN, and you get
xray → TUN → zeptun → xray.

Mitigations, all three implemented:

1. **Selective include routes** (primary) — the loop cannot form; see §6.2.
2. **`sockopt.interface`** on xray's direct outbounds, pinned to the physical NIC.
   Cheap, but breaks on WiFi → Ethernet transitions.
3. **Our own WFP filter** permitting `xray.exe` by `app_id`, lower weight than
   zeptun's. ~200 lines of Go on `golang.org/x/sys/windows`. The safety net.

### 6.2 The fakedns range is the include list

This is the key idea, and it is why selective capture is robust:

```
Windows DNS -> xray :53
    selected domain   -> fake IP from pool 198.18.0.0/15
    unselected domain -> real IP
zeptun include = ["198.18.0.0/15"]
    -> only selected domains enter the TUN
```

No DNS resolution on our side, no CDN IP churn, no refresh timer. Unlisted traffic
never enters userspace, so "bypass" remains literally true. It also dissolves the
loop problem, because xray's direct traffic to a non-included destination leaves via
the NIC.

> **Single source of truth.** The fakedns pool and the zeptun include list must be
> generated from one value in the model. If they desync, selected traffic silently
> bypasses the tunnel. This is the most likely source of a day lost — make it one
> field, `FakednsPool`, written by both generators, and assert it in a test.

Caveat: apps with their own DoH (Chrome "Use secure DNS" — FragB's README says turn
it off) bypass the system resolver and get real IPs. Keep a resolved-IP supplement
refreshed on a timer as a fallback for the include list.

---

## 7. Generated xray config

```jsonc
"dns": {
  "hosts": { "cloudflare-dns.com": "challenges.cloudflare.com" },   // domain fronting
  "servers": [
    { "address": "fakedns", "ipPool": "<FakednsPool>",
      "domains": [ <FRAG ∪ TUNNEL ∪ AUTO-UDP> ] },
    { "tag": "no-filter-dns", "address": "https://cloudflare-dns.com/dns-query",
      "timeoutMs": 12000, "finalQuery": true },
    { "tag": "domestic-dns", "address": "localhost",
      "domains": [ ...same... ], "timeoutMs": 12000, "finalQuery": true }
  ],
  "queryStrategy": "UseSystem", "useSystemHosts": true, "serveStale": true
}

"routing": { "domainStrategy": "AsIs", "rules": [
  { "outboundTag": "block",  "domain": ["geosite:category-ads-all"] },        // optional
  { "outboundTag": "dns-out", "port": 53 },

  { "outboundTag": "tunnel", "network": "tcp", "domain": [ <TUNNEL> ] },
  { "outboundTag": "tunnel", "network": "udp", "domain": [ <AUTO-UDP> ] },

  // CRITICAL: kill QUIC for frag domains so the app falls back to TCP,
  // which is the only place ClientHello fragmentation applies.
  { "outboundTag": "block",  "network": "udp", "protocol": ["quic"] },
  { "outboundTag": "block",  "network": "udp", "port": 443 },
  { "outboundTag": "frag",   "network": "udp", "domain": [ <FRAG> ] },
  { "outboundTag": "frag",   "network": "tcp", "domain": [ <FRAG> ] },

  { "outboundTag": "direct", "ip": ["geoip:private", "geoip:ir"] },
  { "outboundTag": "direct", "network": "tcp,udp", "ip": ["0.0.0.0/0", "::/0"] }
]}
```

Three details carried over from FragB that are easy to lose:

1. **fakedns covers only the selected lists.** Everything else resolves normally, so
   the `direct` default keeps working. Widening fakedns breaks the bypass path.
2. **UDP/443 and QUIC are blocked for `frag` domains.** Without this, Discord
   negotiates QUIC and the fragmentation never engages — there is no TLS ClientHello
   on a QUIC connection. Note Chromium disables QUIC through a proxy anyway, so this
   is belt-and-braces in proxy mode and genuinely load-bearing in TUN mode.
3. **The keepalive sockopt on the inbound** (§3) must survive generation.

`domainStrategy: AsIs`, not FragB's `IPOnDemand` — every rule is already
domain-matched, so the extra resolution is pure added latency.

---

## 8. Domain discovery — the highest-value feature

A partial Discord list fails *quietly*: messages work, avatars don't, video won't
play, uploads hang. Worse than a block, because it looks flaky.

So the app **discovers** rather than trusting any hardcoded list — including mine:

1. Enable xray access logging, capturing **all** routed connections.
2. Launch Discord, exercise everything: login, images, video, a file upload,
   **join a voice call**.
3. Diff actual against configured.
4. **Surface every domain that fell through to `direct`** — that is precisely how a
   forgotten domain is found, and a forgotten domain going direct is exactly how
   Discord half-works.

Seeded list, explicitly *unverified*, superseded by discovery:

```
discord.com   discordapp.com   discordapp.net   discord.gg
cdn.discordapp.com   media.discordapp.net
images-ext-1.discordapp.net   images-ext-2.discordapp.net
```

---

## 9. Phase 1 — engine + selftest CLI (no UI)

1. **Model + store** — `rule.go` (`frag|tunnel|auto|direct`, `FakednsPool`,
   `preserve_real_ip`), `profile.go`, persistence.
2. **Generator** — rules → xray JSON, seeded from FragB.
   - Golden test: generated config vs. a checked-in FragB-derived fixture.
   - Assert the QUIC / UDP-443 block exists for every `frag` domain.
   - Assert the inbound keepalive sockopt survives.
   - Assert `ipPool` and the zeptun include list are generated from one value.
3. **xray engine** — embed via `core.New` + `serial.DecodeJSONConfig`; start / stop /
   reconfigure without restart.
4. **Aether supervisor** — child process, env config, health probe, identity dir.
5. **Health / exit-IP probe** — per mode: exit IP, `warp=on|off`, latency, pass/fail,
   whether exit country is IR.
6. **`--selftest`** — prints the answer to each gate in §1 plus a human-readable
   report, designed to be pasted into an issue.

### The four gates `--selftest` must answer

| Gate | Probe | Resolves |
|---|---|---|
| **G1** | UDP ASSOCIATE against Aether's SOCKS5; a UDP datagram through it | whether voice-over-tunnel is possible at all |
| **G2** | reach Discord's voice discovery + a voice UDP endpoint **directly**, no proxy | whether voice needs any tunnel (expected: yes it does not) |
| **G3** | exit IP via `frag`, via `tunnel`, direct — three separate probes | routing defaults and the real-IP badge |
| **G4** | log every domain Discord contacts over a scripted session; flag any that reached `direct` | rule completeness |

Note for G3: the user is currently behind a US VPN, so manual checks report the US
address. The probe must distinguish "my IP" from "tunnel exit" or it will report a
false pass.

## 10. Phase 2 — Wails UI

Rule list with mode and real-IP badges · Aether settings · capture mode selector ·
**per-rule transport** (`tcp`/`udp`/`both`) · **test button** running all three
probes · domain discovery with one-click accept · finalmask array editor in Advanced
· tray icon with **kill switch**.

Per-app launcher (Phase 1 engine, UI in Phase 2): Electron/Chromium get
`--proxy-server=socks5://127.0.0.1:10808`; everything else gets
`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`.

> **Discord must be fully closed before relaunching.** Electron's single-instance
> lock means a running Discord ignores `--proxy-server` entirely — including the tray
> process. The launcher kills, waits, and relaunches. Otherwise the rules silently
> do not apply and the app looks broken.

## 11. Phase 3 — TUN

1. zeptun child process, generated TOML, `wintun.dll` in place, `include` = fakedns
   pool + resolved-IP supplement.
2. Elevated service holding the tunnel; UI stays unelevated over a named pipe.
   Wintun requires elevation.
3. WFP safety net: permit `xray.exe` by `app_id` (§6.1.3).
4. DNS: Windows → `127.0.0.1:53`; xray's fakedns scoping becomes authoritative.
5. Flow verdicts via `zeptun_set_flow_callback` where the library is linked;
   config-driven `include`/`exclude` otherwise.

Definition of done: Discord voice works, and apps that ignore proxy settings are
covered.

## 12. Phase 4 — CI release

```yaml
# .github/workflows/release.yml  —  runs-on: windows-2022
- actions/checkout@v4
- actions/setup-go@v5                      # go 1.24
- run: ./scripts/fetch-cores.ps1
- run: go build -tags selftest -o dist/ARClient-selftest.exe   # gate probe
- run: wails build -clean -platform windows/amd64
- run: ./scripts/package.ps1
- uses: softprops/action-gh-release@v2
```

`fetch-cores.ps1` pins and verifies:

| Artifact | Source | Verify |
|---|---|---|
| `aether-windows-x86_64.zip` | Aether release, pinned tag (v2.1.0) | `.sha256` sidecar |
| `zeptun` windows archive | zeptun release, pinned tag (vendors `wintun.dll`) | checksum |
| `geoip.dat`, `geosite.dat` | XTLS assets | checksum, **optional flag** |

xray-core is a `go.mod` dependency and compiles with the app. One self-contained zip;
the only runtime prerequisite is WebView2, already on Windows 10/11.

**`--with-geo` is off by default.** The app's own routing is a small user-chosen list
and needs no geo data; the only consumer is `geosite:category-ads-all`.

---

## 13. Risks

| # | Risk | Impact | Handling |
|---|---|---|---|
| 1 | **Voice reachability unknown (G2)** | High — the thing that decides if TUN is needed at all | Probed first. `auto` mode escalates only on failure. |
| 2 | **Aether UDP ASSOCIATE unverified (G1)** | High — blocks voice-over-tunnel | Gate 1. If absent, voice works direct or not at all; state that plainly rather than improvise. |
| 3 | **A forgotten domain breaks Discord partially** | High — fails quietly | §8 discovery flags every domain that reached `direct`. |
| 4 | **Keepalive stripped during config cleanup** | High — random "Disconnected" | Asserted in generator tests. |
| 5 | **TUN loop (xray → TUN → zeptun → xray)** | Critical — total outage | Selective include primary; WFP safety net. |
| 6 | **fakedns pool / include list desync** | High — selected traffic silently bypasses | One field, two generators, asserted. |
| 7 | **Discord already running ignores proxy flags** | Medium — looks like a broken app | Launcher kills the full process tree first. |
| 8 | **Half-working IPv6 stalls Chromium ~30s** | Medium — reads as "slow" | Deliberate decision, not inherited. |
| 9 | **Aether SOCKS5 is unauthenticated** | Local processes can use the tunnel | Loopback bind + randomised high port. Never a LAN bind. |
| 10 | **AV false positives** | Release friction | An app that fragments TLS and manipulates routes looks like malware statically. Expect to need signing. |
| 11 | **CI cannot test from inside Iran** | No automated validation of the goal | `--selftest` ships with the app and doubles as the issue format. |
| 12 | **Working split offset drifts** | FragB may stop working | Arrays editable and visible; FragA kept as a variant. |
| 13 | **Local law** | — | The user's responsibility. Stated once. |

---

## 14. Definition of done for "Discord works completely"

- [ ] Login, messages, threads, DMs — over `frag`, real IR IP
- [ ] Avatars, emojis, stickers, image and video playback — no domain missed (§8)
- [ ] File upload and attachment download
- [ ] Voice: join, hear, speak, disconnect cleanly, reconnect after network change
- [ ] Gateway WebSocket stays connected >30 min with no "Disconnected"
- [ ] No IPv6 stall on connect
- [ ] Unlisted traffic reaches its destination with the real IP, untouched
- [ ] Kill switch leaves no residue and no leak
- [ ] All of the above verified by `--selftest` output, not by eye
