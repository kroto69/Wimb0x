# winbox-kotlin

A clean-room, zero-dependency Kotlin library for talking to MikroTik routers
over the **WinBox native protocol** (TCP 8291) — the same binary protocol the
official WinBox client speaks. Not the 8728 API, not REST, not SSH.

Built and verified against real RouterOS hardware. Every handler below was
tested live.

> **Scope:** this is a *simple* version covering the features used most
> often. For the full power of WinBox, use the official MikroTik app.

## Features

- **Login** — EC-SRP5 (RouterOS ≥ 6.43) with automatic fallback to legacy
  MD5 challenge-response. The session mode is picked at runtime.
- **M2 codec** — byte-exact TLV encoder/decoder for the WinBox message layer.
- **CRUD, mode-aware** — `getAllRows`, `addRow`, `setRow`, `removeRow` work
  on both encrypted and legacy sessions. Row targeting uses the `0xFE0001`
  item id (targeting by name silently does nothing — a real gotcha).
- **Typed helpers** — PPP secrets/profiles/active, IP addresses, firewall,
  routes, DNS, queues, interfaces, bridge ports/VLANs, DHCP client, hotspot
  (servers, profiles, users, bindings, active), logs, IP neighbors.
- **Tools** — Ping Speed ([77]: start → poll → stop), Netwatch read,
  terminal (mepty) for arbitrary commands.
- **MNDP discovery** — find nearby MikroTik devices via UDP 5678 broadcast.
- **Zero dependencies** — pure Kotlin/JVM, only JDK stdlib.

## Quick start

```kotlin
import tik.foundation.winbox.*

fun main() {
    WinboxSession("192.168.88.1", 8291).use { s ->
        s.connect()
        s.login("admin", "password")
        println("mode: ${s.sessionMode}") // EC-SRP5/AES or legacy/MD5

        // Read PPP secrets
        val secrets = s.getAllRows(WinboxPaths.PPP_SECRET)
        println("${secrets.size} secrets")

        // Typed helpers
        val logs = s.getLogs()
        logs.take(5).forEach { println("[${it.buffer}] ${it.message}") }

        val neighbors = s.getRouterNeighbors()
        neighbors.forEach { println("${it.identity} @ ${it.ip}") }

        // Ping speed
        val sid = s.pingStart("8.8.8.8") ?: error("ping failed to start")
        repeat(5) {
            Thread.sleep(1200)
            val sample = s.pingPoll(sid)
            println("current=${sample?.currentBps} avg=${sample?.averageBps}")
        }
        s.pingStop(sid)

        // Write: add a PPP secret, then clean up
        val resp = s.addRow(WinboxPaths.PPP_SECRET, listOf(
            M2Field(m2Key(1, M2Ns.USER), M2Value.Str("test-user")),
            M2Field(m2Key(2, M2Ns.USER), M2Value.Str("s3cr3t")),
        ))
        // ... setRow / removeRow need the 0xFE0001 item id from getAllRows:
        // val id = row.itemId() ?: error("no id")
        // s.setRow(WinboxPaths.PPP_SECRET, id, listOf(...))
        // s.removeRow(WinboxPaths.PPP_SECRET, id)
    }
}
```

More examples in [`examples/`](examples/).

## Live updates via subscribe (no polling)

```kotlin
val main = WinboxSession(host, port).apply { connect(); login(user, pass) }
WinboxSubscriber(host, port).use { sub ->
    sub.connect()
    sub.login(user, pass)
    // Tabel cermin yang update sendiri tiap ada perubahan di router:
    val table = sub.liveTable(
        session = main,
        path = WinboxPaths.PPP_SECRET,
        parse = { row -> row.str(m2Key(1, M2Ns.USER)) }, // M2Message -> T
        onChange = { snap -> println("${snap.size} secrets") },
    )
    Thread.sleep(30_000)
    println("final snapshot: ${table.snapshot().size}")
}
```

How it works: `SUBSCRIBE` (`0xFE0012`) → router ACKs, then *pushes* changed
rows (`0xFE000B`, no request id) whenever data changes. Deletes arrive as
marker rows (`0xFE0013` + item id). See `docs/ARCHITECTURE.md`.

## How it works

```
TCP 8291 → handshake (EC-SRP5 or legacy MD5) → M2 TLV messages
```

1. **Handshake.** The client sends an EC-SRP5 init frame immediately. If the
   router stays silent ≥ 3 s, it is treated as legacy-only: reconnect and run
   the MD5 challenge-response flow instead.
2. **Session crypto (new path).** AES-128-CBC per frame with per-direction
   keys derived via HKDF from the SRP shared secret. See `WinboxCrypto.kt`
   and `EcSrp5.kt` (Curve25519 in Weierstrass form).
3. **M2 messages.** Binary TLV: `M2` magic + key (3 bytes LE) + typed value.
   Handler paths are `u32[]`, e.g. `[27,101]` = `/ppp secret`.
   See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the byte-level spec,
   [`docs/HANDLERS.md`](docs/HANDLERS.md) for the handler table, and
   [`docs/FIELD-MAP-2026-10-15.md`](docs/FIELD-MAP-2026-10-15.md) for live field mappings.
4. **Discovery.** MNDP = UDP broadcast to `255.255.255.255:5678`, parse the
   TLV replies. See `discovery/`.

## Building

```bash
./gradlew build        # or: kotlinc $(find src/main/kotlin -name '*.kt') -d out
./gradlew test
```

Requires JDK 17+. No external dependencies for the library itself.

## Testing

- `src/test` — offline unit tests (codec round-trips, EC-SRP5 vectors,
  MNDP parsing). Run with `./gradlew test`.
- Live tests need real hardware and are **not** in this repo; point any
  `WinboxSession` at your own router as in the quick start above.

## Project layout

```
src/main/kotlin/tik/foundation/
├── winbox/
│   ├── M2.kt            # TLV codec, keys, commands
│   ├── WinboxFrame.kt   # TCP framing (chunked)
│   ├── WinboxCrypto.kt  # AES-128-CBC, HKDF
│   ├── EcSrp5.kt        # Curve25519-Weierstrass + EC-SRP5
│   ├── WinboxSession.kt # TCP session, login, request/response, terminal
│   ├── WinboxOps.kt     # mode-aware CRUD, paths, neighbors, ping
│   └── WinboxFeatures.kt# typed: logs, hotspot active
└── discovery/
    ├── Mndp.kt          # MNDP TLV
    └── MndpDiscovery.kt # UDP broadcast discovery
docs/
├── PROTOCOL.md          # byte-level protocol spec
├── HANDLERS.md          # handler path reference
└── ARCHITECTURE.md      # design notes
ROADMAP.md               # status implementasi: mana yang sudah live, mana yang rencana
```

## Status & caveats

- Verified live against RouterOS on `RB750Gr3` (both auth generations).
- Traceroute `[26]` is mapped but its native streaming invocation is not
  fully reverse-engineered yet; use the terminal (`/tool traceroute`) as a
  fallback.
- MNDP discovery needs LAN broadcast; it cannot work through NAT/proxies.

## Disclaimer

Unofficial community project. Not affiliated with or endorsed by MikroTik.
"RouterOS", "WinBox", and "MikroTik" are trademarks of MikroTikls SIA.
Use against routers you own or are authorized to manage.

## License

MIT — see [LICENSE](LICENSE).
