# nchecknet Architecture

## Purpose

nchecknet is a network security auditing tool that cross-references four data sources on a monitored Linux server — nftables firewall rules, active listeners (`netstat -tulpn`), routing table (`netstat -rn`), and network interfaces (`ifconfig`) — against external nmap scans performed from vantage points in front of each interface. The goal is to surface discrepancies: ports open in the firewall with no listener, listeners with no firewall rule, and ports visible externally that should not be.

---

## High-Level Architecture

```
  Monitored servers (cron daily)
  ┌─────────────────────────────┐
  │  collector-script (Python)  │   POST /api_server
  │  ifconfig, netstat, nft     ├──────────────────────┐
  └─────────────────────────────┘                       │
                                                        ▼
  External vantage points (cron daily)         ┌───────────────┐
  ┌─────────────────────────────┐               │   collector   │
  │  nmap-script (Python)       │   POST /api_nmap  (port 8087) │
  │  nmap -Pn <server IPs>      ├──────────────►│               │
  └─────────────────────────────┘               └──────┬────────┘
                                                       │ InsertServerData / InsertNmapData
                                                       ▼
                                               ┌───────────────┐
                                               │   MongoDB     │
                                               │  nchecknet DB │
                                               └──────┬────────┘
                                                      │
                                               ┌──────▼────────┐
  Browser ◄────── WebSocket (JWT) ─────────── │   webserver   │
  (main.html + nchecknet.js)                  │  (port 8086)  │
  Bootstrap + Mermaid.js                       └───────────────┘

  Admin/Ops
  ┌─────────────────────────────┐
  │  utils (CLI)                │ ── direct MongoDB via sharedlib
  │  create users, servers,     │
  │  generate scripts, baseline │
  └─────────────────────────────┘
```

---

## Components

### `cmd/collector` — Data Ingestion Service

HTTP server (default port 8087) that receives raw telemetry from monitored nodes. No user authentication; security is by embedded server key in the collector scripts.

| Endpoint | Method | Handler |
|---|---|---|
| `/api_server` | POST | `jsonPostHandlerServerRawData` |
| `/api_nmap` | POST | `jsonPostHandlerNmapRawData` |

On receipt, raw JSON is parsed (`sharedlib.ProcessRawServerDataJSON` / `ProcessRawNmapDataJSON`) and stored in MongoDB. When both server data and nmap data exist for the same session, `CompareFromNMAPViewpoint` runs automatically and logs warnings.

### `cmd/webserver` — Web UI & API

HTTP server (default port 8086) serving the SPA and providing a WebSocket API.

| Route | Auth | Purpose |
|---|---|---|
| `/*` | None | Static file server (webroot) |
| `/login` | None | Issue JWT cookie |
| `/logoff` | JWT | Invalidate cookie + DB token |
| `/ws` | JWT | WebSocket API (all UI operations) |

Authentication uses JWT in an `HttpOnly; Secure; SameSite=Strict` cookie (24h expiry). The token is also stored in the user's MongoDB document, enabling server-side invalidation on logoff.

All WebSocket messages follow a function-dispatch pattern: the client sends `{Function, Hostname, SessionID, ...}` and receives `{Function, ArrData, ...}`.

WebSocket message functions:

| Client → Server | Server → Client | Description |
|---|---|---|
| `GetServers` | `FillServers` | List servers visible to the user |
| `GetSessionIDs` | `FillSessionIDs` | List available session dates |
| `GetData` | `FillData` | Raw JSON dump of collected data |
| `GetFwListenChart` | `FillChartReport` | Mermaid chart (fw/listen or nmap) |
| `GetNmapSuggestion` | `FillNmapSuggestion` | Interface diagram with nmap entry points |
| `GetNmapCollector` | `FillNmapCollector` | Generated nmap-script for an interface |
| `HideFwrule` | `FillChartReport` | Suppress a fw rule (requires `w` or `a`) |
| `HideListener` | `FillChartReport` | Suppress a listener (requires `w` or `a`) |
| `ChangeFwComment` | _(none)_ | Annotate a fw rule |
| `ChangeLisComment` | _(none)_ | Annotate a listener |
| `SetBaselineServer` | _(none)_ | Mark current session as baseline |

### `cmd/utils` — CLI Admin Tool

Directly connects to MongoDB (via sharedlib). Used for bootstrapping and script generation.

| Flag | Purpose |
|---|---|
| `-nu <user>` | Create user (`-P`, `-O`, `-R` required) |
| `-ns <fqdn>` | Register a new server (`-O` required) |
| `-cs <fqdn>` | Print the collector Python script for stdout |
| `-nm` | Print the nmap Python script (`-i`, `-if`, `-s` required) |
| `-sb <host>` | Set baseline session (`-i sessionid` required) |
| `-r` | Print a JSON report for a host/session |
| `-i2 <sid>` | Compare two session IDs (`-i sid1 -s host`) |
| `-pp <Struct:HN:SID>` | Pretty-print stored server data |

### `pkg/sharedlib` — Shared Library

All business logic lives here; the three binaries are thin wrappers.

| File | Responsibility |
|---|---|
| `database.go` | MongoDB CRUD, script generation, access control |
| `parse.go` | Parse raw CLI output into structured types |
| `report.go` | Baseline comparison, Mermaid diagram generation, reports |
| `yaml.go` | YAML config loading |

---

## Data Model

**Database**: `nchecknet` (MongoDB)

### Collections

#### `servers`
```
hostname      string   (FQDN, unique)
key           string   (SHA-256 of fqdn+epoch, used as auth token in scripts)
owner         string
active        bool
dateinserted  string
```

#### `serverdata`
```
sessionid     string   (YYYYMMDD — one doc per server per day)
key           string   (references servers.key)
sdata:
  hostname    string
  date        string
  key         string
  listeners   []Listener
  fwrules     []Fwrule
  interfaces  []Interface
  routes      []RouteEntry
```

#### `nmapdata`
```
sessionid     string
key           string
ndata:
  date        string
  key         string
  nmaphosts   []NmapHost   (one per vantage point / interface)
```

#### `users`
```
name          string
passhash      string   (bcrypt)
accessright   string   ("a" | "w" | "r")
owner         string
active        bool
token         string   (current JWT, cleared on logoff)
dateinserted  string
```

#### `baseline`
```
hostname      string
sessionid     string
```

### Core Domain Types (`parse.go`)

```go
type Listener struct {
    IPversion, Proto, IP, Port string
    Bound2interface, Command   string
    Comment string; Supressed bool
}

type Fwrule struct {
    IPversion, Port, Proto string
    Intfaces   []string; AllIntfaces bool
    IP_to, IP_from, Ruletype, Chain string
    Comment string; Supressed bool
}

type Interface struct {
    Name string
    V4addresses, V6addresses []string
    Supressed bool
}

type RouteEntry struct {
    Dest, Gateway, Interface string
    Supressed bool
}

type NmapLine  struct { Proto, Port, Status string; Supressed bool }
type NmapHost  struct { IPversion, IPScanned, Interfacename, FromHostname, ScannedHostname string; NmapLines []NmapLine }
```

---

## Data Flow

### Collection (runs daily via cron)

1. **Collector script** (Python, runs as root on monitored server):
   - Runs `ifconfig`, `netstat -tulpn`, `netstat -rn`, `nft list ruleset`
   - Packages output as `RawDataServer` JSON with embedded server key
   - POSTs to `collector/api_server`

2. **Nmap script** (Python, runs as root from an external host):
   - Scans the server's IPs visible from that network (`nmap -Pn`)
   - Packages as `RawDataNmap` JSON with embedded server key
   - POSTs to `collector/api_nmap`

### Processing (on each POST to collector)

`InsertServerData`:
1. Verify server key is registered
2. Derive `sessionid` = `YYYYMMDD` from the data timestamp
3. Delete any existing document for same (key, sessionid) — idempotent daily runs
4. Parse raw text into structured types
5. Copy `Comment` and `Supressed` flags from the previous session's matching rules (matched by SHA-256 checksum of static fields), so annotations survive daily re-ingestion
6. Trigger `CompareBaseline` — log appeared/disappeared items vs baseline session
7. If nmap data also exists for this session, trigger `CompareFromNMAPViewpoint`

`InsertNmapData`:
1. Verify server key
2. Upsert: if session doc exists, replace the NmapHost entry matching same `FromHostname + IPversion + ScannedHostname`; otherwise insert new doc or append new NmapHost
3. If server data also exists, trigger `CompareFromNMAPViewpoint`

### Viewing (on demand via WebSocket)

Charts are generated server-side as Mermaid flowchart syntax and rendered in the browser by Mermaid.js.

**FwAllow chart** (`CompareFromFWViewpoint`): Groups fw rules and listeners by port, renders them as two subgraphs connected by arrows where a fw rule port matches a listener port. Interactive buttons per node allow hide/suppress and inline comment editing.

**Nmap chart** (`CompareFromNMAPViewpoint`): Shows each nmap vantage point's findings linked to the interface they scanned through. Highlights ports found open externally but without a matching firewall rule (red label).

**Systems tab** (`GenPic`): Mermaid diagram of the server's interfaces with clickable buttons to generate the nmap script for each interface.

---

## Access Control

| Right | Scope |
|---|---|
| `a` (admin) | See all servers across all owners; full write access |
| `w` (write) | See own owner's servers; can suppress rules and edit comments |
| `r` (read) | See own owner's servers; read-only |

`NoAccess2DB()` enforces owner-scoped access on every WebSocket request.

---

## Script Generation

Scripts are generated from templates in `database.go` with string substitution:
- **Collector script**: fills in `server.key` and `collectorurl`
- **Nmap script**: fills in `server.key`, `collectorurl`, interface name, and list of IP addresses to scan (taken from the selected interface's current session data)

Scripts write a temp JSON file to `/var/tmp/`, POST it via curl, then delete it.

---

## Configuration (`etc/nchecknet.yml` or `/usr/local/etc/nchecknet.yml`)

```yaml
webserver:
  jwtsecret: "long random secret"
  port: "8086"
  mongodburl: "mongodb://..."
  maxsessionidselect: 3   # how many recent sessions the UI shows
  webroot: "/path/to/webroot"

collector:
  collectorurl: "https://your-collector-fqdn"
  port: "8087"
```

---

## Frontend

Single-page app (`webroot/main.html` + `webroot/js/nchecknet.js`).

- **Bootstrap 5** for layout and tabs
- **jQuery** for DOM manipulation and event handling
- **Mermaid.js** (bundled local copy) for diagram rendering
- Connects to `/ws` over WebSocket (WSS in production, WS for localhost)
- Three tabs: **Systems** (server/session selectors, nmap script generator), **Charts** (fw/listener or nmap diagrams), **Data** (raw JSON dump)

Chart nodes rendered by Mermaid contain embedded HTML (`<input>`, `<button>`) wired up via `setTimeout` after Mermaid renders, using CSS class selectors (`hidefwrule`, `hidelistener`, `Fwcomment`, `Liscomment`).

---

## Build

```
cd v2
go mod tidy
make          # builds bin/webserver bin/collector bin/utils bin/testers
```

Key dependencies: `go.mongodb.org/mongo-driver`, `github.com/golang-jwt/jwt/v5`, `github.com/gorilla/websocket`, `gopkg.in/yaml.v2`, `golang.org/x/crypto` (bcrypt).

---

## Known Gaps / Todo

- Baseline comparison currently only logs to stderr (no UI display)
- `RunReport` has a bug: `ok=false` is forced, so every nmap port is always flagged as unmanaged
- Nmap script IPv6 scanning is stubbed out (returns early on `:` in IP)
- No session pruning (old sessions accumulate indefinitely)
- `maxsessionidselect` governs UI display only, not DB retention
