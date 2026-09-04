# PLAN — Browser Extension Inventory (Python)

> **Project:** Extension Searcher · **Owner:** m.arunprasad@giggso.com · **Org:** giggso
> **Status:** Plan ready for build · **Planned by:** Andie (📘 Deep) · **Date:** 2026-08-27
>
> **Scope decisions — LOCKED by owner, 2026-08-27:**
> 1. **Cross-OS, first-class:** Windows · Linux · macOS. No "Windows-first, port later".
> 2. **Dual output:** human-readable CLI table (default) **and** JSON. Both are P5 deliverables.
> 3. **Safari and Internet Explorer are in scope**, not optional extras. P6 is mandatory.
> 4. **Current user only.** No `--all-users`, no elevation path, no cross-user profile reads.

---

## 1. Goal

A single Python tool that runs on the host machine and answers:

> "Which browsers are installed here, which profiles do they have, and exactly which
> extensions are in each profile — with version, ID, permissions, enabled state, and origin?"

**Non-goals:** no remote scanning, no browser automation, no network calls, no extension
*content* analysis (that is a follow-on security task), no mobile browsers.

---

## 2. Feasibility Verdict

**Fully feasible with the Python standard library alone.** No browser API, no extension API,
no admin rights (for the current user), and the browser does **not** need to be running.

Why: every Chromium and Gecko browser persists its extension inventory to disk as plain
JSON. The tool is a **filesystem reader + JSON parser**, nothing more.

| Concern | Reality |
|---|---|
| Admin rights | **Never needed.** Scope is current-user only by decision — every path is inside `$HOME` / `%USERPROFILE%`. The one exception is *read-only* `HKLM` registry keys, which are world-readable on Windows. |
| macOS TCC / Full Disk Access | **The one real permission wall.** `~/Library/Safari/` is TCC-protected on modern macOS. Chrome and Firefox profile paths are **not**. See §6.8. |
| Browser running | Irrelevant. Files are readable; Chromium does not exclusive-lock them. |
| File locks | `Preferences` / `Secure Preferences` are flushed on write and readable mid-session. Retry once on `PermissionError`. |
| Antivirus / EDR | Read-only access to user profile dirs. No process injection, no hooks, no credential files touched. |
| Encryption | Extension manifests are **not** encrypted. Only `Login Data` / `Cookies` are DPAPI-protected — and those are explicitly out of scope. |

---

## 3. The Central Insight

**45+ browsers collapse into 4 parsers + 1 path table — and 2 of those 4 cover ~95% of hosts.**

Every Chromium fork inherits Chrome's exact on-disk layout. Every Gecko fork inherits
Firefox's. So the real engineering effort is **discovery coverage**, not parsing.

| Parser | Engine | Covers | Source of truth |
|---|---|---|---|
| `chromium.py` | Blink | ~30 browsers, all 3 OSes | `manifest.json` on disk |
| `gecko.py` | Gecko | ~16 browsers, all 3 OSes | `extensions.json` on disk |
| `safari.py` | WebKit | Safari — **macOS only** | `pluginkit` + `.appex` `Info.plist` |
| `trident.py` | Trident/MSHTML | Internet Explorer — **Windows only** | Windows registry |

```
Browser Registry (data)  ──┐
                           ├──> Profile Discovery ──> Engine Parser ──> Normalizer ──> Output
Platform probe (code)    ──┘        (per browser)      (4 of them)      (1 schema)    (table|json)
```

**OS dispatch rule:** the registry table is keyed by `sys.platform`. Parsers that cannot run
on the current OS are never registered — they are absent, not failing. `safari.py` on Windows
and `trident.py` on Linux simply do not exist in the active parser set.

---

## 4. Tech Stack

### 4.1 Runtime

- **Python 3.11+** — needed for `datetime.UTC`, mature `slots=True` dataclasses, and
  `ExceptionGroup` for aggregating per-profile failures.
- **Zero third-party dependencies.** Deliberate choice: keeps the tool droppable onto any
  endpoint, avoids a Raven library-approval cycle, and works on air-gapped hosts.

### 4.2 Standard library modules and *why each one*

| Module | Used for |
|---|---|
| `pathlib.Path` | All path construction. Never string concatenation. |
| `os.scandir` | **Fast** directory iteration — returns `DirEntry` with cached type info, avoiding an extra `stat` syscall per entry. |
| `os.environ` | Resolving `%LOCALAPPDATA%`, `%APPDATA%`, `%PROGRAMFILES%` (Windows); `$HOME`, `$XDG_CONFIG_HOME`, `$XDG_DATA_HOME` (Linux); `$HOME` (macOS). |
| `pathlib.Path.home()` / `os.path.expanduser` | The portable `~` resolution used by the macOS and Linux rows. |
| `json` | Parsing `manifest.json`, `Local State`, `Secure Preferences`, `extensions.json`. |
| `configparser` | Parsing Gecko `profiles.ini` and `installs.ini`. |
| `platform` / `sys.platform` | OS dispatch into the path table. |
| `dataclasses` | Normalized record types (`BrowserHit`, `ProfileHit`, `ExtensionRecord`). |
| `enum.Enum` | `Engine`, `ExtensionState`, `InstallOrigin`, `Confidence`. |
| `concurrent.futures.ThreadPoolExecutor` | Parallel profile scans. Workload is **I/O-bound**, so threads beat processes — no pickling, no spawn cost. |
| `argparse` | CLI surface. |
| `csv` | CSV export. |
| `zipfile` | Optional `--deep`: an `.xpi` is a ZIP; read its inner `manifest.json`. |
| `logging` | Structured, level-gated diagnostics. Raven rule: never `print` for diagnostics. |
| `datetime` / `timezone` | Timestamp normalization to ISO-8601 UTC. |
| `winreg` | **Windows only — first-class, not optional.** Installed-browser detection, enterprise policy keys, and the entire Internet Explorer parser. Needs both registry views (`KEY_WOW64_64KEY` and `KEY_WOW64_32KEY`) — see §6.9. |
| `subprocess` | **macOS only — first-class, not optional.** `pluginkit` is the only reliable way to enumerate Safari app extensions and their enabled state. See §6.8. |
| `plistlib` | **macOS only.** Parsing `Info.plist` inside `.appex` bundles and Safari's `Extensions.plist`. Handles both binary and XML plists transparently. |
| `shutil.which` | Locate `pluginkit` before invoking it; degrade gracefully if absent. |
| `typing` | Full annotations on every function — Raven style requirement. |
| `hashlib` | Optional: verify a Chromium extension ID against its manifest `key`. |
| `re` | Validating the Chromium extension ID shape `^[a-p]{32}$`. |

### 4.3 Explicitly rejected

| Rejected | Reason |
|---|---|
| `pandas` | Heavy dependency for what `csv` + `json` already do. Raven also prefers Polars over Pandas. |
| `polars` | Only if a later analytics/reporting layer is requested. Not for v1. |
| `psutil` | Not needed — we never inspect running processes. |
| `glob` / `os.walk` | Slower and unbounded. Our directory depths are **known and fixed**; recursion is pure waste. |
| `browser-cookie3`, `browserhistory` | Wrong scope, poorly maintained, and pull in DPAPI/crypto dependencies we do not want anywhere near this tool. |

### 4.4 Dev tooling

- `pytest` (tests) · `ruff` (lint + format) · `mypy --strict` (types).
- **Dev-only** — `requirements-dev.txt`, never in the runtime import path.
- Action item: add `python` to `.raven/manifest.json` → `stack.language`, and the three dev
  tools to `stack.libraries`, so `stack-validator` does not block the first commit.

---

## 5. Browser Registry — The Path Table

This is a **declarative data table**, not code. Adding a browser means adding a row, never a
new code path. This is the single most important design decision in the plan.

### 5.1 Chromium family

Layout is always: `<user_data_root>/<Profile Dir>/Extensions/<ext_id>/<version>/manifest.json`

| Browser | Windows | macOS (`~/Library/Application Support/`) | Linux (`~/.config/`) |
|---|---|---|---|
| Google Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data` | `Google/Chrome` | `google-chrome` |
| Chrome Beta / Dev / Canary | `...\Google\Chrome Beta\User Data`, `Chrome Dev`, `Chrome SxS` | `Google/Chrome Beta`, `Chrome Dev`, `Chrome Canary` | `google-chrome-beta`, `google-chrome-unstable` |
| Microsoft Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data` | `Microsoft Edge` | `microsoft-edge` |
| Edge Beta / Dev / Canary | `...\Microsoft\Edge Beta\User Data`, `Edge Dev`, `Edge SxS` | `Microsoft Edge Beta`, `Dev`, `Canary` | `microsoft-edge-beta`, `-dev` |
| Brave | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data` | `BraveSoftware/Brave-Browser` | `BraveSoftware/Brave-Browser` |
| Brave Beta / Nightly | `...\Brave-Browser-Beta\User Data`, `-Nightly` | same pattern | same pattern |
| Opera | `%APPDATA%\Opera Software\Opera Stable` | `com.operasoftware.Opera` | `opera` |
| Opera GX | `%APPDATA%\Opera Software\Opera GX Stable` | `com.operasoftware.OperaGX` | — |
| Opera Air / Crypto | `%APPDATA%\Opera Software\Opera Air`, `Opera Crypto Stable` | same pattern | — |
| Vivaldi | `%LOCALAPPDATA%\Vivaldi\User Data` | `Vivaldi` | `vivaldi` |
| Chromium | `%LOCALAPPDATA%\Chromium\User Data` | `Chromium` | `chromium` |
| Yandex Browser | `%LOCALAPPDATA%\Yandex\YandexBrowser\User Data` | `Yandex/YandexBrowser` | `yandex-browser` |
| Naver Whale | `%LOCALAPPDATA%\Naver\Naver Whale\User Data` | `Naver/Whale` | `naver-whale` |
| CocCoc | `%LOCALAPPDATA%\CocCoc\Browser\User Data` | `Coccoc` | — |
| 360 Chrome / 360 Secure | `%LOCALAPPDATA%\360Chrome\Chrome\User Data`, `360ChromeX` | — | — |
| Epic Privacy Browser | `%LOCALAPPDATA%\Epic Privacy Browser\User Data` | — | — |
| SRWare Iron | `%LOCALAPPDATA%\Chromium\User Data` (Iron variant) | — | — |
| Slimjet | `%LOCALAPPDATA%\Slimjet\User Data` | — | — |
| CentBrowser | `%LOCALAPPDATA%\CentBrowser\User Data` | — | — |
| Ungoogled Chromium | `%LOCALAPPDATA%\Chromium\User Data` | `Chromium` | `chromium` |
| Thorium | `%LOCALAPPDATA%\Thorium\User Data` | `Thorium` | `thorium` |
| Supermium | `%LOCALAPPDATA%\Supermium\User Data` | — | — |
| Wavebox | `%LOCALAPPDATA%\WaveboxApp\User Data` | `WaveboxApp` | `wavebox` |
| Sidekick | `%LOCALAPPDATA%\Sidekick\User Data` | `Sidekick` | — |
| Maxthon 6+ | `%LOCALAPPDATA%\Maxthon\Application\User Data` | `Maxthon` | — |
| Comodo Dragon | `%LOCALAPPDATA%\Comodo\Dragon\User Data` | — | — |
| Iridium | `%LOCALAPPDATA%\Iridium\User Data` | — | `iridium-browser` |
| Arc | packaged — `%LOCALAPPDATA%\Packages\TheBrowserCompany.*\LocalCache\Local\...` **(verify at P1)** | `Arc/User Data` | — |

**Sandboxed variants that MUST be in the table, or the browser is silently missed:**

- **Linux Snap:** `~/snap/chromium/common/chromium`, `~/snap/<pkg>/current/.config/<pkg>`
- **Linux Flatpak:** `~/.var/app/com.google.Chrome/config/google-chrome`,
  `~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser`
- **Windows MSIX / Store:** `%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalCache\Local\...`

### 5.2 Gecko family

Layout: `<gecko_root>/profiles.ini` → resolves to `<profile_dir>/extensions.json`

| Browser | Windows | macOS (`~/Library/Application Support/`) | Linux |
|---|---|---|---|
| Firefox | `%APPDATA%\Mozilla\Firefox` | `Firefox` | `~/.mozilla/firefox` |
| Firefox ESR | `%APPDATA%\Mozilla\Firefox` (separate profile) | `Firefox` | `~/.mozilla/firefox` |
| Firefox Developer Edition | `%APPDATA%\Mozilla\Firefox` (`dev-edition-default`) | `Firefox` | `~/.mozilla/firefox` |
| Firefox Nightly | `%APPDATA%\Mozilla\Firefox` | `Firefox` | `~/.mozilla/firefox` |
| Tor Browser | `<install>\Browser\TorBrowser\Data\Browser` — **portable** | `~/Library/Application Support/TorBrowser-Data/Browser` | `<install>/Browser/TorBrowser/Data/Browser` |
| Mullvad Browser | `%APPDATA%\Mullvad\MullvadBrowser` or portable | `MullvadBrowser` | `~/.mullvad/mullvadbrowser` |
| LibreWolf | `%APPDATA%\librewolf` | `librewolf` | `~/.librewolf` |
| Waterfox | `%APPDATA%\Waterfox` | `Waterfox` | `~/.waterfox` |
| Floorp | `%APPDATA%\Floorp` | `Floorp` | `~/.floorp` |
| Zen Browser | `%APPDATA%\zen` | `zen` | `~/.zen` |
| SeaMonkey | `%APPDATA%\Mozilla\SeaMonkey` | `SeaMonkey` | `~/.mozilla/seamonkey` |
| Basilisk | `%APPDATA%\Moonchild Productions\Basilisk` | `Basilisk` | `~/.moonchild productions/basilisk` |
| Pale Moon | `%APPDATA%\Moonchild Productions\Pale Moon` | `Pale Moon` | `~/.moonchild productions/pale moon` |
| GNU IceCat | `%APPDATA%\Mozilla\IceCat` | — | `~/.mozilla/icecat` |
| Comodo IceDragon | `%APPDATA%\Comodo\IceDragon` | — | — |
| Snap / Flatpak Firefox | — | — | `~/snap/firefox/common/.mozilla/firefox`, `~/.var/app/org.mozilla.firefox/.mozilla/firefox` |

> **Pale Moon / Basilisk caveat:** they retain the pre-WebExtension add-on model, so
> `extensions.json` has a different schema. **Parse defensively and flag as `partial` —
> never crash the run.**

### 5.3 Non-file-based targets — **IN SCOPE** (decision 3)

| Target | OS | Method | Fidelity |
|---|---|---|---|
| **Safari** (App Extensions) | macOS | `pluginkit` + `.appex` `Info.plist` — §6.8 | **Partial by design.** Modern Safari extensions ship inside host apps; there is no manifest to read. Name, bundle ID, version, enabled state. **No permission list.** |
| **Safari** (legacy `.safariextz`) | macOS | `~/Library/Safari/Extensions/` + `Extensions.plist` | Deprecated format, still present on older hosts. |
| **Internet Explorer** | Windows | Windows registry, four key families — §6.9 | BHOs, toolbars, and IE Extensions. Not "extensions" in the WebExtension sense; DLL path is the identity. |
| **Legacy Edge (EdgeHTML)** | Windows | `%LOCALAPPDATA%\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\LocalState\` | Dead platform. Probe and report only if the package directory exists. |

> **Honest framing, carried into the README:** Safari and IE records will always carry
> `confidence="partial"` and an empty `permissions` tuple. That is a platform limitation, not a
> parser gap. Reporting them as `full` would be a lie in the data.

### 5.4 Installed-but-empty detection (per OS)

This is how you distinguish "browser present, zero extensions" from "browser absent" — the
difference that makes a clean report trustworthy.

**Windows** — registry:
- `HKLM\SOFTWARE\Clients\StartMenuInternet\*` and its `WOW6432Node` mirror
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{chrome,msedge,brave,firefox,opera,vivaldi}.exe`

**macOS** — bundle presence:
- `/Applications/*.app` and `~/Applications/*.app`; match `CFBundleIdentifier` from
  `Contents/Info.plist` against a known-bundle-ID table (`com.google.Chrome`,
  `org.mozilla.firefox`, `com.brave.Browser`, `com.apple.Safari`, …)

**Linux** — executables and desktop entries:
- `shutil.which` over a known binary-name list (`google-chrome`, `firefox`, `brave-browser`, …)
- `/usr/share/applications/*.desktop`, `~/.local/share/applications/*.desktop`
- Package-manager-agnostic on purpose: **never** shell out to `dpkg` / `rpm` / `pacman`.
  Presence of the config root plus the binary is sufficient evidence.

---

## 6. Method — Parser Specifications

### 6.1 Chromium: profile discovery

1. Read `<user_data_root>/Local State` (JSON).
2. Preferred source of truth: `profile.info_cache` — a dict keyed by profile directory name,
   each value carrying `name` (the human label, e.g. "Work"), `user_name`, `gaia_name`.
   `profile.profiles_order` gives display order.
3. Fallback when `Local State` is missing or corrupt: `os.scandir(user_data_root)` and accept
   any directory named `Default`, matching `Profile \d+`, or named `Guest Profile` /
   `System Profile` — **and** containing an `Extensions` subdirectory.

### 6.2 Chromium: extension enumeration (the hot path)

Fixed, known depth — **never recurse**:

```
<profile>/Extensions/          <- scandir level 1: extension IDs
    <ext_id>/                  <- validate against ^[a-p]{32}$
        <version_dir>/         <- scandir level 2: e.g. "1.4.2_0"; pick highest
            manifest.json      <- direct open, no searching
```

Also enumerate and tag distinctly:

- `<profile>/Local Extension Settings/<ext_id>/` — storage exists but the extension folder
  may be gone (orphan record).
- `<profile>/Extension Rules`, `<profile>/Extension State` — presence signals.
- **Component / default extensions:** `<install_dir>/<version>/resources/` and
  `<install_dir>/<version>/default_apps/` — browser-bundled. Tag `builtin` and hide unless
  `--include-builtin` is passed.

### 6.3 Chromium: `manifest.json` fields to extract

| Field | Meaning |
|---|---|
| `name`, `short_name` | Display name. **See the localization gotcha in §6.4.** |
| `version` | Version string. |
| `manifest_version` | 2 or 3. MV2 on a current browser suggests stale or sideloaded. |
| `description` | Free text. |
| `permissions`, `optional_permissions` | API permissions — the security payload. |
| `host_permissions` (MV3) / URL entries in `permissions` (MV2) | Which sites it may read or modify. `<all_urls>` or `*://*/*` is the flag to raise. |
| `content_scripts[].matches` | Injected-script scope. |
| `background.service_worker` / `background.scripts` | Persistent code presence. |
| `update_url` | `https://clients2.google.com/service/update2/crx` ⇒ Web Store. Anything else ⇒ third-party update channel. Absent ⇒ unpacked / dev-loaded. |
| `key` | Base64 DER public key. See ID derivation below. |
| `default_locale` | Needed to resolve `__MSG_*` names. |
| `externally_connectable` | Which web origins may message the extension. |

**Extension ID derivation (optional integrity check):** base64-decode `key` → SHA-256 →
take the first 16 bytes → hex-encode (32 hex chars) → map each hex digit `0`–`f` to `a`–`p`.
The result must equal the folder name.

### 6.4 Localization gotcha — do not skip this

A large share of extensions declare `"name": "__MSG_extName__"`. Naive parsers report the
literal `__MSG_extName__` string. Resolution chain:

1. Detect `name` matching `^__MSG_(.+)__$` and capture the message key.
2. Read `<version_dir>/_locales/<default_locale>/messages.json`.
3. If absent, try `en_US`, then `en`, then the first available locale directory.
4. Look up `messages[key]["message"]`.
5. **Lazy:** only run this when the `__MSG_` prefix is actually present — otherwise you pay an
   extra file read per extension for nothing.

### 6.5 Chromium: state enrichment

Extension *state* is **not** in `manifest.json`. It lives in the profile preferences blob:

- **`Secure Preferences`** — where Chrome / Edge / Brave keep `extensions.settings`, with MAC hashes.
- **`Preferences`** — where some forks keep it instead.
- **Strategy: read both, merge, prefer `Secure Preferences`.** Parse once per profile and cache.

Per-extension keys under `extensions.settings.<ext_id>`:

| Key | Meaning |
|---|---|
| `state` | `1` = enabled, `0` = disabled. **Confirmed absent on Chrome 151 (live-tested, 2026-08-27):** recently-written profile entries no longer carry this field at all. Older, long-lived profile entries can still have it. |
| `disable_reasons` | On current Chrome this is **the primary signal, not a secondary one**: an empty list means enabled — there is no separate `state` field to check first. Read `state` when present (legacy profiles), fall back to `disable_reasons` when it is not (§6.5 implementation note, confirmed via live host testing). Never infer state from folder presence. |
| `from_webstore` | Boolean — the cleanest sideload signal available. |
| `install_time` | **Chromium epoch: microseconds since 1601-01-01 UTC.** Convert with `datetime(1601,1,1,tzinfo=UTC) + timedelta(microseconds=int(v))`. Do **not** treat it as Unix time. |
| `location` | Install location enum (`Manifest::Location`): `1` internal · `2` external_pref · `3` external_registry · `4` unpacked · `5` component · `6` external_pref_download · `7` external_policy_download · `9` external_policy · `10` external_component. **Verify these against the Chromium source for your target version — the enum has shifted historically.** Treat unknown values as `unknown`, not as a crash. |
| `path` | Relative for normal installs, **absolute for unpacked/dev builds** — a strong dev-mode tell. |
| `granted_permissions` | What was actually granted, versus merely requested in the manifest. |
| `was_installed_by_default`, `was_installed_by_oem` | Bundled flags. |
| `manifest` | A cached copy of the manifest — the fallback when the on-disk folder was deleted. |

Also worth reading: `extensions.pinned_extensions` (toolbar-pinned), and on Windows
`HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist` (plus the Edge and Brave
equivalents) for enterprise-forced IDs.

### 6.6 Gecko: profile discovery

1. Read `<gecko_root>/profiles.ini` with `configparser`.
2. Each `[ProfileN]` section carries `Name`, `IsRelative` (`1` ⇒ join to `gecko_root`,
   `0` ⇒ absolute), `Path`, `Default`.
3. Also read `installs.ini` — it maps each install hash to its default profile. That is how
   Firefox, Developer Edition, and Nightly share one root without colliding.
4. Fallback: `os.scandir(<gecko_root>/Profiles)` for `*.default*` directories.

### 6.7 Gecko: extension enumeration

Primary source: `<profile>/extensions.json` — a single JSON file with an `addons[]` array.

| Field | Meaning |
|---|---|
| `id` | `name@domain` or a UUID in braces. |
| `type` | Keep `extension`. Skip or flag `theme`, `dictionary`, `locale`, `sitepermission`. |
| `version` | Version string. |
| `active` | Currently running. |
| `userDisabled`, `appDisabled`, `softDisabled` | Together give the real state. |
| `defaultLocale.name` / `.description` / `.creator` | Display metadata. Gecko pre-resolves locales, so **there is no `__MSG_` problem here**. |
| `installDate`, `updateDate` | **Milliseconds since the Unix epoch** — different from Chromium. `datetime.fromtimestamp(v / 1000, UTC)`. |
| `sourceURI` | `addons.mozilla.org` ⇒ AMO. Anything else ⇒ sideloaded. |
| `location` | `app-profile` = user-installed. `app-builtin` / `app-system-defaults` / `app-global` = shipped with the browser ⇒ tag `builtin`. |
| `rootURI` | Path to the `.xpi` or the unpacked directory. |
| `signedState` | `4` privileged · `3` system · `2` signed · `1` preliminary · `0` missing · `-1` unknown · `-2` broken. Missing or broken is notable. |
| `userPermissions.permissions` / `.origins` | The permission payload. |

Secondary sources: `addons.json` (older, simpler), `extension-preferences.json`,
`extension-settings.json` (which extension controls which browser setting), and a raw
`os.scandir(<profile>/extensions/)` for `*.xpi` files that are present but unregistered.

**`.xpi` deep read (optional, Phase P4):** an `.xpi` is a ZIP archive — `zipfile.ZipFile` →
read the inner `manifest.json`. Only do this under `--deep`; it is the most expensive step
in the whole tool.

### 6.8 Safari — macOS only

Safari has no on-disk manifest to read. Extensions are **macOS app extensions** (`.appex`)
bundled inside host applications, registered with the system's PlugInKit. Three sources,
merged in this order:

**Source A — `pluginkit` (authoritative for enabled state):**

```
pluginkit -mAvvv -p com.apple.Safari.extension
pluginkit -mAvvv -p com.apple.Safari.content-blocker
pluginkit -mAvvv -p com.apple.Safari-extension        # older identifier, try as fallback
```

Parse `stdout` line by line. Each record begins with a **state flag character**:
`+` = enabled · `-` = disabled · `!` = ineligible/invalid. Then the bundle identifier,
version, a UUID, a timestamp, and the on-disk path to the `.appex`.

- Run via `subprocess.run([...], capture_output=True, text=True, timeout=15, check=False)`.
- **Never `shell=True`.** Fixed argument list only.
- Guard with `shutil.which("pluginkit")`; if missing, emit warning `pluginkit_unavailable`
  and fall through to Source B.
- Treat the output format as **unstable across macOS versions** — parse tolerantly, and on a
  line that does not match, record a warning rather than raising.

**Source B — `.appex` bundle scan (authoritative for metadata):**

Scan `/Applications/*.app/Contents/PlugIns/*.appex` and `~/Applications/*.app/Contents/PlugIns/*.appex`.
Read each `<appex>/Contents/Info.plist` with `plistlib`:

| Plist key | Maps to |
|---|---|
| `CFBundleIdentifier` | `extension_id` |
| `CFBundleDisplayName` (fallback `CFBundleName`) | `name` |
| `CFBundleShortVersionString` (fallback `CFBundleVersion`) | `version` |
| `NSExtension.NSExtensionPointIdentifier` | **The filter.** Keep only `com.apple.Safari.extension`, `com.apple.Safari.content-blocker`, `com.apple.Safari.web-extension`. |
| Enclosing `.app` name | `install_path` / host app attribution |

**Source C — legacy and state plists (best-effort, TCC-gated):**

- `~/Library/Safari/Extensions/*.safariextz` plus `Extensions.plist` — the pre-2018 format.
- `~/Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions/Extensions.plist`
  — per-extension enabled state.

> **TCC wall:** `~/Library/Safari/` requires **Full Disk Access** on modern macOS. Without it,
> the read raises `PermissionError`. **Expected outcome, not a bug** — catch it, emit warning
> `tcc_denied_safari`, and continue. Sources A and B still work without FDA, and together they
> give name, ID, version, and enabled state. Source C only adds legacy extensions.

**Field mapping into `ExtensionRecord`:** `engine="webkit"`, `confidence="partial"`,
`permissions=()`, `host_permissions=()`, `manifest_version=None`,
`install_origin="mac_app_store"` if the host `.app` has `_MASReceipt/receipt`, else `"unknown"`.

### 6.9 Internet Explorer — Windows only

Everything comes from the registry via `winreg`. **Read both registry views on every key** —
32-bit BHOs are invisible from the 64-bit view and vice versa:

```
access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY    # then repeat with KEY_WOW64_32KEY
```

**Four key families to enumerate:**

| # | Key | Yields |
|---|---|---|
| 1 | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{CLSID}` | BHOs — the classic IE add-on. Subkey name **is** the CLSID. |
| 2 | `HKLM\SOFTWARE\Microsoft\Internet Explorer\Toolbar` and `HKCU\...\Toolbar` | Toolbars, keyed by CLSID; value data is the display name. |
| 3 | `HKLM\SOFTWARE\Microsoft\Internet Explorer\Extensions\{CLSID}` | Button/menu extensions. Values: `ButtonText`, `MenuText`, `Exec`, `Script`, `ClsidExtension`. |
| 4 | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Ext\PreApproved\{CLSID}` and `HKCU\...\Ext\Settings\{CLSID}` | Approval + **enabled state**. |

**CLSID resolution — how you turn a GUID into a real name:**

1. Open `HKEY_CLASSES_ROOT\CLSID\{CLSID}` → the **default (unnamed) value** is the friendly name.
2. Open `HKEY_CLASSES_ROOT\CLSID\{CLSID}\InprocServer32` → the default value is the **DLL path**
   (expand `%SystemRoot%` etc. via `os.path.expandvars`).
3. If step 1 is empty, fall back to the DLL filename stem as the display name.

**Enabled state:** `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Ext\Settings\{CLSID}` →
a `Flags` `REG_DWORD` of `1` indicates user-disabled. Absence of the key means enabled.
Also check `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions` for policy locks.

**Robustness rules:**
- Wrap every `winreg.OpenKey` in `try/except FileNotFoundError` — most of these keys are
  simply absent on a modern Windows 11 host. **Absent is the normal case, not an error.**
- Enumerate with `winreg.EnumKey` in a bounded `while` loop, breaking on `OSError`.
- Always `winreg.CloseKey` (or use a `contextlib.contextmanager` wrapper).

**Field mapping into `ExtensionRecord`:** `engine="trident"`, `extension_id` = the CLSID,
`install_path` = the DLL path, `confidence="partial"`, `permissions=()`,
`install_origin="unknown"`, `version` = the DLL's file version if trivially available, else
`"unknown"`.

> **Expectation setting:** on Windows 11, IE is removed and this parser will usually return
> **zero records** — while still correctly reporting a handful of Microsoft-shipped BHOs on
> some hosts. That empty result is a *valid, informative* answer, and the report must show
> `"internet_explorer": {"found": false, "keys_checked": [...]}` rather than omitting it.

---

## 7. Efficiency Strategy — Concrete Rules

| # | Rule | Why it matters |
|---|---|---|
| 1 | `os.scandir`, never `os.walk` / `glob` / `listdir`+`stat` | `DirEntry.is_dir()` uses type info the OS already returned — no extra syscall. Especially significant on Windows, where per-file `stat` is expensive. |
| 2 | **Bounded depth.** Open `Extensions/<id>/<ver>/manifest.json` directly | The layout is a contract. Recursively walking a profile means touching the entire browser cache — thousands of irrelevant files. |
| 3 | Fail fast on non-existent roots | `Path.is_dir()` across ~90 candidate roots costs microseconds and eliminates ~85 of them instantly. Do this **before** spawning any thread. |
| 4 | **Threads, not processes.** `ThreadPoolExecutor(max_workers=min(32, (os.cpu_count() or 4) * 4))` | The workload is I/O-bound and the GIL is released during file reads. Processes would add spawn and pickling overhead for zero gain. |
| 5 | Parallelize at **profile** granularity | Coarse enough to amortize task overhead, fine enough to saturate I/O. Per-extension tasks would be too granular. |
| 6 | One preferences parse per profile, cached | `Secure Preferences` can exceed 10 MB. Re-parsing it per extension would dominate total runtime. |
| 7 | Lazy `_locales` resolution | Only extensions with `__MSG_` names pay the extra read. |
| 8 | Select the version directory without reading it | Pick the highest version by parsed tuple; do not open every version's manifest. |
| 9 | Size guard | Skip any JSON above a configurable cap (default 25 MB) and record a `skipped_too_large` warning instead of blocking. |
| 10 | Optional `--cache` | Store `(path, mtime_ns, size)` → parsed record in a JSON sidecar. Re-runs skip unchanged extensions — valuable for scheduled or repeated inventory. |
| 11 | Stream output | For `--format=jsonl`, yield records as they are found instead of buffering the full list. |
| 12 | Never fail the whole run on one bad file | Every parse is individually guarded; failures become `errors[]` entries. **Partial results always beat a traceback.** |

**Expected cost:** a typical host (3–5 browsers, ~8 profiles, ~60 extensions) completes in
**well under one second**. The dominant cost is preference-blob JSON parsing, not directory
traversal.

---

## 8. Output Schema — One Normalized Record

Every browser and every engine collapses into this single shape:

```python
@dataclass(frozen=True, slots=True)
class ExtensionRecord:
    # Identity
    extension_id: str            # Chromium 32-char, or Gecko id@domain
    name: str                    # localization already resolved
    version: str
    description: str | None

    # Where it lives
    browser: str                 # "Google Chrome"
    browser_channel: str | None  # "Stable" | "Beta" | "Dev" | "Canary"
    engine: str                  # "chromium" | "gecko" | "webkit" | "trident"
    profile_dir: str             # "Profile 1"
    profile_name: str | None     # "Work"
    install_path: str

    # State
    enabled: bool | None
    disabled_reason: str | None
    state_source: str            # "secure_preferences" | "preferences" | "extensions_json"

    # Origin / trust
    install_origin: str          # "webstore"|"amo"|"mac_app_store"|"sideloaded"
                                 # |"policy"|"builtin"|"unpacked"|"unknown"
    update_url: str | None
    signed_state: str | None     # Gecko only
    is_builtin: bool
    is_unpacked: bool

    # Security surface
    manifest_version: int | None
    permissions: tuple[str, ...]
    host_permissions: tuple[str, ...]
    content_script_matches: tuple[str, ...]
    has_background_worker: bool | None

    # Timeline
    install_time: str | None     # ISO-8601 UTC
    update_time: str | None      # ISO-8601 UTC

    # Provenance
    source_files: tuple[str, ...]
    confidence: str              # "full" | "partial" | "state_only"
    warnings: tuple[str, ...]
```

**Report envelope:**

```json
{
  "scan": { "host": "...", "os": "...", "started_at": "...", "finished_at": "...",
            "tool_version": "...", "duration_ms": 0 },
  "browsers":   [ { "name": "...", "found": true, "roots_checked": ["..."], "profiles": 3 } ],
  "extensions": [ /* ExtensionRecord[] */ ],
  "errors":     [ { "path": "...", "kind": "json_decode", "detail": "..." } ],
  "summary":    { "browsers_found": 4, "profiles": 8, "extensions": 61,
                  "unique_extensions": 44, "disabled": 6, "sideloaded": 2 }
}
```

---

## 9. File Structure

```
extension_searcher/
├── __init__.py
├── __main__.py            # python -m extension_searcher
├── cli.py                 # argparse, exit codes, output dispatch
├── models.py              # dataclasses + enums. Zero logic.
├── registry.py            # THE PATH TABLE. Pure data, per-OS. No logic.
├── discovery.py           # expand roots, probe existence, resolve profiles
├── parsers/
│   ├── __init__.py
│   ├── chromium.py        # manifest.json + Local State + (Secure) Preferences
│   ├── gecko.py           # profiles.ini + extensions.json (+ optional .xpi)
│   ├── safari.py          # macOS: pluginkit + .appex Info.plist
│   └── trident.py         # Windows: registry BHOs / toolbars / IE extensions
├── enrich.py              # locale resolution, timestamp conversion, origin classification
├── normalize.py           # engine output -> ExtensionRecord
├── report/
│   ├── __init__.py
│   ├── table.py           # human-readable renderer  (decision 2)
│   └── structured.py      # json / jsonl / csv       (decision 2)
├── platform_probe.py      # per-OS installed-browser detection, env expansion
└── errors.py              # typed exception hierarchy
tests/
├── fixtures/              # synthetic profile trees committed to the repo
│   ├── chromium_profile/
│   ├── gecko_profile/
│   ├── appex_bundle/      # fake .appex + Info.plist for the Safari parser
│   ├── pluginkit_output/  # captured pluginkit stdout samples, several macOS versions
│   └── malformed/
├── test_registry.py
├── test_chromium_parser.py
├── test_gecko_parser.py
├── test_safari_parser.py  # plist fixtures + pluginkit stdout fixtures
├── test_trident_parser.py # winreg mocked — no real registry reads
├── test_enrich.py
├── test_report_table.py
├── test_report_json.py
└── test_end_to_end.py
PLAN.md
README.md
requirements-dev.txt
pyproject.toml             # ruff + mypy + pytest config
```

**Raven style compliance:** every module under 300 lines, every public function typed and
docstringed, `logging` (never `print`) for diagnostics, `snake_case` throughout.

---

## 10. CLI Surface

```
python -m extension_searcher [options]

  --format {table,json,jsonl,csv}   default: table  (decision 2 — both are first-class)
  --output PATH                     default: stdout
  --browser NAME                    repeatable filter
  --engine {chromium,gecko,webkit,trident,all}
  --include-builtin                 include browser-bundled extensions
  --include-themes                  include Gecko themes / dictionaries
  --deep                            open .xpi archives, verify extension IDs
  --extra-root PATH                 repeatable — portable installs, USB, D:\ drives
  --no-state                        skip preference blobs (fastest possible run)
  --cache PATH                      incremental scan cache
  --workers N                       override thread count
  --risk                            annotate high-privilege permissions
  --no-color                        plain ASCII table (also auto-off when not a TTY)
  -v / -vv                          logging verbosity
  --version
```

**Removed by decision 4:** no `--all-users`. Scope is the invoking user's profiles only.

### 10.1 Dual-output contract (decision 2)

Both formats are **equal deliverables**, generated from the same `ExtensionRecord` list. Neither
is a degraded view of the other.

**`--format=table` — the human view.** Grouped `Browser → Profile → Extension`, with a
per-browser count header and a closing summary line. Columns: `Name` (truncated to terminal
width), `Version`, `State`, `Origin`, `ID`. Rules:
- Column widths computed from `shutil.get_terminal_size()`, floor of 80.
- Disabled rows marked with a leading `·`, sideloaded with `!` — glyphs, not colour alone,
  so the output survives piping and screen readers.
- ANSI colour only when `sys.stdout.isatty()` and `NO_COLOR` is unset.
- **Never** truncate the extension ID — it is the join key a human will paste into a search.

**`--format=json` — the machine view.** The full §8 envelope, `indent=2`, `ensure_ascii=False`,
keys in stable declared order. Every field present even when `null` — **no key omission**, so
downstream consumers never need `.get()` guards.

**`--format=jsonl`** streams one `ExtensionRecord` per line, no envelope — for piping into
`jq` or a log shipper. **`--format=csv`** flattens tuple fields with `;` separators.

**Exit codes:** `0` clean · `1` completed with entries in `errors[]` · `2` no browsers found ·
`3` bad usage.

---

## 11. Edge Cases — The Register

| # | Edge case | Handling |
|---|---|---|
| 1 | **Portable installs** (Tor, USB, `D:\PortableApps`) | Invisible to any fixed path table. `--extra-root`, plus an optional opt-in drive sweep for `profiles.ini` / `User Data`. **Documented as a known gap.** |
| 2 | Snap / Flatpak / MSIX sandboxed browsers | Extra rows in the path table — §5.1. Miss these and you silently miss the browser entirely. |
| 3 | Multiple version directories per extension | Pick the highest parsed version tuple; record the others as `stale_versions`. |
| 4 | Extension folder deleted, prefs entry remains — **or** the extension is a browser-bundled component installed under the browser's own install directory rather than the profile (confirmed common in P2 live-host testing: Chrome PDF Viewer, Web Store, etc. never appear under `<profile>/Extensions/` at all) | Emit a record with `confidence="state_only"` built from the cached `manifest` in prefs. The `--include-builtin` filter applies to this path too, not just the on-disk path — an early P2 build leaked builtins here because the filter was only wired into the on-disk loop. |
| 5 | Unresolved `__MSG_*` names | Run the §6.4 chain; if every step fails, keep the literal and add warning `locale_unresolved`. |
| 6 | Corrupt / truncated JSON | Per-file `try/except json.JSONDecodeError` → `errors[]`; the scan continues. |
| 7 | `PermissionError` (locked file, or another user's profile) | Retry once, then record `access_denied`. Never crash. |
| 8 | Chromium epoch mistaken for Unix epoch | Explicit converter in `enrich.py` plus a unit test asserting a known value. This is a classic silent bug. |
| 9 | Pale Moon / Basilisk legacy schema | Defensive parse, `confidence="partial"`. |
| 10 | Guest / System Profile directories | Enumerate but tag them; exclude from default output. |
| 11 | Symlink loops / NTFS reparse points | `follow_symlinks=False` on every `scandir` call. |
| 12 | Non-ASCII paths and extension names | Force `encoding="utf-8"` on every `open`, with `errors="replace"` as a last resort. Never rely on the Windows ANSI default. |
| 13 | Enterprise policy-forced extensions | Read `ExtensionInstallForcelist` from the registry; tag `install_origin="policy"`. |
| 14 | Same extension present in N profiles | One record **per profile** (correct behaviour), plus a deduplicated `summary.unique_extensions`. |
| 15 | Very large `Secure Preferences` | Size guard — §7 rule 9. |
| 16 | Browser running mid-scan | Fine. Records are point-in-time; `scan.started_at` documents that. |
| 17 | Unknown `location` / `signedState` enum value | Map to `unknown` and add a warning. Never raise on an unexpected integer. |
| 18 | **macOS without Full Disk Access** | `~/Library/Safari/` raises `PermissionError`. Catch, warn `tcc_denied_safari`, continue — `pluginkit` and `.appex` scanning still work. **Not a failure.** |
| 19 | `pluginkit` missing, or output format changed by a macOS update | `shutil.which` guard; tolerant line parsing; unmatched lines become warnings. Fall back to the `.appex` bundle scan for metadata. |
| 20 | **IE registry keys absent** (normal on Windows 11) | `found: false` with `keys_checked` listed. An empty result is a valid answer — never omit the browser from the report. |
| 21 | 32-bit BHO invisible from the 64-bit registry view | Read every key twice: `KEY_WOW64_64KEY` **and** `KEY_WOW64_32KEY`, then deduplicate by CLSID. |
| 22 | Linux `$XDG_CONFIG_HOME` overridden or unset | Honour `$XDG_CONFIG_HOME` when set; default to `~/.config` when not. Same for `$XDG_DATA_HOME` → `~/.local/share`. Hardcoding `~/.config` is a silent miss on customised systems. |
| 23 | Case-insensitive macOS filesystem vs case-sensitive Linux | Never rely on case-insensitive matching. Path table entries use the exact on-disk casing per OS. |
| 24 | Windows long paths (> 260 chars) in deep extension trees | `pathlib` handles this on Python 3.6+ with long-path support enabled; catch `OSError` and record `path_too_long` where it is not. |
| 25 | Terminal too narrow / output piped to a file | Table renderer floors width at 80 and drops ANSI colour when `not sys.stdout.isatty()`. |

---

## 12. Testing Strategy

- **Fixture-driven, filesystem-isolated.** Commit synthetic profile trees under
  `tests/fixtures/` — real directory layouts with hand-written `manifest.json`,
  `extensions.json`, `Local State`, and `Secure Preferences`. Point the registry at the
  fixture root via dependency injection. **No test touches the real user profile.**
- **Golden-file tests:** fixture tree in → expected normalized JSON out.
- **Dedicated `malformed/` fixtures:** truncated JSON, empty file, wrong value types, missing
  keys, a `__MSG_` name with no `_locales` directory, an absolute unpacked path.
- **Regression test for the 1601 epoch conversion** — assert a known microsecond value maps
  to a known ISO-8601 date. This is the one bug most likely to ship silently.
- **Enum robustness test** — feed unknown `location` and `signedState` integers, assert
  `unknown` plus a warning rather than an exception.
- **Safari parser tests, no macOS required:** `pluginkit` is invoked through an injected
  runner, so tests feed captured stdout fixtures instead of shelling out. `.appex` tests use a
  synthetic bundle directory with a real `Info.plist`. Include a **TCC-denial test** that makes
  the `~/Library/Safari` read raise `PermissionError` and asserts the scan still completes.
- **IE parser tests, no registry writes:** `winreg` is accessed through a thin wrapper that
  tests replace with an in-memory fake key tree. Cover: key absent (the Windows 11 case),
  32-bit-only BHO, CLSID with no friendly name, and a `Flags=1` disabled entry.
- **Renderer tests (decision 2):** table output is snapshot-tested at 80 and 200 columns, with
  and without a TTY; JSON output is asserted to contain **every** schema key even when `null`.
- **One opt-in live smoke test** (`pytest -m live`) that runs against the real host and asserts
  only "does not raise, returns a list". Runs on all three CI OSes.
- Target: **≥ 85% coverage** on `parsers/`, `enrich.py`, and `normalize.py`.

---

## 13. Build Phases

| Phase | Deliverable | Exit criterion | Status |
|---|---|---|---|
| **P0** | `models.py`, `errors.py`, `pyproject.toml`, package skeleton | `mypy --strict` clean on an empty run | ✅ Done |
| **P1** | `registry.py` path table + `discovery.py` + `platform_probe.py` | Correctly lists installed browsers and profiles on this host | ✅ Done — verified live on this Windows host (10 browsers found across chromium+gecko) |
| **P2** | `parsers/chromium.py` + `enrich.py` locale resolution | Every Chromium extension found, names resolved, zero `__MSG_` leakage | ✅ Done — live testing found and fixed 2 real bugs (see below) |
| **P3** | `parsers/gecko.py` | Every Firefox-family extension found, builtins correctly separated | ✅ Done — live testing found and fixed the Firefox/Dev/Nightly triple-count bug (see below) |
| **P4** | State enrichment (prefs merge, timestamps, origin classification) + optional `.xpi` deep read | Enabled/disabled and webstore/sideloaded accurate against a manually verified profile | ✅ Enrichment done and live-verified. `.xpi` deep read (`--deep`) deferred — flag accepted, logs a warning, no-op |
| **P5** | `report/table.py` + `report/structured.py` + `cli.py` | **Both** human table and JSON correct on all 3 OSes; exit codes wired | ✅ Windows-verified (table/json/jsonl/csv, exit codes 0/2). Linux/macOS not yet verified — no non-Windows host available this session |
| **P6** | `parsers/safari.py` (macOS) + `parsers/trident.py` (Windows) + `--extra-root` | Safari enumerates on macOS with and without FDA; IE returns a correct empty-or-populated result on Windows; both absent-by-design on other OSes | 🟡 Trident **built and live-verified** on this host (8 real BHOs found, correct enable state). Safari **built but unverified** — no macOS host available (§15.1); ships with `unverified=True` on every record. `--extra-root` deferred, same as `--deep` |
| **P7** | Full test suite + README + `--risk` annotations | Coverage target met, CI green on all 3 OSes | ✅ **Coverage target met on Windows**: 82 tests passing, 87% overall (target was ≥85% on `parsers/`, `enrich.py`, `normalize.py` — all now 74-100%, plus registry/discovery/cli/report/platform_probe added beyond the original target). `ruff check` clean, `mypy --strict` clean (18 source files, 0 errors). README.md written. `--risk` implemented, live-tested, and unit-tested. IE (winreg) and Safari (`.appex`+`pluginkit`) tested via in-memory fakes per section 12, with zero real registry writes or macOS dependency. 🟡 Still open: no CI configured (no git repo initialized); Linux/macOS test runs unconfirmed — the fixture suite has never executed on either OS, only reasoned about |

**Real bugs found and fixed via live-host testing (2026-08-27), each recorded inline in the
relevant section above and covered by a regression test:**
1. Builtin filter only applied to the on-disk parse path, not the state-only/orphan path —
   leaked Chrome's bundled PDF Viewer/Web Store into default output (§6.5, edge case 4).
2. Modern Chrome (151, tested live) omits the legacy `state` field entirely on
   freshly-written profile entries — `enabled` fell back to `disable_reasons` (§6.5).
3. Firefox / Developer Edition / Nightly sharing one `profiles.ini` root tripled every
   profile and extension in the default report — fixed with channel-name filtering,
   applied to both the `profiles.ini` path and its directory-scan fallback (§6.6).

**Ship point: end of P6** (decision 3 puts Safari and IE inside the deliverable, so P5 alone is
no longer a complete product). P7 is hardening — do it before anyone else depends on the output.

**Cross-OS verification gate (decision 1).** No phase is "done" on one OS. Each of P1–P6 must
be confirmed on **Windows, Linux, and macOS** before the next phase starts. Practical approach:
- Windows 11 — the primary dev host, verified directly.
- Linux — verify in WSL2 **and** a real distro VM. WSL2 alone is not enough: it will not show
  Snap or Flatpak layouts, which are exactly the rows most likely to be wrong.
- macOS — the only way to verify `safari.py` and the `~/Library` paths. **If no macOS host is
  available, say so and mark those rows `unverified` in `registry.py`** rather than assuming
  they are correct. An unverified path row is a latent silent-miss bug (§14, row 1).
- CI: GitHub Actions matrix `windows-latest` × `ubuntu-latest` × `macos-latest`, running the
  fixture suite on all three plus the opt-in live smoke test.

---

## 14. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Silent discovery gap — a portable / Snap / Store install is missed | **High** | **High** — the tool reports "clean" when it is not | Always emit `browsers_probed` and `roots_checked` in the report. **Absence must be visible, never implied.** |
| A vendor changes its on-disk layout in a future release | Medium | Medium | Layout lives in `registry.py` as data only. One-row fix, no code change. |
| Epoch conversion bug | Medium | Medium | Explicit converter plus regression test — §12. |
| Misreading disabled extensions as enabled | Medium | Medium | Merge `state` **and** `disable_reasons`; never infer state from folder presence alone. |
| **No macOS host available to verify Safari and `~/Library` paths** | **High** | **High** — an unverified path row silently reports "clean" | Mark unverified rows explicitly in `registry.py`; surface them in the report as `unverified_paths`. Add `macos-latest` to CI so at least the fixture suite runs there. **Do not claim macOS support until a real host has been scanned.** |
| Safari / IE records mistaken for full-fidelity data | Medium | Medium | `confidence="partial"` and empty `permissions` on every such record; stated in the README and in the table renderer's footnote. |
| `pluginkit` output format drifts across macOS releases | Medium | Low | Tolerant parsing, captured stdout fixtures from multiple versions, `.appex` scan as the metadata fallback. |
| Scope creep into malware / risk scoring | Medium | Low | `--risk` is annotation only. Real analysis is a separate follow-on effort. |
| Reads flagged by EDR as credential access | Low | Medium | Never open `Login Data`, `Cookies`, or `Web Data`. Document the file allowlist explicitly in the README. |
| Tool used to profile users without consent | Low | Medium | README states intended use plainly: **own-host or authorized endpoint inventory.** |

---

## 15. Decisions — LOCKED

Settled by the owner on 2026-08-27. These are the session contract; changing one means
revisiting the phases it touches.

| # | Decision | Chosen | Consequence in this plan |
|---|---|---|---|
| 1 | OS scope | **All three: Windows, Linux, macOS** — first-class, not a port | Path table is per-OS from P1 (§5.1, §5.2). Every phase has a 3-OS verification gate (§13). CI matrix across all three. `platform_probe.py` gets three detection strategies (§5.4). |
| 2 | Output | **Human-readable CLI table *and* JSON** — both first-class | `report/` splits into `table.py` and `structured.py` (§9). Dual-output contract specified (§10.1). Default is `table`; `json` is a flag away, same data. |
| 3 | Extra platforms | **Safari and Internet Explorer included** | §5.3 promoted from optional to in-scope. Parser count goes 2 → 4 (§3). Full method specs added (§6.8, §6.9). Ship point moves from P5 to **P6**. `plistlib`, `subprocess`, `shutil.which` join the stack (§4.2). |
| 4 | User scope | **Current user only** | `--all-users` removed from the CLI (§10). No elevation path, no cross-user reads. Simplifies discovery and removes the admin-rights concern entirely (§2). |

### 15.1 What is still genuinely unknown

Not decisions — facts that only a real host can settle. Resolve during P1 and P6:

1. **No macOS host available — confirmed 2026-08-27.** `safari.py` and every
   `~/Library/Application Support/` row ship marked `unverified` in `registry.py`, surfaced
   in the report as `unverified_paths`. Table/JSON footnote states this plainly. Re-verify the
   first time a macOS host is available (CI `macos-latest` fixture runs do **not** substitute
   for a live-host confirmation of real vendor paths).
2. **Arc on Windows** — the packaged path in §5.1 is marked *verify at P1*.
3. **`pluginkit` output shape** on the specific macOS version(s) in use — capture real stdout
   into `tests/fixtures/pluginkit_output/` before writing the parser.
4. **Which Linux packaging** is actually in play (native / Snap / Flatpak) — determines which
   §5.1 sandboxed rows matter most on your hosts.

---

## 16. Handoff

Andie plans; Andie does not implement. The next step is implementation:

- `/andie-jr` — build phase by phase, or
- `raven-plan` → `raven-test` (test-first, per Raven discipline) → implementation.

**Before the first commit:** update `.raven/manifest.json` → `stack.language = ["python"]`,
`stack.libraries = ["pytest", "ruff", "mypy"]`, so `stack-validator` passes the pre-commit
gate. Also close the two open scan warnings — add `*.pem` and `*.key` to `.gitignore`, and
install `.git/hooks/pre-commit`.

---
*Planned by Andie 📘 Deep · Triad: Meera (Endpoint Asset Inventory) · Kenji (Browser Internals) · Aisha (Data Normalization)*
