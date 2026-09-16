"""The browser path table. PLAN.md section 5 — pure data, no logic.

Adding a browser means adding one `BrowserSpec` row, never a new code path.

Every `macos` entry is marked `macos_unverified=True` by default: PLAN.md
section 15.1 records that no macOS host has been available to confirm these
paths against a real install. `discovery.py` surfaces every unverified path
actually probed into `ScanReport.unverified_paths` — absence of a live
confirmation must stay visible, never silently implied as "checked".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from extension_searcher.models import Engine


class RootKind:
    """Named filesystem roots, resolved per-OS by `platform_probe.py`."""

    WIN_LOCALAPPDATA = "win_localappdata"
    WIN_APPDATA = "win_appdata"
    MAC_APP_SUPPORT = "mac_app_support"
    HOME = "home"
    LINUX_CONFIG = "linux_config"  # honours $XDG_CONFIG_HOME, PLAN.md 5.1/22


@dataclass(frozen=True, slots=True)
class PathEntry:
    """One candidate root + relative subpath, for one OS."""

    root: str
    subpath: str


@dataclass(frozen=True, slots=True)
class BrowserSpec:
    """One browser's cross-OS profile-root candidates."""

    name: str
    engine: Engine
    channel: str | None = None
    windows: tuple[PathEntry, ...] = field(default_factory=tuple)
    macos: tuple[PathEntry, ...] = field(default_factory=tuple)
    linux: tuple[PathEntry, ...] = field(default_factory=tuple)
    macos_unverified: bool = True
    verify_note: str | None = None


def _win_local(subpath: str) -> PathEntry:
    return PathEntry(RootKind.WIN_LOCALAPPDATA, subpath)


def _win_roaming(subpath: str) -> PathEntry:
    return PathEntry(RootKind.WIN_APPDATA, subpath)


def _mac(subpath: str) -> PathEntry:
    return PathEntry(RootKind.MAC_APP_SUPPORT, subpath)


def _linux_cfg(subpath: str) -> PathEntry:
    return PathEntry(RootKind.LINUX_CONFIG, subpath)


def _home(subpath: str) -> PathEntry:
    return PathEntry(RootKind.HOME, subpath)


# --------------------------------------------------------------------------
# 5.1 Chromium family — manifest.json under Extensions/<id>/<ver>/
# --------------------------------------------------------------------------

CHROMIUM_BROWSERS: tuple[BrowserSpec, ...] = (
    BrowserSpec(
        "Google Chrome", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Google\Chrome\User Data"),),
        macos=(_mac("Google/Chrome"),),
        linux=(_linux_cfg("google-chrome"),),
    ),
    BrowserSpec(
        "Google Chrome Beta", Engine.CHROMIUM, "Beta",
        windows=(_win_local(r"Google\Chrome Beta\User Data"),),
        macos=(_mac("Google/Chrome Beta"),),
        linux=(_linux_cfg("google-chrome-beta"),),
    ),
    BrowserSpec(
        "Google Chrome Dev", Engine.CHROMIUM, "Dev",
        windows=(_win_local(r"Google\Chrome Dev\User Data"),),
        macos=(_mac("Google/Chrome Dev"),),
        linux=(_linux_cfg("google-chrome-unstable"),),
    ),
    BrowserSpec(
        "Google Chrome Canary", Engine.CHROMIUM, "Canary",
        windows=(_win_local(r"Google\Chrome SxS\User Data"),),
        macos=(_mac("Google/Chrome Canary"),),
    ),
    BrowserSpec(
        "Microsoft Edge", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Microsoft\Edge\User Data"),),
        macos=(_mac("Microsoft Edge"),),
        linux=(_linux_cfg("microsoft-edge"),),
    ),
    BrowserSpec(
        "Microsoft Edge Beta", Engine.CHROMIUM, "Beta",
        windows=(_win_local(r"Microsoft\Edge Beta\User Data"),),
        macos=(_mac("Microsoft Edge Beta"),),
        linux=(_linux_cfg("microsoft-edge-beta"),),
    ),
    BrowserSpec(
        "Microsoft Edge Dev", Engine.CHROMIUM, "Dev",
        windows=(_win_local(r"Microsoft\Edge Dev\User Data"),),
        macos=(_mac("Microsoft Edge Dev"),),
        linux=(_linux_cfg("microsoft-edge-dev"),),
    ),
    BrowserSpec(
        "Microsoft Edge Canary", Engine.CHROMIUM, "Canary",
        windows=(_win_local(r"Microsoft\Edge SxS\User Data"),),
        macos=(_mac("Microsoft Edge Canary"),),
    ),
    BrowserSpec(
        "Brave", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"BraveSoftware\Brave-Browser\User Data"),),
        macos=(_mac("BraveSoftware/Brave-Browser"),),
        linux=(
            _linux_cfg("BraveSoftware/Brave-Browser"),
            _home("snap/brave/current/.config/BraveSoftware/Brave-Browser"),
            _home(".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"),
        ),
    ),
    BrowserSpec(
        "Brave Beta", Engine.CHROMIUM, "Beta",
        windows=(_win_local(r"BraveSoftware\Brave-Browser-Beta\User Data"),),
        macos=(_mac("BraveSoftware/Brave-Browser-Beta"),),
        linux=(_linux_cfg("BraveSoftware/Brave-Browser-Beta"),),
    ),
    BrowserSpec(
        "Brave Nightly", Engine.CHROMIUM, "Nightly",
        windows=(_win_local(r"BraveSoftware\Brave-Browser-Nightly\User Data"),),
        macos=(_mac("BraveSoftware/Brave-Browser-Nightly"),),
        linux=(_linux_cfg("BraveSoftware/Brave-Browser-Nightly"),),
    ),
    BrowserSpec(
        "Opera", Engine.CHROMIUM, "Stable",
        windows=(_win_roaming(r"Opera Software\Opera Stable"),),
        macos=(_mac("com.operasoftware.Opera"),),
        linux=(_linux_cfg("opera"),),
    ),
    BrowserSpec(
        "Opera GX", Engine.CHROMIUM, "Stable",
        windows=(_win_roaming(r"Opera Software\Opera GX Stable"),),
        macos=(_mac("com.operasoftware.OperaGX"),),
    ),
    BrowserSpec(
        "Opera Air", Engine.CHROMIUM, "Stable",
        windows=(_win_roaming(r"Opera Software\Opera Air"),),
        macos=(_mac("com.operasoftware.OperaAir"),),
    ),
    BrowserSpec(
        "Opera Crypto", Engine.CHROMIUM, "Stable",
        windows=(_win_roaming(r"Opera Software\Opera Crypto Stable"),),
        macos=(_mac("com.operasoftware.OperaCrypto"),),
    ),
    BrowserSpec(
        "Vivaldi", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Vivaldi\User Data"),),
        macos=(_mac("Vivaldi"),),
        linux=(_linux_cfg("vivaldi"),),
    ),
    BrowserSpec(
        "Chromium", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Chromium\User Data"),),
        macos=(_mac("Chromium"),),
        linux=(
            _linux_cfg("chromium"),
            _home("snap/chromium/common/chromium"),
            _home(".var/app/org.chromium.Chromium/config/chromium"),
        ),
    ),
    BrowserSpec(
        "Yandex Browser", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Yandex\YandexBrowser\User Data"),),
        macos=(_mac("Yandex/YandexBrowser"),),
        linux=(_linux_cfg("yandex-browser"),),
    ),
    BrowserSpec(
        "Naver Whale", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Naver\Naver Whale\User Data"),),
        macos=(_mac("Naver/Whale"),),
        linux=(_linux_cfg("naver-whale"),),
    ),
    BrowserSpec(
        "CocCoc", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"CocCoc\Browser\User Data"),),
        macos=(_mac("Coccoc"),),
    ),
    BrowserSpec(
        "360 Chrome", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"360Chrome\Chrome\User Data"),),
    ),
    BrowserSpec(
        "360 Secure Browser", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"360ChromeX\Chrome\User Data"),),
    ),
    BrowserSpec(
        "Epic Privacy Browser", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Epic Privacy Browser\User Data"),),
    ),
    BrowserSpec(
        "SRWare Iron", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Chromium\User Data"),),
    ),
    BrowserSpec(
        "Slimjet", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Slimjet\User Data"),),
    ),
    BrowserSpec(
        "CentBrowser", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"CentBrowser\User Data"),),
    ),
    BrowserSpec(
        "Ungoogled Chromium", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Chromium\User Data"),),
        macos=(_mac("Chromium"),),
        linux=(_linux_cfg("chromium"),),
    ),
    BrowserSpec(
        "Thorium", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Thorium\User Data"),),
        macos=(_mac("Thorium"),),
        linux=(_linux_cfg("thorium"),),
    ),
    BrowserSpec(
        "Supermium", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Supermium\User Data"),),
    ),
    BrowserSpec(
        "Wavebox", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"WaveboxApp\User Data"),),
        macos=(_mac("WaveboxApp"),),
        linux=(_linux_cfg("wavebox"),),
    ),
    BrowserSpec(
        "Sidekick", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Sidekick\User Data"),),
        macos=(_mac("Sidekick"),),
    ),
    BrowserSpec(
        "Maxthon", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Maxthon\Application\User Data"),),
        macos=(_mac("Maxthon"),),
    ),
    BrowserSpec(
        "Comodo Dragon", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Comodo\Dragon\User Data"),),
    ),
    BrowserSpec(
        "Iridium", Engine.CHROMIUM, "Stable",
        windows=(_win_local(r"Iridium\User Data"),),
        linux=(_linux_cfg("iridium-browser"),),
    ),
    BrowserSpec(
        "Arc", Engine.CHROMIUM, "Stable",
        windows=(
            _win_local(
                r"Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data"
            ),
        ),
        macos=(_mac("Arc/User Data"),),
        verify_note="Windows MSIX package family name unverified at P1 — check the real "
                    "PackageFamilyName on an Arc-for-Windows host before relying on this row.",
    ),
)


# --------------------------------------------------------------------------
# 5.2 Gecko family — profiles.ini -> extensions.json
# --------------------------------------------------------------------------

GECKO_BROWSERS: tuple[BrowserSpec, ...] = (
    BrowserSpec(
        "Mozilla Firefox", Engine.GECKO, "Stable",
        windows=(_win_roaming(r"Mozilla\Firefox"),),
        macos=(_mac("Firefox"),),
        linux=(
            _home(".mozilla/firefox"),
            _home("snap/firefox/common/.mozilla/firefox"),
            _home(".var/app/org.mozilla.firefox/.mozilla/firefox"),
        ),
    ),
    BrowserSpec(
        "Firefox Developer Edition", Engine.GECKO, "Dev",
        windows=(_win_roaming(r"Mozilla\Firefox"),),
        macos=(_mac("Firefox"),),
        linux=(_home(".mozilla/firefox"),),
    ),
    BrowserSpec(
        "Firefox Nightly", Engine.GECKO, "Nightly",
        windows=(_win_roaming(r"Mozilla\Firefox"),),
        macos=(_mac("Firefox"),),
        linux=(_home(".mozilla/firefox"),),
    ),
    BrowserSpec(
        "Tor Browser", Engine.GECKO, "Stable",
        macos=(_mac("../TorBrowser-Data/Browser"),),
        verify_note="Tor Browser is typically a portable install; the fixed roots here are "
                    "a best-effort default. Use --extra-root for non-default install paths.",
    ),
    BrowserSpec(
        "Mullvad Browser", Engine.GECKO, "Stable",
        windows=(_win_roaming(r"Mullvad\MullvadBrowser"),),
        macos=(_mac("MullvadBrowser"),),
        linux=(_home(".mullvad/mullvadbrowser"),),
    ),
    BrowserSpec(
        "LibreWolf", Engine.GECKO, "Stable",
        windows=(_win_roaming("librewolf"),),
        macos=(_mac("librewolf"),),
        linux=(_home(".librewolf"),),
    ),
    BrowserSpec(
        "Waterfox", Engine.GECKO, "Stable",
        windows=(_win_roaming("Waterfox"),),
        macos=(_mac("Waterfox"),),
        linux=(_home(".waterfox"),),
    ),
    BrowserSpec(
        "Floorp", Engine.GECKO, "Stable",
        windows=(_win_roaming("Floorp"),),
        macos=(_mac("Floorp"),),
        linux=(_home(".floorp"),),
    ),
    BrowserSpec(
        "Zen Browser", Engine.GECKO, "Stable",
        windows=(_win_roaming("zen"),),
        macos=(_mac("zen"),),
        linux=(_home(".zen"),),
    ),
    BrowserSpec(
        "SeaMonkey", Engine.GECKO, "Stable",
        windows=(_win_roaming(r"Mozilla\SeaMonkey"),),
        macos=(_mac("SeaMonkey"),),
        linux=(_home(".mozilla/seamonkey"),),
    ),
    BrowserSpec(
        "Basilisk", Engine.GECKO, "Stable",
        windows=(_win_roaming(r"Moonchild Productions\Basilisk"),),
        macos=(_mac("Basilisk"),),
        linux=(_home(".moonchild productions/basilisk"),),
        verify_note="Pre-WebExtension add-on model — parse defensively, expect "
                    "confidence=partial (PLAN.md 5.2).",
    ),
    BrowserSpec(
        "Pale Moon", Engine.GECKO, "Stable",
        windows=(_win_roaming(r"Moonchild Productions\Pale Moon"),),
        macos=(_mac("Pale Moon"),),
        linux=(_home(".moonchild productions/pale moon"),),
        verify_note="Pre-WebExtension add-on model — parse defensively, expect "
                    "confidence=partial (PLAN.md 5.2).",
    ),
    BrowserSpec(
        "GNU IceCat", Engine.GECKO, "Stable",
        windows=(_win_roaming(r"Mozilla\IceCat"),),
        linux=(_home(".mozilla/icecat"),),
    ),
    BrowserSpec(
        "Comodo IceDragon", Engine.GECKO, "Stable",
        windows=(_win_roaming(r"Comodo\IceDragon"),),
    ),
)

ALL_BROWSERS: tuple[BrowserSpec, ...] = CHROMIUM_BROWSERS + GECKO_BROWSERS
