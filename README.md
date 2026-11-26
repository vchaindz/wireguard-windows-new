# An unofficial client for [WireGuard](https://www.wireguard.com/) on Windows

This is a modified version of [WireGuard for Windows](https://git.zx2c4.com/wireguard-windows/about/), the official client. It keeps the official tunnel implementation, [WireGuardNT](https://git.zx2c4.com/wireguard-nt/about/), and changes the application around it: what you see, what it tells you about a connection, and what happens when a peer does not answer.

**This project is not affiliated with, endorsed by, or supported by the WireGuard project.** "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld. If you simply want WireGuard on Windows, use [the official client](https://www.wireguard.com/install/). Please do not report problems with this version to the WireGuard project.

## What is different

**A status-first window and tray popup.** The tabbed window and the tray menu are replaced by one screen that leads with the state of your connection and a single switch, with details one step away. It is fully usable by keyboard, and follows the light, dark and high-contrast settings of Windows.

**It tells you whether a tunnel actually works.** An active tunnel in the official client only means that it is configured. This version checks for a live session and says so plainly: connected, peer does not answer, connection unstable, or key used on another device.

**Routes are applied only once a peer answers.** Activating a tunnel whose peer is gone no longer takes the machine off the network. The adapter comes up, a handshake is started, and routes, DNS and firewall rules follow when the peer has answered. See [`netquirk.md`](docs/netquirk.md) for what this means for the kill-switch.

**A listen port that gets no replies is replaced.** If a configuration sets `ListenPort` and nothing comes back on it, typically because the router uses the same port, the tunnel tries a random port after 15 seconds and names the port that did not work.

**Connection insights.**

- Traffic and latency charts over the last minute, hour and day
- Optional measurement of latency, jitter and loss through the tunnel
- A history of sessions and daily usage per tunnel, with CSV export
- The path a tunnel takes: endpoint, the network adapter that carries it, and MTU warnings
- A timeline of state changes, handshakes and reconnects
- "Test this tunnel": five checks with results in plain language
- A diagnostics file for support, with keys left out and addresses hidden unless you choose to include them

**A more readable log**, with severity levels, tunnel tags and filters.

Administrators can switch off the new behaviors by policy; the keys are listed in [`adminregistry.md`](docs/adminregistry.md).

## Status

This is a personal project in active development. Know this before you use it:

- **Releases are test builds.** The [releases page](https://github.com/vchaindz/wireguard-windows-new/releases) has an installer for x64. You can also build it yourself; see below.
- **Builds are not signed**, so Windows warns when you install or run one. The kernel driver inside is the official, Microsoft-signed WireGuardNT.
- **There are no automatic updates.** The updater only accepts official builds and is switched off in all others.
- **It has been tested on few machines**, on x64. The x86 and ARM64 builds compile but have not been run.
- **The new texts are in English only**, whatever language the rest of the application uses.
- It installs to the same place and uses the same service names as the official client, so the two cannot be installed side by side.

## Building

On Windows, run `build.bat` in the root of the repository. It downloads and verifies its own toolchain and produces `wireguard.exe` and `wg.exe` in `amd64\`, `x86\` and `arm64\`. [`buildrun.md`](docs/buildrun.md) has the details, including how to build the installer.

## Documentation

- [`adminregistry.md`](docs/adminregistry.md) &ndash; Registry keys settable by the system administrator for changing the behavior of the application.
- [`attacksurface.md`](docs/attacksurface.md) &ndash; The components from a security perspective, including what this version adds to the manager service.
- [`buildrun.md`](docs/buildrun.md) &ndash; Building, localizing, running, and developing for this repository.
- [`enterprise.md`](docs/enterprise.md) &ndash; Features and tips for making the application usable in enterprise settings.
- [`netquirk.md`](docs/netquirk.md) &ndash; Networking quirks, "kill-switch" semantics, waiting for a peer before routing, and connection quality and history.
- [`roadmap-insights.md`](docs/roadmap-insights.md) &ndash; The plan behind the insights features, and what is still open.

## License

This repository is MIT-licensed, like the official client it is based on. The changes made here are published under the same license.

```text
Copyright (C) 2018-2026 WireGuard LLC. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```
