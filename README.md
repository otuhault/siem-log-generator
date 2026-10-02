# SIEM Log Generator

Generates realistic security logs — firewalls, Windows, Linux, network devices,
cloud proxies — in the exact format each Splunk add-on expects, and ships them to
a file, to Splunk over HEC, or to a syslog collector such as SC4S. Use it to feed
a lab, exercise detections, or size an infrastructure.

It is a web application: once it is running, everything is configured from the
browser, and the **Read Me** tab inside the app explains how to use it.

> **Test data, not production data.** The logs are synthetic. They are modelled on
> each vendor's documented format and on its Splunk add-on, so they parse and map
> to CIM the way real events would — but they simulate behaviour for testing
> purposes and are not guaranteed to match what a given device, firmware version or
> configuration produces in production. Validate detections and sizing against real
> data before relying on them.

---

## Requirements

| | |
|---|---|
| **Python** | 3.9 or newer |
| **Git** | to clone the repository |
| **Node.js** | 22 or newer — *only* to run the browser-side test suite |

---

## Getting started on macOS

```bash
git clone https://github.com/otuhault/siem-log-generator.git
cd siem-log-generator
./start.sh
```

`start.sh` creates a virtual environment in `venv/` the first time, makes sure the
dependencies are installed, and starts the app. Use the same command every time.

Then open **http://127.0.0.1:5002**. Stop it with `Ctrl+C`, or `./stop.sh` from
another terminal.

### If port 5002 is taken

`start.sh` checks the port before the server starts, and names what holds it.
Serve somewhere else with `-p`:

```bash
./start.sh -p 5005      # and then ./stop.sh -p 5005
```

If it reports the port busy while nothing of yours is running, the holder
belongs to another account: `lsof` only lists your own processes. Look with
`sudo lsof -nP -iTCP:5002 -sTCP:LISTEN`, or just move to another port.

### Reaching it from another machine

The server answers only the machine it runs on. That is deliberate: it has no
authentication, and its API returns HEC tokens in clear text, so anything that
can reach the port can read them and drive the generator.

Open it when you mean to, and only on a network you trust:

```bash
./start.sh -H 0.0.0.0        # warns, and switches the debugger off
```

The interactive debugger is an arbitrary-code console; it stays available while
the server is local and is switched off as soon as it is not.

<details>
<summary>Doing it by hand instead</summary>

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
cd log-generator
python app.py
```

If `python3` is missing, install the Xcode command-line tools
(`xcode-select --install`) or Python from [python.org](https://www.python.org/downloads/).
</details>

---

## Getting started on Windows

Install Python from [python.org](https://www.python.org/downloads/) and tick
**Add python.exe to PATH** in the installer. Then, in **PowerShell**:

```powershell
git clone https://github.com/otuhault/siem-log-generator.git
cd siem-log-generator

py -3 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

cd log-generator
python app.py            # -p 5005 for another port, -H 0.0.0.0 to open it up
```

Then open **http://127.0.0.1:5002**. Stop it with `Ctrl+C`.

Next time, only the activation and the start are needed:

```powershell
cd siem-log-generator
.\venv\Scripts\Activate.ps1
cd log-generator
python app.py
```

A few things specific to Windows:

- **`Activate.ps1 cannot be loaded because running scripts is disabled`** — allow
  it for the current window only, then activate again:
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.
  From `cmd.exe` instead of PowerShell, activate with `venv\Scripts\activate.bat`.
- **A Windows Firewall prompt appears on first launch** — see
  [Network exposure](#network-exposure) below before choosing.
- **Local File destinations** take a Windows path, e.g. `C:\logs\firewall.log`.

---

## Running with Docker or Podman

The container runs the application without requiring Python on the host. Building
the image requires internet access to download the base image and Python
dependencies from PyPI.

### Docker Compose

Requires Docker Engine with the Compose plugin.

```bash
git clone https://github.com/otuhault/siem-log-generator.git
cd siem-log-generator
docker compose up --build -d
```

Then open **http://127.0.0.1:5002**. Follow the logs with
`docker compose logs -f`, and stop the app with `docker compose down`.

### Podman

The same `Dockerfile` and `compose.yaml` can be used with Podman. Podman requires
a Compose provider; these commands use the standalone `podman-compose` provider:

```bash
git clone https://github.com/otuhault/siem-log-generator.git
cd siem-log-generator
podman-compose up --build -d
```

Alternatively, `podman compose` delegates to an installed Compose provider. If
that provider is Docker Compose using Podman's rootless socket, enable the socket
and point Compose to it before starting the app:

```bash
systemctl --user enable --now podman.socket
export DOCKER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock"
podman compose up --build -d
```

The Compose healthcheck is defined in `compose.yaml` as well as the `Dockerfile`.
Podman defaults to OCI-format images, which do not preserve the Dockerfile
`HEALTHCHECK`; the Compose healthcheck provides container health reporting under
both Docker and Podman.

### State and updates

Senders, destinations, assets, identities, network pools and simulations are
kept in the `siem-log-generator-state` named volume. They survive container
recreation and image rebuilds. As with a local run, senders come back stopped
after an application restart.

To update the checked-out repository and rebuild:

```bash
git pull
docker compose up --build -d
```

With Podman, use the Compose command you started with:

```bash
git pull
podman-compose up --build -d
```

`docker compose down -v` or `podman-compose down -v` also deletes the state
volume, including saved configurations and HEC tokens.

`LOG_GENERATOR_PORT` changes the host-side port, not the port the app listens on
inside the container. For example:

```bash
LOG_GENERATOR_PORT=5005 docker compose up --build -d
```

Open **http://127.0.0.1:5005**.

### Writing to files

A file destination writes inside the container, so its output is not visible
from the host and is lost when the container is recreated. To keep it, mount a
host folder:

1. Create the folder next to `compose.yaml`: `mkdir output`. On Linux, also
   make it writable by the container user: `sudo chown 10001:10001 output`.
2. In `compose.yaml`, uncomment `- ./output:/output` under `volumes`.
3. Recreate the service, then use `/output/<name>.log` as the destination path
   in the app.

### Sending to another container or a service on this machine

Inside the container, `127.0.0.1` is the container itself — a destination set
to it receives nothing. To reach something running on the same machine, such as
an SC4S or Splunk container that publishes its port:

- **Docker Desktop (macOS, Windows):** use `host.docker.internal` as the
  destination host, with the port the other container publishes (514 for SC4S).
- **Docker on Linux:** same, after uncommenting the `extra_hosts` lines in
  `compose.yaml`.
- **Podman:** use `host.containers.internal`.

If both run under Compose, you can instead attach them to a shared Docker
network and use the other container's name as the destination host.

### Exposing the container on your network

The Compose configuration publishes the service on loopback only by default.
The application has no authentication, and its API returns stored HEC tokens.
To allow LAN access, replace the `ports` entry in `compose.yaml` with:

```yaml
    ports:
      - "${LOG_GENERATOR_PORT:-5002}:5002"
```

Recreate the service, then connect to the host's LAN IP and the selected host
port. Expose it only on a trusted network. Docker-published ports may bypass
some host firewall rules, so review the firewall behavior on your system before
enabling LAN access.

Flask's interactive debugger is off in the container. The image starts the app
with `flask run --no-debugger --no-reload` rather than `python app.py`, so the
arbitrary-code console is not exposed on the container's network interface.

---

## First steps in the app

1. **Configuration → HEC Destinations** (or **Syslog Destinations**): add where the
   logs should go, and use **Test Connection**.
2. **Senders → + Add Sender**: pick a technology, its sourcetypes, a frequency and
   that destination.
3. Start it with ▶ and search Splunk: `index=<your index> earliest=-15m latest=+1h`.

The **Catalog** tab lists every data source and attack available; the **Read Me**
tab covers the rest, including troubleshooting.

---

## Good to know

### Where your configuration lives

Everything created in the app — senders, destinations and their HEC tokens,
assets and identities, network pools, simulations — is saved as JSON files in
`log-generator/`, whichever directory the app is started from. They are
**deliberately not tracked by git**, so a fresh clone starts empty. To start over,
stop the app and delete `log-generator/*.json`.

### Updating

```bash
git pull
python -m pip install -r requirements.txt   # with the virtual environment active
```

Then restart the app, reload the page with a hard refresh (`⇧⌘R` on macOS,
`Ctrl+F5` on Windows) and start your senders again: they do not restart on their
own when the app does.

### Network exposure

The app runs Flask's development server in debug mode and listens on **all network
interfaces**, so other machines on your network can reach port 5002. Use it on a
trusted network only. On Windows, denying the firewall prompt keeps it reachable
from your own machine at `127.0.0.1` while blocking everyone else.

---

## Running the tests

```bash
python -m pip install -r requirements-dev.txt   # once, virtual environment active
python -m pytest                                # Python suite, from the repository root

npm install                                     # once — browser-side suite, Node 22+
npm test
```

Some Python tests check the generated events against the real Splunk add-ons.
The add-ons are not distributed with this repository, so those tests are skipped
on a fresh clone; to run them, extract the add-ons from Splunkbase into `TAs/`
(for instance `TAs/Splunk_TA_nix/`).

---

## Repository layout

| Path | What it holds |
|---|---|
| `log-generator/` | The application: Flask server (`app.py`), generators, senders, web UI |
| `log-generator/ta_registry.py` | Single source of truth for every sourcetype, source and datamodel |
| `references/` | How each data source was researched, and the checklist for adding one |
| `tests/`, `tests-js/` | Python and browser-side test suites |
| `start.sh`, `stop.sh` | macOS / Linux launch helpers — `-p PORT`, `-H HOST` |
| `Dockerfile`, `compose.yaml` | Container image and Compose setup - see *Running with Docker or Podman* |

---

## License

**Free for noncommercial use.** You may download, run and adapt the generator for
personal learning, a home lab, teaching, research or evaluation.

Redistributing it — modified or not — and any commercial use, including use within
a company or during paid work such as a consulting engagement, require written
permission from the author.

The software is provided as is, without warranty. See [LICENSE](LICENSE) for the
full terms.
