# =============================================================
# FRAGMENT: scan_vector_db_ports.py.frag
# PROJECT: PatronAI
# VERSION: 1.0.0
# UPDATED: 2026-08-31
# OWNER: Giggso Inc (Ravi Venugopal)
# PURPOSE: Vector DB process/port detection (D2c1/D2c2) - additive to
#          scan_vector_dbs.py.frag's file-signature check, per team
#          decision (runs alongside it, does not replace it). Detects a
#          real listening port for known vector-DB defaults and
#          correlates against `docker ps` for container_id when
#          containerized. Real port bind (Chroma, :8901) and real
#          Docker lifecycle were both verified this session; the
#          `netstat -an` column layout for macOS/Linux below follows
#          long-standing, stable convention but was not live-verified
#          on those OSes this session (Windows' layout was).
# AUDIT LOG:
#   v1.0.0  2026-08-31  Initial.
# =============================================================

_VDB_PORTS = {8000: "chroma", 6333: "qdrant", 19530: "milvus", 8080: "weaviate"}


def _listening_ports() -> set:
    """OS-aware set of local TCP ports currently in LISTEN state. Local
    address is column 1 on Windows (no Recv-Q/Send-Q columns) vs column
    3 on macOS/Linux (standard netstat -an layout)."""
    try:
        out = subprocess.check_output(["netstat", "-an"], stderr=subprocess.DEVNULL, text=True, timeout=10)
    except Exception:
        return set()
    addr_col = 1 if OS_NAME == "windows" else 3
    ports: set = set()
    for line in out.splitlines():
        if "LISTEN" not in line.upper():
            continue
        parts = line.split()
        if len(parts) <= addr_col:
            continue
        addr = parts[addr_col]
        sep = ":" if ":" in addr else "."
        tail = addr.rsplit(sep, 1)[-1]
        if tail.isdigit():
            ports.add(int(tail))
    return ports


def _docker_containers() -> list:
    """Real running containers via `docker ps` - (container_id, image,
    ports_str). Returns [] if Docker isn't installed/running - never
    crashes the scan over an absent, optional dependency."""
    try:
        out = subprocess.check_output(
            ["docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Ports}}"],
            stderr=subprocess.DEVNULL, text=True, timeout=10,
        )
    except Exception:
        return []
    containers: list = []
    for line in out.splitlines():
        cols = line.split("\t")
        if len(cols) == 3:
            containers.append((cols[0], cols[1], cols[2]))
    return containers


def _container_for_port(port: int, containers: list):
    """Find a running container whose published ports include `port`."""
    needle = f":{port}->"
    for cid, image, ports_str in containers:
        if needle in ports_str:
            return cid, image
    return "", ""


def scan_vector_db_ports() -> list:
    """One finding per known vector-DB port actually LISTENING right now.
    Emits the same "vector_db" type as scan_vector_dbs.py.frag, tagged
    source="listening_port" to distinguish from the file-signature scan -
    both run and neither replaces the other."""
    listening = _listening_ports()
    if not listening:
        return []
    containers = _docker_containers()
    findings: list = []
    for port, kind in _VDB_PORTS.items():
        if port not in listening:
            continue
        container_id, image = _container_for_port(port, containers)
        findings.append({
            "type":             "vector_db",
            "kind":             kind,
            "source":           "listening_port",
            "listening_port":   port,
            "container_id":     container_id,
            "container_image":  image,
        })
    return findings
