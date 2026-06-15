#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[info]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ok]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}  $*"; }
error() { echo -e "${RED}[error]${NC} $*"; }

echo ""
echo "  WebFilter Proxy — Installer"
echo "  ================================"
echo ""

# Check Python 3.10+
if ! command -v python3 &>/dev/null; then
    error "Python 3 not found. Install Python 3.10+ from https://python.org"
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [[ "$PY_MAJOR" -lt 3 || ( "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 10 ) ]]; then
    error "Python $PY_VERSION found, but 3.10+ is required."
    exit 1
fi
info "Python $PY_VERSION found"

# Create virtual environment
if [[ ! -d ".venv" ]]; then
    info "Creating virtual environment..."
    python3 -m venv .venv
    ok "Virtual environment created"
else
    info "Virtual environment already exists"
fi

# Install dependencies
info "Installing dependencies (this may take a few minutes)..."
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -r requirements.txt
ok "Dependencies installed"

# Create required directories
mkdir -p certs logs models
info "Directories created: certs/ logs/ models/"

# Generate mitmproxy CA certificate
info "Generating CA certificate..."
.venv/bin/mitmdump --set confdir=./certs -q --mode regular --listen-port 18080 &
MITM_PID=$!
sleep 3
kill "$MITM_PID" 2>/dev/null || true
wait "$MITM_PID" 2>/dev/null || true

# Find the generated cert
CERT_PEM=""
for name in mitmproxy-ca-cert.pem mitmproxy-ca.pem mitmproxy-ca-cert.cer; do
    if [[ -f "certs/$name" ]]; then
        CERT_PEM="certs/$name"
        break
    fi
done

if [[ -n "$CERT_PEM" ]]; then
    ok "CA certificate generated: $CERT_PEM"
else
    warn "CA certificate not found in certs/ — it will be generated on first proxy start"
fi

echo ""
echo "  ============================================"
echo "  Installation complete!"
echo ""
echo "  Next steps:"
echo "    1. Run:  ./start.sh"
echo "    2. Open: http://localhost:8000  (management UI)"
echo "    3. Configure browser proxy:  127.0.0.1:8080"
if [[ -n "$CERT_PEM" ]]; then
echo "    4. Install CA cert in your browser/OS:"
echo "       $SCRIPT_DIR/$CERT_PEM"
fi
echo "  ============================================"
echo ""
