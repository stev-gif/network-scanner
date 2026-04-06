#!/usr/bin/env bash
# =============================================================================
# network_scanner.sh — Local Network Port & Host Scanner
# Author  : Alex Johnson
# GitHub  : github.com/alexjohnson
# Version : 1.0.0
#
# Description:
#   Scans a local network range to discover:
#     - Active/live hosts (ping sweep)
#     - Open TCP ports on each host
#     - Service names and version banners on open ports
#
# Requirements:
#   - nmap  (install: sudo apt install nmap  |  brew install nmap)
#   - Run as root/sudo for OS detection and version scanning
#
# Usage:
#   chmod +x network_scanner.sh
#   sudo ./network_scanner.sh [OPTIONS]
#
# Examples:
#   sudo ./network_scanner.sh                         # Auto-detect network
#   sudo ./network_scanner.sh -t 192.168.1.0/24       # Scan a specific range
#   sudo ./network_scanner.sh -t 192.168.1.1-50        # Scan a host range
#   sudo ./network_scanner.sh -t 192.168.1.0/24 -o    # Save results to file
#   sudo ./network_scanner.sh -t 192.168.1.0/24 -p "22,80,443,8080"
# =============================================================================

set -euo pipefail

# ─── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Defaults ─────────────────────────────────────────────────────────────────
TARGET=""
PORTS="1-1024"          # Default: well-known ports
OUTPUT=false
OUTPUT_FILE="scan_results_$(date +%Y%m%d_%H%M%S).txt"
VERBOSE=false
TIMING=3                # nmap timing template (0=slowest, 5=fastest)

# ─── Usage ────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${BOLD}Usage:${RESET} sudo $0 [OPTIONS]"
    echo ""
    echo -e "${BOLD}Options:${RESET}"
    echo "  -t <target>    Target IP, range, or CIDR (e.g. 192.168.1.0/24)"
    echo "  -p <ports>     Port range or list  (default: 1-1024)"
    echo "                 Examples: '22,80,443'  '1-65535'  '80,8000-8100'"
    echo "  -o             Save results to a timestamped .txt file"
    echo "  -T <0-5>       nmap timing template (default: 3)"
    echo "  -v             Verbose output"
    echo "  -h             Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${RESET}"
    echo "  sudo $0 -t 192.168.1.0/24"
    echo "  sudo $0 -t 192.168.0.0/16 -p 22,80,443,3306,8080 -o"
    exit 0
}

# ─── Parse arguments ──────────────────────────────────────────────────────────
while getopts ":t:p:T:ovh" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        p) PORTS="$OPTARG" ;;
        T) TIMING="$OPTARG" ;;
        o) OUTPUT=true ;;
        v) VERBOSE=true ;;
        h) usage ;;
        :) echo -e "${RED}[!] Option -$OPTARG requires an argument.${RESET}" >&2; exit 1 ;;
        \?) echo -e "${RED}[!] Unknown option: -$OPTARG${RESET}" >&2; exit 1 ;;
    esac
done

# ─── Banner ───────────────────────────────────────────────────────────────────
print_banner() {
    echo -e "${CYAN}"
    echo "  ███╗   ██╗███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗"
    echo "  ████╗  ██║██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║"
    echo "  ██╔██╗ ██║█████╗     ██║       ███████╗██║     ███████║██╔██╗ ██║"
    echo "  ██║╚██╗██║██╔══╝     ██║       ╚════██║██║     ██╔══██║██║╚██╗██║"
    echo "  ██║ ╚████║███████╗   ██║       ███████║╚██████╗██║  ██║██║ ╚████║"
    echo "  ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
    echo -e "${RESET}"
    echo -e "  ${BOLD}Local Network Port & Host Scanner${RESET}  |  v1.0.0"
    echo -e "  ${BLUE}For educational and authorised use only${RESET}"
    echo ""
}

# ─── Helpers ──────────────────────────────────────────────────────────────────
log()     { echo -e "${GREEN}[+]${RESET} $*"; }
info()    { echo -e "${BLUE}[*]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*" >&2; }
section() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}${CYAN}  $*${RESET}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"; }

# ─── Dependency check ─────────────────────────────────────────────────────────
check_dependencies() {
    local missing=()
    for cmd in nmap ip awk grep; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing[*]}"
        echo "  Install nmap with:"
        echo "    sudo apt install nmap     (Debian/Ubuntu/Kali)"
        echo "    brew install nmap         (macOS)"
        echo "    sudo dnf install nmap     (Fedora/RHEL)"
        exit 1
    fi
}

# ─── Root check ───────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        warn "Not running as root. Version/OS detection may be limited."
        warn "Re-run with: ${BOLD}sudo $0 $*${RESET}"
        echo ""
    fi
}

# ─── Auto-detect local network range ─────────────────────────────────────────
auto_detect_network() {
    info "Auto-detecting local network range..."

    # Try ip route first (Linux), fall back to ifconfig (macOS)
    local gateway cidr iface

    if command -v ip &>/dev/null; then
        # Get default route interface
        iface=$(ip route | awk '/^default/ {print $5; exit}')
        # Get CIDR for that interface
        cidr=$(ip -o -f inet addr show "$iface" 2>/dev/null | \
               awk '{print $4}' | head -1)
    elif command -v ifconfig &>/dev/null; then
        # macOS fallback
        iface=$(route -n get default 2>/dev/null | awk '/interface/ {print $2}')
        local ip mask
        ip=$(ifconfig "$iface" 2>/dev/null | awk '/inet / {print $2}')
        mask=$(ifconfig "$iface" 2>/dev/null | awk '/inet / {print $4}')
        cidr="$ip/$mask"
    fi

    if [[ -z "${cidr:-}" ]]; then
        error "Could not auto-detect network. Please specify with -t <CIDR>"
        exit 1
    fi

    # Convert to network address using nmap's --iflist or simple math
    # Use nmap to validate and normalise the CIDR
    TARGET=$(nmap -sL "$cidr" 2>/dev/null | awk '/Nmap scan report for/ {print $NF}' | \
             head -1 | sed 's/[0-9]*$/0/')
    TARGET="${TARGET}/24"

    log "Detected network: ${BOLD}$TARGET${RESET} (interface: $iface)"
}

# ─── Phase 1: Host discovery (ping sweep) ────────────────────────────────────
discover_hosts() {
    section "Phase 1 — Host Discovery"
    info "Performing ping sweep on: ${BOLD}$TARGET${RESET}"
    info "This finds which hosts are online (no port scanning yet)..."
    echo ""

    # -sn  = ping scan (no port scan)
    # -T$TIMING = timing template
    # --open = only show hosts that respond
    LIVE_HOSTS=$(nmap -sn -T"$TIMING" "$TARGET" 2>/dev/null | \
                 awk '/Nmap scan report for/{
                     # Extract hostname and IP
                     if (match($0, /\(([0-9.]+)\)/, arr)) {
                         print arr[1]   # Has hostname: grab IP in parens
                     } else {
                         print $NF      # IP only
                     }
                 }')

    HOST_COUNT=$(echo "$LIVE_HOSTS" | grep -c '[0-9]' || true)

    if [[ $HOST_COUNT -eq 0 ]]; then
        warn "No live hosts found on $TARGET"
        warn "Try: ping $TARGET manually, or check your network range"
        exit 0
    fi

    log "Found ${BOLD}$HOST_COUNT${RESET} live host(s):"
    echo ""
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        # Attempt reverse DNS lookup
        hostname=$(nmap -sn "$host" 2>/dev/null | awk '/Nmap scan report for/{
            if (match($0, /for (.+) \(/, arr)) print arr[1]; else print "N/A"
        }')
        printf "  ${GREEN}●${RESET} %-18s  %s\n" "$host" "$hostname"
    done <<< "$LIVE_HOSTS"
    echo ""
}

# ─── Phase 2: Port & version scan on each live host ──────────────────────────
scan_ports() {
    section "Phase 2 — Port & Version Scan"
    info "Scanning ports: ${BOLD}$PORTS${RESET}"
    info "Detecting service names and version banners..."
    echo ""

    local scan_count=0

    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        (( scan_count++ ))

        echo -e "${BOLD}${BLUE}[$scan_count/$HOST_COUNT] Scanning: $host${RESET}"
        echo -e "  ${YELLOW}──────────────────────────────────────────────────────${RESET}"

        # Build nmap command:
        #   -sV         = service/version detection
        #   -sS or -sT  = SYN stealth scan (root) or TCP connect (non-root)
        #   -O          = OS detection (requires root)
        #   -p          = port range
        #   --open      = only show open ports
        #   -T          = timing
        #   --version-intensity 5 = moderate version probe depth

        local nmap_flags="-sV --version-intensity 5 -p $PORTS --open -T$TIMING"

        if [[ $EUID -eq 0 ]]; then
            nmap_flags="$nmap_flags -sS -O"  # SYN scan + OS detection (root)
        else
            nmap_flags="$nmap_flags -sT"     # TCP connect scan (non-root)
        fi

        # Run the scan and capture output
        local result
        result=$(nmap $nmap_flags "$host" 2>/dev/null)

        # ── OS Detection ──────────────────────────────────────────────────────
        local os_info
        os_info=$(echo "$result" | awk '/OS details:|Running:/{
            sub(/OS details: /,""); sub(/Running: /,"OS: "); print; exit
        }')
        if [[ -n "$os_info" ]]; then
            echo -e "  ${CYAN}OS${RESET}  : $os_info"
        fi

        # ── MAC address ───────────────────────────────────────────────────────
        local mac
        mac=$(echo "$result" | awk '/MAC Address/{print $3, $4, $5, $6}')
        if [[ -n "$mac" ]]; then
            echo -e "  ${CYAN}MAC${RESET} : $mac"
        fi

        echo ""

        # ── Open ports table ──────────────────────────────────────────────────
        local open_ports
        open_ports=$(echo "$result" | awk '
            /^[0-9]+\/(tcp|udp)/ && /open/ {
                port    = $1
                state   = $2
                service = $3
                # Version info is everything from field 4 onward
                version = ""
                for (i=4; i<=NF; i++) version = version $i " "
                sub(/ +$/, "", version)
                printf "  %-20s %-10s %-18s %s\n", port, state, service, version
            }
        ')

        if [[ -n "$open_ports" ]]; then
            printf "  ${BOLD}%-20s %-10s %-18s %s${RESET}\n" \
                   "PORT" "STATE" "SERVICE" "VERSION"
            printf "  ${YELLOW}%-20s %-10s %-18s %s${RESET}\n" \
                   "────────────────────" "──────────" "──────────────────" "───────────────────────"
            echo "$open_ports"
        else
            warn "No open ports found on $host in range: $PORTS"
        fi

        echo ""

        # ── Verbose: raw nmap output ──────────────────────────────────────────
        if [[ "$VERBOSE" == true ]]; then
            echo -e "  ${BLUE}── Raw nmap output ──${RESET}"
            echo "$result" | sed 's/^/  /'
            echo ""
        fi

        # ── Append to output file if -o flag set ─────────────────────────────
        if [[ "$OUTPUT" == true ]]; then
            {
                echo "=== Host: $host ==="
                echo "$result"
                echo ""
            } >> "$OUTPUT_FILE"
        fi

    done <<< "$LIVE_HOSTS"
}

# ─── Phase 3: Summary ─────────────────────────────────────────────────────────
print_summary() {
    section "Scan Complete"
    log "Target range  : $TARGET"
    log "Ports scanned : $PORTS"
    log "Live hosts    : $HOST_COUNT"
    log "Scan finished : $(date '+%Y-%m-%d %H:%M:%S')"

    if [[ "$OUTPUT" == true ]]; then
        log "Results saved : ${BOLD}$OUTPUT_FILE${RESET}"
    fi

    echo ""
    echo -e "${YELLOW}  ⚠  Only scan networks you own or have explicit permission to test.${RESET}"
    echo ""
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    print_banner
    check_root "$@"
    check_dependencies

    # Auto-detect network if no target specified
    if [[ -z "$TARGET" ]]; then
        auto_detect_network
    fi

    # Initialise output file header
    if [[ "$OUTPUT" == true ]]; then
        {
            echo "============================================"
            echo "  Network Scan Report"
            echo "  Date   : $(date '+%Y-%m-%d %H:%M:%S')"
            echo "  Target : $TARGET"
            echo "  Ports  : $PORTS"
            echo "============================================"
            echo ""
        } > "$OUTPUT_FILE"
    fi

    discover_hosts
    scan_ports
    print_summary
}

main "$@"
