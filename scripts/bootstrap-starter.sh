#!/usr/bin/env sh
set -eu

REPO_OWNER=${CONTAIND_REPO_OWNER:-tonylturner}
REPO_NAME=${CONTAIND_REPO_NAME:-containd}
REF=${CONTAIND_REF:-main}
TARGET_DIR=.
START=1
FORCE=0
IMAGE_OVERRIDE=
HTTP_PORT=
HTTPS_PORT=
SSH_PORT=
JWT_SECRET=
EXTRA_SET_ARGS=
ENV_SEEDED=0

usage() {
    cat <<'EOF'
Usage: sh bootstrap-starter.sh [options]

Prepare a starter containd lab directory, generate a JWT secret if needed,
and optionally start the stack.

Options:
  --dir DIR           Target directory (default: current directory)
  --ref REF           Git ref used when downloading starter files (default: main)
  --image IMAGE       Override CONTAIND_IMAGE in .env
  --http-port PORT    Override CONTAIND_PUBLISH_HTTP_PORT
  --https-port PORT   Override CONTAIND_PUBLISH_HTTPS_PORT
  --ssh-port PORT     Override CONTAIND_PUBLISH_SSH_PORT
  --jwt-secret VALUE  Use the provided JWT secret instead of generating one
  --set KEY=VALUE     Additional .env override (repeatable)
  --no-start          Prepare files but do not run docker compose up -d
  --force             Overwrite starter files even if they already exist
  --help              Show this help

Examples:
  sh bootstrap-starter.sh
  sh bootstrap-starter.sh --dir my-lab --no-start --set CONTAIND_LAN1_SUBNET=10.42.1.0/24
EOF
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

generate_secret() {
    if [ -n "${JWT_SECRET}" ]; then
        printf '%s\n' "$JWT_SECRET"
        return
    fi
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
        return
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
        return
    fi
    echo "unable to generate CONTAIND_JWT_SECRET automatically (need openssl or python3)" >&2
    exit 1
}

download_file() {
    src=$1
    dest=$2
    require_cmd curl
    curl -fsSL "$src" -o "$dest"
}

set_env_value() {
    file=$1
    key=$2
    value=$3
    tmp=$(mktemp "${TMPDIR:-/tmp}/containd-env.XXXXXX")
    awk -v key="$key" -v value="$value" '
        BEGIN { done = 0 }
        index($0, key "=") == 1 {
            print key "=" value
            done = 1
            next
        }
        { print }
        END {
            if (!done) {
                print key "=" value
            }
        }
    ' "$file" >"$tmp"
    mv "$tmp" "$file"
}

starter_topology_is_default() {
    file=$1
    [ "$(current_env_value "$file" "CONTAIND_WAN_SUBNET" || true)" = "192.168.240.0/24" ] &&
        [ "$(current_env_value "$file" "CONTAIND_DMZ_SUBNET" || true)" = "192.168.241.0/24" ] &&
        [ "$(current_env_value "$file" "CONTAIND_LAN1_SUBNET" || true)" = "192.168.242.0/24" ] &&
        [ "$(current_env_value "$file" "CONTAIND_LAN2_SUBNET" || true)" = "192.168.243.0/24" ] &&
        [ "$(current_env_value "$file" "CONTAIND_LAN3_SUBNET" || true)" = "192.168.244.0/24" ] &&
        [ "$(current_env_value "$file" "CONTAIND_LAN4_SUBNET" || true)" = "192.168.245.0/24" ] &&
        [ "$(current_env_value "$file" "CONTAIND_LAN5_SUBNET" || true)" = "192.168.246.0/24" ] &&
        [ "$(current_env_value "$file" "CONTAIND_LAN6_SUBNET" || true)" = "192.168.247.0/24" ]
}

docker_subnets() {
    ids=$(docker network ls -q 2>/dev/null || true)
    [ -n "$ids" ] || return 0
    # shellcheck disable=SC2086
    set -- $ids
    docker network inspect "$@" --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' 2>/dev/null | awk 'NF'
}

choose_starter_prefix() {
    existing=$1
    command -v python3 >/dev/null 2>&1 || return 1
    EXISTING_SUBNETS=$existing python3 - <<'PY'
import ipaddress
import os

existing = []
for line in os.environ.get("EXISTING_SUBNETS", "").splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        existing.append(ipaddress.ip_network(line, strict=False))
    except ValueError:
        pass

candidates = [
    ("192.168", 240),
    ("10.240", 240),
    ("10.241", 240),
    ("10.242", 240),
    ("10.243", 240),
    ("10.244", 240),
    ("172.30", 240),
    ("172.29", 240),
    ("172.28", 240),
]

for prefix, start in candidates:
    networks = [ipaddress.ip_network(f"{prefix}.{octet}.0/24") for octet in range(start, start + 8)]
    if any(any(net.overlaps(cur) for cur in existing) for net in networks):
        continue
    print(prefix)
    raise SystemExit(0)

raise SystemExit(1)
PY
}

apply_starter_topology_prefix() {
    file=$1
    prefix=$2
    octet=240
    for role in WAN DMZ LAN1 LAN2 LAN3 LAN4 LAN5 LAN6; do
        set_env_value "$file" "CONTAIND_${role}_SUBNET" "${prefix}.${octet}.0/24"
        set_env_value "$file" "CONTAIND_${role}_IP" "${prefix}.${octet}.2"
        set_env_value "$file" "CONTAIND_AUTO_${role}_SUBNET" "${prefix}.${octet}.0/24"
        octet=$((octet + 1))
    done
}

maybe_adjust_starter_topology() {
    file=$1
    [ "$ENV_SEEDED" -eq 1 ] || return 0
    starter_topology_is_default "$file" || return 0
    existing=$(docker_subnets || true)
    prefix=$(choose_starter_prefix "$existing" || true)
    [ -n "$prefix" ] || return 0
    [ "$prefix" = "192.168" ] && return 0
    apply_starter_topology_prefix "$file" "$prefix"
    echo "starter topology adjusted to ${prefix}.240.0/24-${prefix}.247.0/24 to avoid overlapping Docker networks." >&2
}

current_env_value() {
    file=$1
    key=$2
    awk -F= -v key="$key" '
        index($0, key "=") == 1 {
            print substr($0, length(key) + 2)
            exit
        }
    ' "$file"
}

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." 2>/dev/null && pwd || printf '')
use_local=0
if [ -n "$repo_root" ] && [ -f "$repo_root/deploy/docker-compose.yml" ] && [ -f "$repo_root/.env.example" ]; then
    use_local=1
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --dir)
            TARGET_DIR=$2
            shift 2
            ;;
        --ref)
            REF=$2
            shift 2
            ;;
        --image)
            IMAGE_OVERRIDE=$2
            shift 2
            ;;
        --http-port)
            HTTP_PORT=$2
            shift 2
            ;;
        --https-port)
            HTTPS_PORT=$2
            shift 2
            ;;
        --ssh-port)
            SSH_PORT=$2
            shift 2
            ;;
        --jwt-secret)
            JWT_SECRET=$2
            shift 2
            ;;
        --set)
            EXTRA_SET_ARGS="${EXTRA_SET_ARGS}
$2"
            shift 2
            ;;
        --no-start)
            START=0
            shift
            ;;
        --force)
            FORCE=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

require_cmd docker
if ! docker compose version >/dev/null 2>&1; then
    echo "docker compose is required" >&2
    exit 1
fi

mkdir -p "$TARGET_DIR"

compose_dest=$TARGET_DIR/docker-compose.yml
env_example_dest=$TARGET_DIR/.env.example
env_dest=$TARGET_DIR/.env

if [ "$use_local" -eq 1 ]; then
    compose_src=$repo_root/deploy/docker-compose.yml
    env_example_src=$repo_root/.env.example
    if [ "$FORCE" -eq 1 ] || [ ! -f "$compose_dest" ]; then
        cp "$compose_src" "$compose_dest"
    fi
    if [ "$FORCE" -eq 1 ] || [ ! -f "$env_example_dest" ]; then
        cp "$env_example_src" "$env_example_dest"
    fi
else
    compose_url="https://raw.githubusercontent.com/$REPO_OWNER/$REPO_NAME/$REF/deploy/docker-compose.yml"
    env_example_url="https://raw.githubusercontent.com/$REPO_OWNER/$REPO_NAME/$REF/.env.example"
    if [ "$FORCE" -eq 1 ] || [ ! -f "$compose_dest" ]; then
        download_file "$compose_url" "$compose_dest"
    fi
    if [ "$FORCE" -eq 1 ] || [ ! -f "$env_example_dest" ]; then
        download_file "$env_example_url" "$env_example_dest"
    fi
fi

if [ "$FORCE" -eq 1 ] || [ ! -f "$env_dest" ]; then
    cp "$env_example_dest" "$env_dest"
    ENV_SEEDED=1
fi

secret_value=$(current_env_value "$env_dest" "CONTAIND_JWT_SECRET" || true)
if [ -z "$secret_value" ] || [ "$secret_value" = "containd-dev-secret-change-me" ] || [ "$secret_value" = "REPLACE_WITH_RANDOM_32_PLUS_CHAR_SECRET" ]; then
    set_env_value "$env_dest" "CONTAIND_JWT_SECRET" "$(generate_secret)"
fi

maybe_adjust_starter_topology "$env_dest"

if [ -n "$IMAGE_OVERRIDE" ]; then
    set_env_value "$env_dest" "CONTAIND_IMAGE" "$IMAGE_OVERRIDE"
fi
if [ -n "$HTTP_PORT" ]; then
    set_env_value "$env_dest" "CONTAIND_PUBLISH_HTTP_PORT" "$HTTP_PORT"
fi
if [ -n "$HTTPS_PORT" ]; then
    set_env_value "$env_dest" "CONTAIND_PUBLISH_HTTPS_PORT" "$HTTPS_PORT"
fi
if [ -n "$SSH_PORT" ]; then
    set_env_value "$env_dest" "CONTAIND_PUBLISH_SSH_PORT" "$SSH_PORT"
fi

if [ -n "$EXTRA_SET_ARGS" ]; then
    printf '%s\n' "$EXTRA_SET_ARGS" | while IFS= read -r pair; do
        [ -n "$pair" ] || continue
        case "$pair" in
            *=*)
                set_env_value "$env_dest" "${pair%%=*}" "${pair#*=}"
                ;;
            *)
                echo "invalid --set value: $pair (expected KEY=VALUE)" >&2
                exit 2
                ;;
        esac
    done
fi

if uname -r 2>/dev/null | grep -qi 'microsoft'; then
    case $(pwd) in
        /mnt/*)
            echo "note: running from /mnt/* on WSL can be slow; a Linux-home directory is usually better for Docker workloads." >&2
            ;;
    esac
fi

if [ "$START" -eq 1 ]; then
    (
        cd "$TARGET_DIR"
        docker compose up -d
    )
fi

http_port=$(current_env_value "$env_dest" "CONTAIND_PUBLISH_HTTP_PORT" || true)
https_port=$(current_env_value "$env_dest" "CONTAIND_PUBLISH_HTTPS_PORT" || true)
ssh_port=$(current_env_value "$env_dest" "CONTAIND_PUBLISH_SSH_PORT" || true)
[ -n "$http_port" ] || http_port=8080
[ -n "$https_port" ] || https_port=8443
[ -n "$ssh_port" ] || ssh_port=2222

echo "starter directory: $TARGET_DIR"
echo "compose file: $compose_dest"
echo ".env file: $env_dest"
if [ "$START" -eq 1 ]; then
    echo "started containd starter compose"
fi
echo "web ui:  http://localhost:$http_port"
echo "https:   https://localhost:$https_port"
echo "ssh cli: ssh -p $ssh_port containd@localhost"
echo "login:   containd / containd"
echo "next:    bind interfaces to zones, create policy, then commit the candidate config"
