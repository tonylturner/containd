#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Receiver-verified exact ICS learner smoke in isolated AF_PACKET and NFQUEUE
# Compose stacks. Requires Docker Compose, jq, curl and Python 3.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STAMP=$(date -u +%Y%m%d-%H%M%S)-$$
RESULTS=${EXACT_LEARNER_RESULTS:-$ROOT/build/exact-learner-$STAMP}
FIREWALL_IMAGE=${EXACT_LEARNER_IMAGE:-containd/containd:exact-learner-$STAMP}
ENDPOINT_IMAGE=${EXACT_LEARNER_ENDPOINT_IMAGE:-containd-iec104-endpoint:exact-learner-$STAMP}
CAPTURE_IMAGE=${EXACT_LEARNER_CAPTURE_IMAGE:-containd-exact-learner-capture:$STAMP}
COMPOSE_FILE=$ROOT/test/exact-learner/compose.yml
JWT_SECRET=${EXACT_LEARNER_JWT_SECRET:-}
ADMIN_PASSWORD=${EXACT_LEARNER_ADMIN_PASSWORD:-ExactLearnerSmoke9A!}
AUTH_HEADER=""
PASS_COUNT=0

for tool in docker jq curl python3; do
	command -v "$tool" >/dev/null 2>&1 || {
		printf 'missing required tool: %s\n' "$tool" >&2
		exit 1
	}
done

if [[ -z $JWT_SECRET ]]; then
	JWT_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
fi
mkdir -p "$RESULTS"
printf '{"stamp":"%s","assertions":[]}\n' "$STAMP" >"$RESULTS/summary.json"
docker build -f "$ROOT/build/Dockerfile.mgmt" -t "$FIREWALL_IMAGE" "$ROOT" \
	>"$RESULTS/firewall-build.log" 2>&1 || {
	cat "$RESULTS/firewall-build.log" >&2
	printf 'FAIL: branch firewall image build failed; evidence: %s\n' "$RESULTS" >&2
	exit 1
}
docker build -t "$ENDPOINT_IMAGE" "$ROOT/test/iec104/endpoint" \
	>"$RESULTS/endpoint-build.log" 2>&1 || {
	cat "$RESULTS/endpoint-build.log" >&2
	printf 'FAIL: IEC 104 receiver/client image build failed; evidence: %s\n' "$RESULTS" >&2
	exit 1
}
docker build -f "$ROOT/test/exact-learner/capture.Dockerfile" -t "$CAPTURE_IMAGE" "$ROOT/test/exact-learner" \
	>"$RESULTS/capture-build.log" 2>&1 || {
	cat "$RESULTS/capture-build.log" >&2
	printf 'FAIL: tcpdump capture-helper image build failed; evidence: %s\n' "$RESULTS" >&2
	exit 1
}

# shellcheck source=scripts/smoke-exact-learner-lib.sh
source "$ROOT/scripts/smoke-exact-learner-lib.sh"

compose() {
	docker compose --project-name "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

append_result() {
	local assertion=$1 status=$2 detail=$3 tmp="$MODE_RESULTS/summary.tmp"
	jq --arg name "$assertion" --arg status "$status" --arg detail "$detail" \
		'.assertions += [{name:$name,status:$status,detail:$detail}]' \
		"$MODE_RESULTS/summary.json" >"$tmp"
	mv "$tmp" "$MODE_RESULTS/summary.json"
}

mode_cleanup() {
	local rc=$?
	trap - EXIT
	set +e
	if [[ ${STACK_UP:-0} == 1 ]]; then
		compose logs --no-color >"$MODE_RESULTS/compose.log" 2>&1
		compose down --volumes --remove-orphans --timeout 10 >"$MODE_RESULTS/compose-down.log" 2>&1
	fi
	exit "$rc"
}

exact_pass_record() {
	exact_pass "$1"
	PASS_COUNT=$((PASS_COUNT + 1))
	append_result "$1" PASS "${2:-}"
}

setup_routes() {
	compose exec -T modbus_client ip route flush table main >/dev/null
	compose exec -T modbus_client ip route add "$LAN_SUBNET.0/24" dev eth0 scope link src "$LAN_CLIENT_IP"
	compose exec -T modbus_client ip route add "$WAN_SUBNET.0/24" via "$LAN_SUBNET.2" dev eth0
	compose exec -T modbus_client ip route add default via "$LAN_SUBNET.2" dev eth0
	compose exec -T modbus_server ip route flush table main >/dev/null
	compose exec -T modbus_server ip route add "$WAN_SUBNET.0/24" dev eth0 scope link src "$MODBUS_SERVER_IP"
	compose exec -T modbus_server ip route add "$LAN_SUBNET.0/24" via "$WAN_SUBNET.2" dev eth0
	compose exec -T modbus_server ip route add default via "$WAN_SUBNET.2" dev eth0
}

api_save_and_commit() {
	local config_file=$1 label=$2
	exact_api_post /config/candidate "$config_file" "$MODE_RESULTS/$label-save.json" "$label candidate save"
	exact_write_json "$MODE_RESULTS/commit-request.json" <<<'{}'
	exact_api_post /config/commit "$MODE_RESULTS/commit-request.json" "$MODE_RESULTS/$label-commit.json" "$label commit"
}

api_wait_ready() {
	for _ in $(seq 1 90); do
		if curl -fsS --connect-timeout 2 --max-time 3 "${BASE}/health" \
			>"$MODE_RESULTS/health.json" 2>/dev/null; then
			return 0
		fi
		sleep 1
	done
	exact_fail "management did not become healthy within 90 seconds after container start/restart; compose=$(cat "$MODE_RESULTS/compose.log" 2>/dev/null || true)"
}

authenticate_admin() {
	local status
	cat >"$MODE_RESULTS/admin-login-request.json" <<'JSON'
{"username":"containd","password":"containd"}
JSON
	status=$(curl -sS --connect-timeout 5 --max-time 30 -H 'Content-Type: application/json' \
		-X POST --data-binary @"$MODE_RESULTS/admin-login-request.json" \
		-o "$MODE_RESULTS/admin-login-response.json" -w '%{http_code}' "${BASE}/auth/login" \
		2>"$MODE_RESULTS/admin-login-curl-error.log") || status=000
	[[ $status == 200 ]] ||
		exact_fail "default admin session login returned HTTP $status; response=$(cat "$MODE_RESULTS/admin-login-response.json" 2>/dev/null || true); curl=$(cat "$MODE_RESULTS/admin-login-curl-error.log" 2>/dev/null || true)"
	TOKEN=$(jq -r '.token // empty' "$MODE_RESULTS/admin-login-response.json")
	[[ -n $TOKEN ]] ||
		exact_fail "admin login returned no session JWT; response=$(cat "$MODE_RESULTS/admin-login-response.json")"
	AUTH_HEADER="Authorization: Bearer $TOKEN"
	cat >"$MODE_RESULTS/admin-password-request.json" <<JSON
{"currentPassword":"containd","newPassword":"$ADMIN_PASSWORD"}
JSON
	exact_api_post /auth/me/password "$MODE_RESULTS/admin-password-request.json" \
		"$MODE_RESULTS/admin-password-response.json" "initial admin password setup"
	exact_pass_record "$CAPTURE_MODE management API uses an authenticated admin session" \
		"role=$(jq -r '.user.role // .role' "$MODE_RESULTS/admin-login-response.json"); actor=containd"
}

wait_deadline() {
	local watch_id=$1 state
	for _ in $(seq 1 50); do
		exact_api_get "/learn/watches/$watch_id" "$MODE_RESULTS/deadline-watch-status.json" "deadline watch status"
		state=$(cat "$MODE_RESULTS/deadline-watch-status.json")
		if jq -e '.stopReason == "deadline" and .stoppedAt != null' <<<"$state" >/dev/null; then
			return 0
		fi
		sleep 0.25
	done
	exact_fail "short live watch did not stop on its deadline; status=$state"
}

verify_generated_sets() {
	local items=$1 label=$2
	jq -e 'any(.items[]; any(.content.rules[]; .ics.protocol == "modbus" and ((.ics.functionCode // []) | index(3) != null)))' \
		"$items" >/dev/null ||
		exact_fail "$label generation did not certify a Modbus FC3 read suggestion; response=$(cat "$items")"
	jq -e 'any(.items[]; any(.content.rules[]; .ics.protocol == "modbus" and ((.ics.functionCode // []) | index(5) != null)))' \
		"$items" >/dev/null ||
		exact_fail "$label generation did not certify a Modbus FC5 coil suggestion; response=$(cat "$items")"
	jq -e 'any(.items[]; any(.content.rules[]; .ics.protocol == "iec104" and ((.ics.typeIds // []) | index(46) != null)))' \
		"$items" >/dev/null ||
		exact_fail "$label generation did not certify the receiver-verified IEC 104 type-46 command; response=$(cat "$items")"
	jq -e 'all(.items[]; .status == "certified" or .status == "reviewed")' "$items" >/dev/null ||
		exact_fail "$label generation returned a suggestion without a passing certificate; response=$(cat "$items")"
}

capture_and_verify_pcap() {
	local bytes packet_lines container status exit_code
	compose exec -T capture kill -INT 1 >"$MODE_RESULTS/capture-stop.log" 2>&1 ||
		exact_fail "could not stop tcpdump with SIGINT; capture log=$(compose logs --no-color capture 2>&1)"
	container=$(compose ps --all --quiet capture)
	[[ -n $container ]] || exact_fail "Compose lost the tcpdump container before it could be checked"
	status=running
	for _ in $(seq 1 50); do
		status=$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null || true)
		[[ $status == exited ]] && break
		sleep 0.1
	done
	[[ $status == exited ]] ||
		exact_fail "tcpdump did not exit after SIGINT within five seconds; container status=$status"
	exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$container")
	[[ $exit_code == 0 ]] ||
		exact_fail "tcpdump exited $exit_code while finalizing the PCAP; logs=$(docker logs "$container" 2>&1)"
	docker logs "$container" >"$MODE_RESULTS/capture.log" 2>&1
	bytes=$(python3 -c 'import os,sys; print(os.path.getsize(sys.argv[1]) if os.path.exists(sys.argv[1]) else 0)' \
		"$MODE_RESULTS/live-traffic.pcap")
	[[ $bytes -gt 24 ]] ||
		exact_fail "tcpdump produced a header-only or missing capture ($bytes bytes); capture log=$(cat "$MODE_RESULTS/capture.log")"
	docker run --rm -v "$MODE_RESULTS:/evidence:ro" "$CAPTURE_IMAGE" -nn -r /evidence/live-traffic.pcap \
		>"$MODE_RESULTS/pcap-packets.txt" 2>"$MODE_RESULTS/pcap-read.log" ||
		exact_fail "tcpdump could not read the captured classic PCAP; log=$(cat "$MODE_RESULTS/pcap-read.log")"
	packet_lines=$(wc -l <"$MODE_RESULTS/pcap-packets.txt" | tr -d ' ')
	[[ $packet_lines -gt 0 ]] ||
		exact_fail "PCAP had no readable Ethernet packets despite size $bytes; decoder output=$(cat "$MODE_RESULTS/pcap-read.log")"
	exact_pass_record "$CAPTURE_MODE live traffic capture contains packets" "bytes=$bytes packets=$packet_lines"
}

run_mode() {
	CAPTURE_MODE=$1
	MODE_RESULTS="$RESULTS/$CAPTURE_MODE"
	PROJECT="exact-learner-$STAMP-$CAPTURE_MODE"
	STACK_UP=0
	trap mode_cleanup EXIT
	mkdir -p "$MODE_RESULTS/data" "$MODE_RESULTS/data/rtu-state"
	printf '{"mode":"%s","assertions":[]}\n' "$CAPTURE_MODE" >"$MODE_RESULTS/summary.json"

	if [[ $CAPTURE_MODE == afpacket ]]; then
		LAN_SUBNET=10.235.0
		WAN_SUBNET=10.236.0
	else
		LAN_SUBNET=10.237.0
		WAN_SUBNET=10.238.0
	fi
	LAN_CLIENT_IP=$LAN_SUBNET.3
	MODBUS_SERVER_IP=$WAN_SUBNET.3
	RTU_IP=$MODBUS_SERVER_IP
	# Compose resolves every service's interpolation even when capture is not
	# started yet. Replace this placeholder with the discovered WAN NIC below.
	export EXACT_CAPTURE_IFACE=eth1
	export EXACT_FIREWALL_IMAGE="$FIREWALL_IMAGE" EXACT_ENDPOINT_IMAGE="$ENDPOINT_IMAGE"
	export EXACT_CAPTURE_IMAGE="$CAPTURE_IMAGE" EXACT_DATA_DIR="$MODE_RESULTS/data"
	export EXACT_RESULTS_DIR="$MODE_RESULTS" EXACT_LAN_SUBNET="$LAN_SUBNET"
	export EXACT_WAN_SUBNET="$WAN_SUBNET" EXACT_JWT_SECRET="$JWT_SECRET"
	COMPOSE_PROJECT_NAME=$PROJECT
	export COMPOSE_PROJECT_NAME

	compose up -d --wait --wait-timeout 120 >"$MODE_RESULTS/compose-up.log" 2>&1 || {
		cat "$MODE_RESULTS/compose-up.log" >&2
		exact_fail "$CAPTURE_MODE Compose stack did not become healthy; startup log=$(cat "$MODE_RESULTS/compose-up.log")"
	}
	STACK_UP=1
	local port
	port=$(compose port firewall 18080 | awk -F: '{print $NF}')
	[[ -n $port ]] || exact_fail "$CAPTURE_MODE Compose did not publish a loopback management port"
	BASE="http://127.0.0.1:$port/api/v1"
	export BASE
	api_wait_ready
	authenticate_admin

	API_OUTPUT="$MODE_RESULTS/interfaces-state.json"
	exact_api_get /interfaces/state "$API_OUTPUT" "$CAPTURE_MODE interface discovery"
	WAN_IFACE=$(jq -r --arg ip "$WAN_SUBNET.2" 'map(select(.addrs[]? | contains($ip))) | .[0].name // empty' "$API_OUTPUT")
	LAN_IFACE=$(jq -r --arg ip "$LAN_SUBNET.2" 'map(select(.addrs[]? | contains($ip))) | .[0].name // empty' "$API_OUTPUT")
	[[ -n $WAN_IFACE && -n $LAN_IFACE ]] ||
		exact_fail "$CAPTURE_MODE interface state did not identify both isolated network interfaces; response=$(cat "$API_OUTPUT")"
	EXACT_CAPTURE_IFACE=$(compose exec -T firewall sh -c \
		"ip -o -4 addr show | awk '\$4 == \"$WAN_SUBNET.2/24\" {print \$2; exit}'" | tr -d '\r')
	[[ -n $EXACT_CAPTURE_IFACE ]] ||
		exact_fail "$CAPTURE_MODE could not find the server-side Ethernet capture interface for $WAN_SUBNET.2"
	export EXACT_CAPTURE_IFACE

	API_OUTPUT="$MODE_RESULTS/initial-running.json"
	exact_api_get /config "$API_OUTPUT" "$CAPTURE_MODE running configuration read"
	if [[ $CAPTURE_MODE == afpacket ]]; then
		jq --arg wan_dev "$WAN_IFACE" --arg lan_dev "$LAN_IFACE" --arg client "$LAN_CLIENT_IP" --arg server "$MODBUS_SERVER_IP" \
			--arg rtu "$RTU_IP" '
		.zones = [{name:"wan"},{name:"lan"}]
		| .interfaces = [{name:"wan",device:$wan_dev,zone:"wan"},{name:"lan",device:$lan_dev,zone:"lan"}]
		| .system.mgmt.httpListenAddr=":18080"
		| .system.mgmt.listenAddr=":18080"
		| .dataplane.enforcement=true
		| .dataplane.dpiEnabled=true
		| .dataplane.dpiMode="monitor"
		| .dataplane.dpiIcsProtocols={"modbus":true,"iec104":true}
		| .dataplane.captureInterfaces=[$wan_dev,$lan_dev]
		| del(.dataplane.nfqueueGroup)
		| .firewall.defaultAction="DENY"
		| .firewall.nat={enabled:false}
		| .firewall.rules=[
			{id:"exact-learner-l4-modbus",sourceZones:["lan"],destZones:["wan"],sources:[($client+"/32")],destinations:[($server+"/32")],protocols:[{name:"tcp",port:"502"}],action:"ALLOW"},
			{id:"exact-learner-l4-modbus-reply",sourceZones:["wan"],destZones:["lan"],sources:[($server+"/32")],destinations:[($client+"/32")],protocols:[{name:"tcp",port:"502"}],action:"ALLOW"},
			{id:"exact-learner-l4-iec104",sourceZones:["lan"],destZones:["wan"],sources:[($client+"/32")],destinations:[($rtu+"/32")],protocols:[{name:"tcp",port:"2404"}],action:"ALLOW"},
			{id:"exact-learner-l4-iec104-reply",sourceZones:["wan"],destZones:["lan"],sources:[($rtu+"/32")],destinations:[($client+"/32")],protocols:[{name:"tcp",port:"2404"}],action:"ALLOW"}
		]' "$MODE_RESULTS/initial-running.json" >"$MODE_RESULTS/baseline-candidate.json"
	else
		jq --arg wan_dev "$WAN_IFACE" --arg lan_dev "$LAN_IFACE" --arg client "$LAN_CLIENT_IP" --arg server "$MODBUS_SERVER_IP" \
			--arg rtu "$RTU_IP" '
		.zones = [{name:"wan"},{name:"lan"}]
		| .interfaces = [{name:"wan",device:$wan_dev,zone:"wan"},{name:"lan",device:$lan_dev,zone:"lan"}]
		| .system.mgmt.httpListenAddr=":18080"
		| .system.mgmt.listenAddr=":18080"
		| .dataplane.enforcement=true
		| .dataplane.dpiEnabled=true
		| .dataplane.dpiMode="enforce"
		| .dataplane.dpiIcsProtocols={"modbus":true,"iec104":true}
		| .dataplane.nfqueueGroup=101
		| del(.dataplane.captureInterfaces)
		| .firewall.defaultAction="DENY"
		| .firewall.nat={enabled:false}
		| .firewall.rules=[
			{id:"exact-learner-l4-modbus",sourceZones:["lan"],destZones:["wan"],sources:[($client+"/32")],destinations:[($server+"/32")],protocols:[{name:"tcp",port:"502"}],action:"ALLOW"},
			{id:"exact-learner-l4-modbus-reply",sourceZones:["wan"],destZones:["lan"],sources:[($server+"/32")],destinations:[($client+"/32")],protocols:[{name:"tcp",port:"502"}],action:"ALLOW"},
			{id:"exact-learner-l4-iec104",sourceZones:["lan"],destZones:["wan"],sources:[($client+"/32")],destinations:[($rtu+"/32")],protocols:[{name:"tcp",port:"2404"}],action:"ALLOW"},
			{id:"exact-learner-l4-iec104-reply",sourceZones:["wan"],destZones:["lan"],sources:[($rtu+"/32")],destinations:[($client+"/32")],protocols:[{name:"tcp",port:"2404"}],action:"ALLOW"},
			{id:"exact-learner-inspect-modbus",sourceZones:["lan"],destZones:["wan"],sources:[($client+"/32")],destinations:[($server+"/32")],protocols:[{name:"tcp",port:"502"}],ics:{protocol:"modbus",mode:"monitor"},action:"ALLOW"},
			{id:"exact-learner-inspect-iec104",sourceZones:["lan"],destZones:["wan"],sources:[($client+"/32")],destinations:[($rtu+"/32")],protocols:[{name:"tcp",port:"2404"}],ics:{protocol:"iec104",mode:"monitor"},action:"ALLOW"}
        ]' "$MODE_RESULTS/initial-running.json" >"$MODE_RESULTS/baseline-candidate.json"
	fi
	api_save_and_commit "$MODE_RESULTS/baseline-candidate.json" baseline
	cp "$MODE_RESULTS/baseline-candidate.json" "$MODE_RESULTS/baseline-expected.json"
	API_OUTPUT="$MODE_RESULTS/running-baseline.json"
	exact_api_get /config "$API_OUTPUT" "$CAPTURE_MODE baseline running configuration"
	jq -S '{zones,interfaces,dataplane,firewall}' "$API_OUTPUT" >"$MODE_RESULTS/baseline-running-policy.json"
	setup_routes
	exact_drive_modbus_read "$CAPTURE_MODE receiver/routing preflight" "$MODE_RESULTS/preflight-modbus.log"
	exact_pass_record "$CAPTURE_MODE real Modbus receiver responds through the configured firewall" "$(cat "$MODE_RESULTS/preflight-modbus.log")"

	exact_write_json "$MODE_RESULTS/deadline-watch-request.json" <<'JSON'
{"durationSeconds":2}
JSON
	exact_api_post /learn/watches "$MODE_RESULTS/deadline-watch-request.json" "$MODE_RESULTS/deadline-watch.json" \
		"$CAPTURE_MODE short-duration watch start"
	DEADLINE_WATCH_ID=$(jq -r '.id' "$MODE_RESULTS/deadline-watch.json")
	DEADLINE_DATASET_ID=$(jq -r '.datasetId' "$MODE_RESULTS/deadline-watch.json")
	[[ -n $DEADLINE_WATCH_ID && -n $DEADLINE_DATASET_ID ]] ||
		exact_fail "$CAPTURE_MODE watch start returned no watch or dataset identity; response=$(cat "$MODE_RESULTS/deadline-watch.json")"
	exact_drive_modbus_read "$CAPTURE_MODE deadline-watch FC3" "$MODE_RESULTS/deadline-modbus.log"
	wait_deadline "$DEADLINE_WATCH_ID"
	exact_pass_record "$CAPTURE_MODE watch stops with the deadline reason" "$(cat "$MODE_RESULTS/deadline-watch-status.json")"
	exact_write_json "$MODE_RESULTS/deadline-generate-request.json" <<JSON
{"datasetId":"$DEADLINE_DATASET_ID"}
JSON
	exact_api_post /learn/generate "$MODE_RESULTS/deadline-generate-request.json" "$MODE_RESULTS/deadline-generate.json" \
		"$CAPTURE_MODE deadline-stopped dataset generation"
	jq -e 'has("suggestions") and has("withheld")' "$MODE_RESULTS/deadline-generate.json" >/dev/null ||
		exact_fail "$CAPTURE_MODE deadline-stopped dataset returned no generation result; response=$(cat "$MODE_RESULTS/deadline-generate.json")"
	exact_pass_record "$CAPTURE_MODE deadline-stopped dataset remains generatable" "$(cat "$MODE_RESULTS/deadline-generate.json")"

	compose up -d capture >"$MODE_RESULTS/capture-start.log" 2>&1 ||
		exact_fail "$CAPTURE_MODE tcpdump sidecar did not start; output=$(cat "$MODE_RESULTS/capture-start.log")"
	sleep 1
	exact_api_get /health "$MODE_RESULTS/health-before-watch.json" "$CAPTURE_MODE pre-watch engine health"
	exact_write_json "$MODE_RESULTS/live-watch-request.json" <<'JSON'
{"durationSeconds":300}
JSON
	exact_api_post /learn/watches "$MODE_RESULTS/live-watch-request.json" "$MODE_RESULTS/live-watch.json" \
		"$CAPTURE_MODE live watch start"
	LIVE_WATCH_ID=$(jq -r '.id' "$MODE_RESULTS/live-watch.json")
	LIVE_DATASET_ID=$(jq -r '.datasetId' "$MODE_RESULTS/live-watch.json")
	[[ -n $LIVE_WATCH_ID && -n $LIVE_DATASET_ID ]] ||
		exact_fail "$CAPTURE_MODE live watch returned no watch or dataset identity; response=$(cat "$MODE_RESULTS/live-watch.json")"
	BEFORE_MODBUS=$(exact_modbus_state)
	BEFORE_RTU=$(exact_rtu_state)
	exact_drive_modbus_read "$CAPTURE_MODE live-watch Modbus FC3" "$MODE_RESULTS/live-fc3.log"
	exact_drive_coil 0 "$CAPTURE_MODE live-watch FC5 OFF" "$MODE_RESULTS/live-fc5-off.log"
	exact_drive_coil 65280 "$CAPTURE_MODE live-watch FC5 ON" "$MODE_RESULTS/live-fc5-on.log"
	for qualifier in $(seq 0 31); do
		for value in 1 2; do
			exact_drive_sbo "$value" "$qualifier" "$CAPTURE_MODE live-watch IEC104 SBO" \
				"$MODE_RESULTS/live-iec104-q${qualifier}-value${value}.log"
		done
	done
	AFTER_RTU=$(exact_rtu_state)
	[[ $(jq '.writes_applied' <<<"$AFTER_RTU") -ge $(($(jq '.writes_applied' <<<"$BEFORE_RTU") + 64)) ]] ||
		exact_fail "$CAPTURE_MODE IEC SBO matrix did not actuate all 64 value/qualifier combinations at the receiver; before=$BEFORE_RTU after=$AFTER_RTU"
	exact_pass_record "$CAPTURE_MODE live IEC receiver confirms the full Type-46 value/qualifier boundary" \
		"64 positive SBO operations; RTU before=$BEFORE_RTU after=$AFTER_RTU"
	sleep 1
	API_OUTPUT="$MODE_RESULTS/live-watch-before-stop.json"
	exact_api_get "/learn/watches/$LIVE_WATCH_ID" "$API_OUTPUT" "$CAPTURE_MODE live watch status before stop"
	jq -e '.stopReason == null and .stoppedAt == null' "$API_OUTPUT" >/dev/null ||
		exact_fail "$CAPTURE_MODE live watch ended before explicit stop; response=$(cat "$API_OUTPUT")"
	exact_api POST "/learn/watches/$LIVE_WATCH_ID/stop" "$MODE_RESULTS/live-watch-stopped.json"
	exact_api_expect 200 "$CAPTURE_MODE live watch stop and seal"
	jq -e '.stopReason == "operator" and .stoppedAt != null' "$MODE_RESULTS/live-watch-stopped.json" >/dev/null ||
		exact_fail "$CAPTURE_MODE explicit watch stop did not seal with operator reason; response=$(cat "$MODE_RESULTS/live-watch-stopped.json")"
	exact_pass_record "$CAPTURE_MODE live watch seals after real Modbus and IEC traffic" \
		"dataset=$LIVE_DATASET_ID; receiver=$(exact_modbus_state); RTU=$(exact_rtu_state)"
	capture_and_verify_pcap

	exact_write_json "$MODE_RESULTS/live-generate-request.json" <<JSON
{"datasetId":"$LIVE_DATASET_ID"}
JSON
	exact_api_post /learn/generate "$MODE_RESULTS/live-generate-request.json" "$MODE_RESULTS/live-generate.json" \
		"$CAPTURE_MODE live dataset generation"
	API_OUTPUT="$MODE_RESULTS/live-suggestions.json"
	exact_api_get "/learn/suggestions?datasetId=$LIVE_DATASET_ID" "$API_OUTPUT" "$CAPTURE_MODE live suggestion list"
	verify_generated_sets "$API_OUTPUT" "$CAPTURE_MODE live"
	cp "$API_OUTPUT" "$MODE_RESULTS/live-suggestions-original.json"
	jq -c '{suggestions,withheld}' "$MODE_RESULTS/live-generate.json" \
		>"$MODE_RESULTS/live-suggestions-and-withheld.json"
	printf '%s live suggestions/withheld exactly as backend reported: %s\n' "$CAPTURE_MODE" \
		"$(cat "$MODE_RESULTS/live-suggestions-and-withheld.json")"
	exact_pass_record "$CAPTURE_MODE generated backend suggestions and withheld reasons recorded verbatim" \
		"$(cat "$MODE_RESULTS/live-suggestions-and-withheld.json")"

	curl -sS --connect-timeout 5 --max-time 120 -H "$AUTH_HEADER" \
		-F "file=@$MODE_RESULTS/live-traffic.pcap;type=application/vnd.tcpdump.pcap" \
		-o "$MODE_RESULTS/pcap-import.json" -w '%{http_code}' "${BASE}/pcap/analyze" \
		>"$MODE_RESULTS/pcap-import-status.txt" 2>"$MODE_RESULTS/pcap-import-curl-error.log" ||
		exact_fail "$CAPTURE_MODE public PCAP upload failed at transport level; error=$(cat "$MODE_RESULTS/pcap-import-curl-error.log")"
	HTTP_CODE=$(cat "$MODE_RESULTS/pcap-import-status.txt")
	API_OUTPUT="$MODE_RESULTS/pcap-import.json"
	exact_api_expect 200 "$CAPTURE_MODE /pcap/analyze real-traffic upload"
	PCAP_DATASET_ID=$(jq -r '.dataset.id // empty' "$MODE_RESULTS/pcap-import.json")
	[[ -n $PCAP_DATASET_ID ]] ||
		exact_fail "$CAPTURE_MODE PCAP import did not return a sealed dataset identity; response=$(cat "$MODE_RESULTS/pcap-import.json")"
	exact_write_json "$MODE_RESULTS/pcap-generate-request.json" <<JSON
{"datasetId":"$PCAP_DATASET_ID"}
JSON
	exact_api_post /learn/generate "$MODE_RESULTS/pcap-generate-request.json" "$MODE_RESULTS/pcap-generate.json" \
		"$CAPTURE_MODE PCAP dataset generation"
	API_OUTPUT="$MODE_RESULTS/pcap-suggestions.json"
	exact_api_get "/learn/suggestions?datasetId=$PCAP_DATASET_ID" "$API_OUTPUT" "$CAPTURE_MODE PCAP suggestion list"
	verify_generated_sets "$API_OUTPUT" "$CAPTURE_MODE PCAP"
	jq -S '[.items[].content.rules[] | {action,sources,destinations,protocols,ics}] | sort_by(.ics.protocol, (.ics.functionCode|tostring), (.ics.typeIds|tostring), (.ics.addresses|tostring))' \
		"$MODE_RESULTS/live-suggestions.json" >"$MODE_RESULTS/live-rule-projection.json"
	jq -S '[.items[].content.rules[] | {action,sources,destinations,protocols,ics}] | sort_by(.ics.protocol, (.ics.functionCode|tostring), (.ics.typeIds|tostring), (.ics.addresses|tostring))' \
		"$MODE_RESULTS/pcap-suggestions.json" >"$MODE_RESULTS/pcap-rule-projection.json"
	cmp -s "$MODE_RESULTS/live-rule-projection.json" "$MODE_RESULTS/pcap-rule-projection.json" ||
		exact_fail "$CAPTURE_MODE PCAP and live certified rule projections differ beyond source/evidence metadata; live=$(cat "$MODE_RESULTS/live-rule-projection.json"); pcap=$(cat "$MODE_RESULTS/pcap-rule-projection.json")"
	exact_pass_record "$CAPTURE_MODE PCAP-import suggestions match live suggestions after omitting evidence authority metadata" \
		"$(cat "$MODE_RESULTS/live-rule-projection.json")"

	# First exercise the backend's hard IEC review gate through the public admin API.
	IEC_ID=$(jq -r '[.items[] | select(any(.content.rules[]; .ics.protocol == "iec104")) | .id] | first // empty' \
		"$MODE_RESULTS/live-suggestions.json")
	IEC_REVISION=$(jq -r --arg id "$IEC_ID" '.items[] | select(.id == $id) | .revision' "$MODE_RESULTS/live-suggestions.json")
	[[ -n $IEC_ID && -n $IEC_REVISION ]] ||
		exact_fail "$CAPTURE_MODE did not identify the generated IEC104 suggestion for the review gate"
	jq -n --arg id "$IEC_ID" --argjson revision "$IEC_REVISION" \
		'{requestId:"pre-review-probe",selections:[{id:$id,revision:$revision}]}' \
		>"$MODE_RESULTS/iec-pre-review-apply.json"
	exact_api POST /learn/apply "$MODE_RESULTS/iec-pre-review-response.json" "$MODE_RESULTS/iec-pre-review-apply.json"
	[[ $HTTP_CODE -ge 400 && $HTTP_CODE -lt 500 ]] ||
		exact_fail "$CAPTURE_MODE unreviewed IEC /learn/apply returned HTTP $HTTP_CODE instead of 4xx; response=$(cat "$MODE_RESULTS/iec-pre-review-response.json")"
	exact_pass_record "$CAPTURE_MODE IEC suggestion is rejected before authenticated review" \
		"HTTP=$HTTP_CODE response=$(cat "$MODE_RESULTS/iec-pre-review-response.json")"

	jq -r '.items[] | select((any(.content.rules[]; .ics.protocol == "iec104")) or .content.requiresCoordinateReview) | [.id,.revision] | @tsv' \
		"$MODE_RESULTS/live-suggestions.json" >"$MODE_RESULTS/review-selections.tsv"
	while IFS=$'\t' read -r suggestion_id revision; do
		[[ -n $suggestion_id ]] || continue
		jq -n --arg id "$suggestion_id" --argjson revision "$revision" \
			'{selection:{id:$id,revision:$revision},approve:true,coordinateApproved:true}' \
			>"$MODE_RESULTS/review-request-$suggestion_id.json"
		exact_api_post "/learn/suggestions/$suggestion_id/review" \
			"$MODE_RESULTS/review-request-$suggestion_id.json" \
			"$MODE_RESULTS/review-response-$suggestion_id.json" "$CAPTURE_MODE authenticated IEC/coordinate review"
		jq -e '.status == "reviewed" and .review.actor != ""' "$MODE_RESULTS/review-response-$suggestion_id.json" >/dev/null ||
			exact_fail "$CAPTURE_MODE suggestion review did not persist an authenticated reviewed state; response=$(cat "$MODE_RESULTS/review-response-$suggestion_id.json")"
	done <"$MODE_RESULTS/review-selections.tsv"
	API_OUTPUT="$MODE_RESULTS/live-suggestions-reviewed.json"
	exact_api_get "/learn/suggestions?datasetId=$LIVE_DATASET_ID" "$API_OUTPUT" "$CAPTURE_MODE reviewed live suggestions"
	jq -e --arg id "$IEC_ID" '.items[] | select(.id == $id) | .status == "reviewed" and .review.actor != ""' \
		"$API_OUTPUT" >/dev/null ||
		exact_fail "$CAPTURE_MODE IEC suggestion was not reviewed by the public API; response=$(cat "$API_OUTPUT")"

	# Empty the candidate rule list only; the currently running baseline remains
	# active while the selected certified rules are atomically staged.
	jq '.firewall.rules=[] | .firewall.defaultAction="ALLOW"' "$MODE_RESULTS/running-baseline.json" \
		>"$MODE_RESULTS/candidate-empty.json"
	exact_api_post /config/candidate "$MODE_RESULTS/candidate-empty.json" \
		"$MODE_RESULTS/candidate-empty-save.json" "$CAPTURE_MODE prepare an empty candidate rule list"
	API_OUTPUT="$MODE_RESULTS/running-before-stage.json"
	exact_api_get /config "$API_OUTPUT" "$CAPTURE_MODE running config before stage"
	jq -S '{zones,interfaces,dataplane,firewall}' "$API_OUTPUT" >"$MODE_RESULTS/running-policy-before-stage.json"
	cmp -s "$MODE_RESULTS/baseline-running-policy.json" "$MODE_RESULTS/running-policy-before-stage.json" ||
		exact_fail "$CAPTURE_MODE candidate preparation changed the running policy before suggestion staging"

	jq -n --arg request_id "exact-$STAMP-$CAPTURE_MODE" \
		--slurpfile items "$MODE_RESULTS/live-suggestions-reviewed.json" \
		'{requestId:$request_id,selections:[$items[0].items[] | {id,revision}]}' \
		>"$MODE_RESULTS/apply-request.json"
	jq -e '.selections | length > 0' "$MODE_RESULTS/apply-request.json" >/dev/null ||
		exact_fail "$CAPTURE_MODE apply request did not select any certified suggestions"
	exact_api_post /learn/apply "$MODE_RESULTS/apply-request.json" \
		"$MODE_RESULTS/apply-response.json" "$CAPTURE_MODE atomic selected-batch stage"
	jq -e '.staged == true and (.selections | length > 0)' "$MODE_RESULTS/apply-response.json" >/dev/null ||
		exact_fail "$CAPTURE_MODE /learn/apply did not return a successful staged receipt; response=$(cat "$MODE_RESULTS/apply-response.json")"
	exact_api_get /config/candidate "$MODE_RESULTS/candidate-staged.json" "$CAPTURE_MODE staged candidate"
	jq -S '[.items[].content.rules[]]' "$MODE_RESULTS/live-suggestions-reviewed.json" >"$MODE_RESULTS/expected-staged-rules.json"
	jq -S '[.firewall.rules[]]' "$MODE_RESULTS/candidate-staged.json" >"$MODE_RESULTS/actual-staged-rules.json"
	cmp -s "$MODE_RESULTS/expected-staged-rules.json" "$MODE_RESULTS/actual-staged-rules.json" ||
		exact_fail "$CAPTURE_MODE candidate does not contain exactly the selected suggestion rules; expected=$(cat "$MODE_RESULTS/expected-staged-rules.json"); actual=$(cat "$MODE_RESULTS/actual-staged-rules.json")"
	jq -e 'all(.firewall.rules[]; .ics.protocol != null and .ics.mode == "monitor")' \
		"$MODE_RESULTS/candidate-staged.json" >/dev/null ||
		exact_fail "$CAPTURE_MODE stage candidate contains a rule that is not explicitly ics.mode=monitor"
	API_OUTPUT="$MODE_RESULTS/running-after-stage.json"
	exact_api_get /config "$API_OUTPUT" "$CAPTURE_MODE running config after staging"
	jq -S '{zones,interfaces,dataplane,firewall}' "$API_OUTPUT" >"$MODE_RESULTS/running-policy-after-stage.json"
	cmp -s "$MODE_RESULTS/baseline-running-policy.json" "$MODE_RESULTS/running-policy-after-stage.json" ||
		exact_fail "$CAPTURE_MODE staging changed the active policy before commit"
	exact_pass_record "$CAPTURE_MODE selected batch is candidate-only and all staged rules are monitor rules" \
		"candidate rules=$(jq '.firewall.rules|length' "$MODE_RESULTS/candidate-staged.json"); running baseline unchanged"

	exact_api_post /learn/apply "$MODE_RESULTS/apply-request.json" \
		"$MODE_RESULTS/apply-retry-response.json" "$CAPTURE_MODE same-request retry"
	jq -S '[.firewall.rules[]]' "$MODE_RESULTS/candidate-staged.json" >"$MODE_RESULTS/candidate-rules-before-retry.json"
	exact_api_get /config/candidate "$MODE_RESULTS/candidate-after-retry.json" "$CAPTURE_MODE candidate after retry"
	jq -S '[.firewall.rules[]]' "$MODE_RESULTS/candidate-after-retry.json" >"$MODE_RESULTS/candidate-rules-after-retry.json"
	cmp -s "$MODE_RESULTS/candidate-rules-before-retry.json" "$MODE_RESULTS/candidate-rules-after-retry.json" ||
		exact_fail "$CAPTURE_MODE same request ID retry changed the candidate instead of converging as a no-op"
	exact_pass_record "$CAPTURE_MODE retrying the same request ID is an idempotent no-op" \
		"$(cat "$MODE_RESULTS/apply-retry-response.json")"

	exact_api_post /config/commit "$MODE_RESULTS/commit-request.json" \
		"$MODE_RESULTS/staged-rules-commit.json" "$CAPTURE_MODE commit staged monitor rules"
	API_OUTPUT="$MODE_RESULTS/running-monitor-rules.json"
	exact_api_get /config "$API_OUTPUT" "$CAPTURE_MODE running monitor rules"
	jq -S '[.firewall.rules[]]' "$API_OUTPUT" >"$MODE_RESULTS/running-monitor-rule-list.json"
	cmp -s "$MODE_RESULTS/expected-staged-rules.json" "$MODE_RESULTS/running-monitor-rule-list.json" ||
		exact_fail "$CAPTURE_MODE running policy after commit does not contain the selected staged rules exactly"
	jq -e '.firewall.rules | all(.[]; .ics.mode == "monitor")' "$API_OUTPUT" >/dev/null ||
		exact_fail "$CAPTURE_MODE committed learned rules were not all active in monitor mode"

	FC3_RULE_ID=$(jq -r '[.items[].content.rules[] | select(.ics.protocol == "modbus" and ((.ics.functionCode // []) | index(3) != null)) | .id] | first // empty' \
		"$MODE_RESULTS/live-suggestions-reviewed.json")
	FC5_RULE_ID=$(jq -r '[.items[].content.rules[] | select(.ics.protocol == "modbus" and ((.ics.functionCode // []) | index(5) != null)) | .id] | first // empty' \
		"$MODE_RESULTS/live-suggestions-reviewed.json")
	IEC_RULE_ID=$(jq -r '[.items[].content.rules[] | select(.ics.protocol == "iec104") | .id] | first // empty' \
		"$MODE_RESULTS/live-suggestions-reviewed.json")
	[[ -n $FC3_RULE_ID && -n $FC5_RULE_ID && -n $IEC_RULE_ID ]] ||
		exact_fail "$CAPTURE_MODE could not map the generated Modbus and IEC rules to receiver-verification counters"
	BEFORE_MODBUS=$(exact_modbus_state)
	BEFORE_RTU=$(exact_rtu_state)
	exact_drive_modbus_read "$CAPTURE_MODE committed monitor FC3" "$MODE_RESULTS/monitor-fc3.log"
	exact_drive_coil 0 "$CAPTURE_MODE committed monitor FC5 OFF" "$MODE_RESULTS/monitor-fc5-off.log"
	exact_drive_coil 65280 "$CAPTURE_MODE committed monitor FC5 ON" "$MODE_RESULTS/monitor-fc5-on.log"
	exact_drive_sbo 1 0 "$CAPTURE_MODE committed monitor IEC open SBO" "$MODE_RESULTS/monitor-iec-open.log"
	exact_drive_sbo 2 0 "$CAPTURE_MODE committed monitor IEC close SBO" "$MODE_RESULTS/monitor-iec-close.log"
	AFTER_MODBUS=$(exact_modbus_state)
	AFTER_RTU=$(exact_rtu_state)
	[[ $(jq '.coilWrites' <<<"$AFTER_MODBUS") -ge $(($(jq '.coilWrites' <<<"$BEFORE_MODBUS") + 2)) ]] ||
		exact_fail "$CAPTURE_MODE committed monitor rules did not deliver both legitimate FC5 values; before=$BEFORE_MODBUS after=$AFTER_MODBUS"
	[[ $(jq '.writes_applied' <<<"$AFTER_RTU") -ge $(($(jq '.writes_applied' <<<"$BEFORE_RTU") + 2)) ]] ||
		exact_fail "$CAPTURE_MODE committed monitor IEC rules did not deliver both select-before-operate commands; before=$BEFORE_RTU after=$AFTER_RTU"
	exact_wait_for_shadow "$FC3_RULE_ID" "$CAPTURE_MODE monitor Modbus FC3"
	exact_wait_for_shadow "$FC5_RULE_ID" "$CAPTURE_MODE monitor Modbus FC5"
	exact_wait_for_shadow "$IEC_RULE_ID" "$CAPTURE_MODE monitor IEC104 execute"
	cp "$MODE_RESULTS/shadow-counters.json" "$MODE_RESULTS/shadow-counters-after-monitor-traffic.json"
	exact_pass_record "$CAPTURE_MODE committed monitor rules delivered traffic to real receivers and shadow counters moved" \
		"Modbus before=$BEFORE_MODBUS after=$AFTER_MODBUS; RTU before=$BEFORE_RTU after=$AFTER_RTU"

	if [[ $CAPTURE_MODE == nfqueue ]]; then
		API_OUTPUT="$MODE_RESULTS/running-before-enforce-edit.json"
		exact_api_get /config "$API_OUTPUT" "$CAPTURE_MODE running config before normal FC5 candidate edit"
		jq --arg id "$FC5_RULE_ID" '
      .firewall.defaultAction="DENY"
      | .firewall.rules |= map(if .id == $id then .ics.mode="enforce" else . end)
      ' "$API_OUTPUT" >"$MODE_RESULTS/fc5-enforce-candidate.json"
		exact_api_post /config/candidate "$MODE_RESULTS/fc5-enforce-candidate.json" \
			"$MODE_RESULTS/fc5-enforce-candidate-save.json" "$CAPTURE_MODE normal FC5 ALLOW mode edit"
		API_OUTPUT="$MODE_RESULTS/running-before-fc5-commit.json"
		exact_api_get /config "$API_OUTPUT" "$CAPTURE_MODE running policy before FC5 mode commit"
		jq -e --arg id "$FC5_RULE_ID" '.firewall.rules[] | select(.id == $id) | .ics.mode == "monitor"' \
			"$API_OUTPUT" >/dev/null ||
			exact_fail "$CAPTURE_MODE normal candidate edit activated the FC5 enforce rule before commit"
		exact_api_post /config/commit "$MODE_RESULTS/commit-request.json" \
			"$MODE_RESULTS/fc5-enforce-commit.json" "$CAPTURE_MODE commit FC5 enforce candidate edit"
		API_OUTPUT="$MODE_RESULTS/running-after-fc5-commit.json"
		exact_api_get /config "$API_OUTPUT" "$CAPTURE_MODE active FC5 enforce rule"
		jq -e --arg id "$FC5_RULE_ID" '.firewall.rules[] | select(.id == $id) | .ics.mode == "enforce"' \
			"$API_OUTPUT" >/dev/null ||
			exact_fail "$CAPTURE_MODE committed candidate did not activate the selected FC5 ALLOW as enforce"
		BEFORE_MODBUS=$(exact_modbus_state)
		exact_drive_coil 0 "$CAPTURE_MODE enforced FC5 OFF" "$MODE_RESULTS/enforced-fc5-off.log"
		exact_drive_coil 65280 "$CAPTURE_MODE enforced FC5 ON" "$MODE_RESULTS/enforced-fc5-on.log"
		AFTER_MODBUS=$(exact_modbus_state)
		[[ $(jq '.coilWrites' <<<"$AFTER_MODBUS") -ge $(($(jq '.coilWrites' <<<"$BEFORE_MODBUS") + 2)) ]] ||
			exact_fail "$CAPTURE_MODE enforced FC5 ALLOW did not deliver legitimate 0/0xff00 writes; before=$BEFORE_MODBUS after=$AFTER_MODBUS"
		FC5_BEFORE=$(exact_count_modbus 5)
		WRITES_BEFORE=$(jq '.coilWrites' <<<"$(exact_modbus_state)")
		compose exec -T modbus_client python /opt/exact/modbus_client.py coil "$MODBUS_SERVER_IP" 502 --value 4660 \
			>"$MODE_RESULTS/enforced-fc5-reserved.log" 2>&1 && RESERVED_STATUS=0 || RESERVED_STATUS=$?
		sleep 0.5
		FC5_AFTER=$(exact_count_modbus 5)
		WRITES_AFTER=$(jq '.coilWrites' <<<"$(exact_modbus_state)")
		[[ $RESERVED_STATUS != 0 && $FC5_AFTER == "$FC5_BEFORE" && $WRITES_AFTER == "$WRITES_BEFORE" ]] ||
			exact_fail "$CAPTURE_MODE reserved FC5 0x1234 was not denied before the receiver; client=$RESERVED_STATUS FC5 requests=$FC5_BEFORE->$FC5_AFTER coilWrites=$WRITES_BEFORE->$WRITES_AFTER state=$(exact_modbus_state) clientOutput=$(cat "$MODE_RESULTS/enforced-fc5-reserved.log")"
		exact_pass_record "$CAPTURE_MODE enforced FC5 ALLOW admits only the legitimate closed-domain values at the receiver" \
			"0 and 0xff00 delivered; 0x1234 receiver request count unchanged at $FC5_AFTER"
	else
		cat >"$MODE_RESULTS/fc5-enforcement-capability.json" <<'JSON'
{"status":"not-applicable","reason":"AF_PACKET is passive and cannot reject packets; the receiver-side reserved FC5 assertion runs in the NFQUEUE stack."}
JSON
		printf 'INFO: AF_PACKET is passive; receiver-side rejection of FC5 0x1234 is verified in the isolated NFQUEUE run.\n'
	fi

	# Reboot the real all-mode container with its evidence database on the
	# isolated host data directory. The watch is intentionally left active.
	exact_write_json "$MODE_RESULTS/restart-watch-request.json" <<'JSON'
{"durationSeconds":300}
JSON
	exact_api_post /learn/watches "$MODE_RESULTS/restart-watch-request.json" \
		"$MODE_RESULTS/restart-watch.json" "$CAPTURE_MODE restart regression watch start"
	RESTART_WATCH_ID=$(jq -r '.id' "$MODE_RESULTS/restart-watch.json")
	[[ -n $RESTART_WATCH_ID ]] || exact_fail "$CAPTURE_MODE restart regression did not start an active watch"
	exact_api_get "/learn/watches/$RESTART_WATCH_ID" "$MODE_RESULTS/restart-watch-before.json" \
		"$CAPTURE_MODE active watch status before engine restart"
	jq -e '.stopReason == null and .stoppedAt == null' "$MODE_RESULTS/restart-watch-before.json" >/dev/null ||
		exact_fail "$CAPTURE_MODE restart regression watch was not active before restart"
	printf '%s\n' "$BASE" >"$MODE_RESULTS/management-url-before-restart.txt"
	compose restart firewall >"$MODE_RESULTS/restart.log" 2>&1 ||
		exact_fail "$CAPTURE_MODE firewall container restart failed; output=$(cat "$MODE_RESULTS/restart.log")"
	port=$(compose port firewall 18080 | awk -F: '{print $NF}')
	[[ -n $port ]] || exact_fail "$CAPTURE_MODE management port was not published after firewall restart"
	BASE="http://127.0.0.1:$port/api/v1"
	export BASE
	printf '%s\n' "$BASE" >"$MODE_RESULTS/management-url-after-restart.txt"
	api_wait_ready
	exact_api_get "/learn/watches/$RESTART_WATCH_ID" "$MODE_RESULTS/restart-watch-after.json" \
		"$CAPTURE_MODE watch status after engine restart"
	jq -e '.stopReason == "restart" and .stoppedAt != null' "$MODE_RESULTS/restart-watch-after.json" >/dev/null ||
		exact_fail "$CAPTURE_MODE engine restart did not stop the active watch with reason restart; response=$(cat "$MODE_RESULTS/restart-watch-after.json")"
	exact_api_get "/learn/datasets/$LIVE_DATASET_ID" "$MODE_RESULTS/live-dataset-after-restart.json" \
		"$CAPTURE_MODE main dataset after engine restart"
	exact_api_get "/learn/datasets/$DEADLINE_DATASET_ID" "$MODE_RESULTS/deadline-dataset-after-restart.json" \
		"$CAPTURE_MODE deadline dataset after engine restart"
	exact_api_get "/learn/suggestions/$IEC_ID" "$MODE_RESULTS/iec-suggestion-after-restart.json" \
		"$CAPTURE_MODE IEC suggestion after engine restart"
	jq -e --arg id "$LIVE_DATASET_ID" '.id == $id and .state == "sealed"' \
		"$MODE_RESULTS/live-dataset-after-restart.json" >/dev/null ||
		exact_fail "$CAPTURE_MODE live dataset did not survive restart as sealed evidence"
	jq -e --arg id "$DEADLINE_DATASET_ID" '.id == $id and .state == "sealed"' \
		"$MODE_RESULTS/deadline-dataset-after-restart.json" >/dev/null ||
		exact_fail "$CAPTURE_MODE deadline dataset did not survive restart as sealed evidence"
	jq -e --arg id "$IEC_ID" '.id == $id and (.status == "staged" or .status == "reviewed")' \
		"$MODE_RESULTS/iec-suggestion-after-restart.json" >/dev/null ||
		exact_fail "$CAPTURE_MODE certified/reviewed IEC suggestion did not survive restart; response=$(cat "$MODE_RESULTS/iec-suggestion-after-restart.json")"
	exact_pass_record "$CAPTURE_MODE datasets and suggestions survive restart and active watch stops as restart" \
		"watch=$(cat "$MODE_RESULTS/restart-watch-after.json"); dataset=$LIVE_DATASET_ID; suggestion=$IEC_ID"

	jq --argjson passed "$PASS_COUNT" '.summary = {passed:$passed,failed:0}' \
		"$MODE_RESULTS/summary.json" >"$MODE_RESULTS/summary.tmp"
	mv "$MODE_RESULTS/summary.tmp" "$MODE_RESULTS/summary.json"
	jq --arg mode "$CAPTURE_MODE" --slurpfile mode_result "$MODE_RESULTS/summary.json" \
		'.modes[$mode]=$mode_result[0]' "$RESULTS/summary.json" >"$RESULTS/summary.tmp"
	mv "$RESULTS/summary.tmp" "$RESULTS/summary.json"
	printf '%s mode smoke complete; evidence: %s\n' "$CAPTURE_MODE" "$MODE_RESULTS"
	trap - EXIT
	compose logs --no-color >"$MODE_RESULTS/compose.log" 2>&1
	compose down --volumes --remove-orphans --timeout 10 >"$MODE_RESULTS/compose-down.log" 2>&1
	STACK_UP=0
}

run_mode afpacket
# shellcheck disable=SC2317  # run_mode's EXIT trap is removed on a successful run.
run_mode nfqueue
printf 'Exact ICS learner smoke complete; %s assertions passed; evidence: %s\n' "$PASS_COUNT" "$RESULTS"
