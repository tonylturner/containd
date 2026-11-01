#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Shared assertions and public management API helpers for smoke-exact-learner.sh.
# shellcheck source=scripts/config-revision.sh
source "$(dirname "${BASH_SOURCE[0]}")/config-revision.sh"

exact_fail() {
	printf 'FAIL: %s; evidence: %s\n' "$*" "$MODE_RESULTS" >&2
	exit 1
}

exact_pass() {
	printf 'PASS: %s\n' "$*"
}

exact_api() {
	local method=$1 path=$2 output=$3 body=${4:-}
	local -a args
	args=(-sS --connect-timeout 5 --max-time 30 -H "$AUTH_HEADER" -o "$output" -w '%{http_code}')
	if [[ $method == GET || $method == DELETE ]]; then
		args+=(-X "$method")
	else
		args+=(-X "$method" -H 'Content-Type: application/json')
		[[ -z $body ]] || args+=(--data-binary "@$body")
	fi
	local -a request=(curl)
	if [[ $method == GET && ( $path == /config || $path == /config/candidate ) ]]; then
		request=(cas_read "$output.revision" curl)
	elif [[ $method == POST && ( $path == /config/* || $path == /learn/apply ) ]]; then
		request=(cas_write "$MODE_RESULTS/config.revision" curl)
	fi
	HTTP_CODE=$("${request[@]}" "${args[@]}" "${BASE}${path}" 2>"$MODE_RESULTS/curl-error.log") || HTTP_CODE=000
}

exact_api_expect() {
	local expected=$1 description=$2
	[[ $HTTP_CODE == "$expected" ]] ||
		exact_fail "$description returned HTTP $HTTP_CODE, expected $expected; response=$(cat "$API_OUTPUT" 2>/dev/null || true)"
}

exact_api_get() {
	API_OUTPUT=$2
	exact_api GET "$1" "$API_OUTPUT"
	exact_api_expect 200 "$3"
}

exact_api_post() {
	API_OUTPUT=$3
	exact_api POST "$1" "$API_OUTPUT" "$2"
	exact_api_expect 200 "$4"
}

exact_review_required() {
	[[ $HTTP_CODE == 409 ]] &&
		jq -e '.error == "explicit suggestion review required"' "$1" >/dev/null
}

exact_candidate_unchanged() {
	local before after
	cmp -s "$1.revision" "$2.revision" &&
		before=$(jq -Sec 'select(type == "object")' "$1") &&
		after=$(jq -Sec 'select(type == "object")' "$2") &&
		[[ $before == "$after" ]]
}

exact_review_selection() {
	local id=$1 revision=$2
	jq -n --arg id "$id" --argjson revision "$revision" \
		'{selection:{id:$id,revision:$revision},approve:true,coordinateApproved:true}' \
		>"$MODE_RESULTS/review-request-$id.json"
	exact_api_post "/learn/suggestions/$id/review" \
		"$MODE_RESULTS/review-request-$id.json" \
		"$MODE_RESULTS/review-response-$id.json" "$CAPTURE_MODE authenticated IEC/coordinate review"
	jq -e '.status == "reviewed" and .review.actor != ""' "$MODE_RESULTS/review-response-$id.json" >/dev/null ||
		exact_fail "$CAPTURE_MODE suggestion review did not persist an authenticated reviewed state; response=$(cat "$MODE_RESULTS/review-response-$id.json")"
}

exact_write_json() {
	local output=$1
	cat >"$output"
}

exact_count_modbus() {
	local function_code=$1
	compose exec -T modbus_server sh -c 'cat /tmp/modbus-requests.jsonl 2>/dev/null || true' |
		jq -s --argjson fc "$function_code" '[.[] | select(.function_code == $fc)] | length'
}

exact_modbus_state() {
	compose exec -T modbus_server cat /tmp/modbus-state.json
}

exact_rtu_state() {
	compose exec -T iec_rtu cat /state/rtu.json
}

exact_drive_modbus_read() {
	local label=$1 output=$2 status=0
	compose exec -T modbus_client python /opt/exact/modbus_client.py read "$MODBUS_SERVER_IP" 502 \
		>"$output" 2>&1 || status=$?
	[[ $status == 0 ]] ||
		exact_fail "$label: Modbus FC3 client exited $status instead of receiving its response; receiver=$(exact_modbus_state); client=$(cat "$output")"
	grep -q '^READ_OK ' "$output" ||
		exact_fail "$label: Modbus FC3 response was not confirmed; receiver=$(exact_modbus_state); client=$(cat "$output")"
}

exact_drive_coil() {
	local value=$1 label=$2 output=$3 status=0
	compose exec -T modbus_client python /opt/exact/modbus_client.py coil "$MODBUS_SERVER_IP" 502 --value "$value" \
		>"$output" 2>&1 || status=$?
	[[ $status == 0 ]] ||
		exact_fail "$label: legitimate FC5 value $value was not confirmed by the receiver; receiver=$(exact_modbus_state); client=$(cat "$output")"
	grep -q "^COIL_OK 7 $value$" "$output" ||
		exact_fail "$label: FC5 receiver response did not echo address 7/value $value; receiver=$(exact_modbus_state); client=$(cat "$output")"
}

exact_drive_sbo() {
	local value=$1 qualifier=$2 label=$3 output=$4 status=0
	compose exec -T iec_cc iec104ep cmd "$RTU_IP" 2404 sboq 1 2001 "$value" "$qualifier" \
		>"$output" 2>&1 || status=$?
	[[ $status == 0 ]] ||
		exact_fail "$label: IEC 104 select-before-operate value $value/qualifier $qualifier was not confirmed; RTU=$(exact_rtu_state); client=$(cat "$output")"
}

exact_wait_for_shadow() {
	local rule_id=$1 label=$2 counters
	for _ in $(seq 1 30); do
		exact_api_get /firewall/shadow-counters "$MODE_RESULTS/shadow-counters.json" "$label shadow counters"
		counters=$(cat "$MODE_RESULTS/shadow-counters.json")
		if jq -e --arg id "$rule_id" '.available and .unit == "messages" and any(.rules[]; .ruleId == $id and .shadowMatches > 0)' \
			<<<"$counters" >/dev/null; then
			return 0
		fi
		sleep 0.2
	done
	exact_fail "$label: monitor rule $rule_id did not increment shadowMatches; counters=$counters"
}
