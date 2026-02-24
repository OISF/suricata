#!/bin/bash
#
# DPDK run test suite.
#
#
# Usage:
#   dpdk-testsuite.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECKLOG="${SCRIPT_DIR}/dpdk-checklog.sh"

IDS_YAML="${SCRIPT_DIR}/suricata-null-ids.yaml"
BOND_YAML="${SCRIPT_DIR}/suricata-null-bond.yaml"

PASS=0
FAIL=0

run_test() {
    local description="$1"; shift
    echo ""
    echo "=== TEST: ${description} ==="
    local t0=$SECONDS
    if bash "$CHECKLOG" "$@"; then
        echo "  (${description}: $((SECONDS - t0))s)"
        PASS=$((PASS + 1))
    else
        echo "  (${description}: $((SECONDS - t0))s)"
        FAIL=$((FAIL + 1))
        echo "^^^ FAILED: ${description}"
    fi
}

# IDS (single interface: net_null0, 16 rx/tx descriptors)

run_test "IDS: auto mempool, auto cache (1 thread)" \
    --interface-cfg-set net_null0.threads=1 \
    --interface-cfg-set net_null0.mempool-size=auto \
    --interface-cfg-set net_null0.mempool-cache-size=auto \
    --suricata-log-check-grep "1 packet mempools of size 31, cache size 1" \
    --expect-start \
    "$IDS_YAML"

run_test "IDS: auto mempool, auto cache (2 threads)" \
    --interface-cfg-set net_null0.threads=2 \
    --interface-cfg-set net_null0.mempool-size=auto \
    --interface-cfg-set net_null0.mempool-cache-size=auto \
    --suricata-log-check-grep "2 packet mempools of size 31, cache size 1" \
    --expect-start \
    "$IDS_YAML"

run_test "IDS: auto mempool, static cache=1 (1 thread)" \
    --interface-cfg-set net_null0.threads=1 \
    --interface-cfg-set net_null0.mempool-size=auto \
    --interface-cfg-set net_null0.mempool-cache-size=1 \
    --suricata-log-check-grep "1 packet mempools of size 31, cache size 1" \
    --expect-start \
    "$IDS_YAML"

run_test "IDS: auto mempool, static cache=1 (2 threads)" \
    --interface-cfg-set net_null0.threads=2 \
    --interface-cfg-set net_null0.mempool-size=auto \
    --interface-cfg-set net_null0.mempool-cache-size=1 \
    --suricata-log-check-grep "2 packet mempools of size 31, cache size 1" \
    --expect-start \
    "$IDS_YAML"

run_test "IDS: auto mempool, oversized cache=1024 (fail)" \
    --interface-cfg-set net_null0.threads=1 \
    --interface-cfg-set net_null0.mempool-size=auto \
    --interface-cfg-set net_null0.mempool-cache-size=1024 \
    --suricata-log-check-grep "mempool cache size requires a positive number" \
    --expect-fail \
    "$IDS_YAML"

run_test "IDS: static mempool=1023, auto cache (1 thread)" \
    --interface-cfg-set net_null0.threads=1 \
    --interface-cfg-set net_null0.mempool-size=1023 \
    --interface-cfg-set net_null0.mempool-cache-size=auto \
    --suricata-log-check-grep "1 packet mempools of size 1023, cache size 341" \
    --expect-start \
    "$IDS_YAML"

# 2^n - 1 mempool size recommendation
run_test "IDS: static mempool=1024, auto cache (1 thread)" \
    --interface-cfg-set net_null0.threads=1 \
    --interface-cfg-set net_null0.mempool-size=1024 \
    --interface-cfg-set net_null0.mempool-cache-size=auto \
    --suricata-log-check-grep "1 packet mempools of size 1023, cache size 341" \
    --expect-start \
    "$IDS_YAML"


run_test "IDS: static mempool=1023, auto cache (2 threads)" \
    --interface-cfg-set net_null0.threads=2 \
    --interface-cfg-set net_null0.mempool-size=1023 \
    --interface-cfg-set net_null0.mempool-cache-size=auto \
    --suricata-log-check-grep "2 packet mempools of size 511, cache size 73" \
    --expect-start \
    "$IDS_YAML"

run_test "IDS: mempool too small (fail)" \
    --interface-cfg-set net_null0.threads=1 \
    --interface-cfg-set net_null0.mempool-size=15 \
    --suricata-log-check-grep "mempool size is likely too small" \
    --expect-fail \
    "$IDS_YAML"

run_test "IDS: auto descriptors, auto mempool (OOM expected with nohuge)" \
    --interface-cfg-set net_null0.threads=1 \
    --interface-cfg-set net_null0.mempool-size=auto \
    --interface-cfg-set net_null0.mempool-cache-size=auto \
    --interface-cfg-set net_null0.rx-descriptors=auto \
    --interface-cfg-set net_null0.tx-descriptors=auto \
    --suricata-log-check-grep "1 packet mempools of size 65535, cache size 257" \
    --suricata-log-check-grep "rte_pktmbuf_pool_create failed" \
    --expect-fail \
    "$IDS_YAML"

# Bond (net_bonding0, 2 members, 16 rx/tx descriptors)

run_test "Bond: auto mempool, auto cache (1 thread)" \
    --interface-cfg-set net_bonding0.threads=1 \
    --interface-cfg-set net_bonding0.mempool-size=auto \
    --interface-cfg-set net_bonding0.mempool-cache-size=auto \
    --suricata-log-check-grep "1 packet mempools of size 63, cache size 21" \
    --expect-start \
    "$BOND_YAML"

run_test "Bond: auto mempool, auto cache (2 threads)" \
    --interface-cfg-set net_bonding0.threads=2 \
    --interface-cfg-set net_bonding0.mempool-size=auto \
    --interface-cfg-set net_bonding0.mempool-cache-size=auto \
    --suricata-log-check-grep "2 packet mempools of size 63, cache size 21" \
    --expect-start \
    "$BOND_YAML"

run_test "Bond: auto mempool, static cache=7 (1 thread)" \
    --interface-cfg-set net_bonding0.threads=1 \
    --interface-cfg-set net_bonding0.mempool-size=auto \
    --interface-cfg-set net_bonding0.mempool-cache-size=7 \
    --suricata-log-check-grep "1 packet mempools of size 63, cache size 7" \
    --expect-start \
    "$BOND_YAML"

run_test "Bond: auto mempool, static cache=7 (2 threads)" \
    --interface-cfg-set net_bonding0.threads=2 \
    --interface-cfg-set net_bonding0.mempool-size=auto \
    --interface-cfg-set net_bonding0.mempool-cache-size=7 \
    --suricata-log-check-grep "2 packet mempools of size 63, cache size 7" \
    --expect-start \
    "$BOND_YAML"

run_test "Bond: auto mempool, oversized cache=1024 (fail)" \
    --interface-cfg-set net_bonding0.threads=1 \
    --interface-cfg-set net_bonding0.mempool-size=auto \
    --interface-cfg-set net_bonding0.mempool-cache-size=1024 \
    --suricata-log-check-grep "mempool cache size requires a positive number" \
    --expect-fail \
    "$BOND_YAML"

run_test "Bond: static mempool=1023, auto cache (1 thread)" \
    --interface-cfg-set net_bonding0.threads=1 \
    --interface-cfg-set net_bonding0.mempool-size=1023 \
    --interface-cfg-set net_bonding0.mempool-cache-size=auto \
    --suricata-log-check-grep "1 packet mempools of size 1023, cache size 341" \
    --expect-start \
    "$BOND_YAML"

run_test "Bond: static mempool=1023, auto cache (2 threads)" \
    --interface-cfg-set net_bonding0.threads=2 \
    --interface-cfg-set net_bonding0.mempool-size=1023 \
    --interface-cfg-set net_bonding0.mempool-cache-size=auto \
    --suricata-log-check-grep "2 packet mempools of size 511, cache size 73" \
    --expect-start \
    "$BOND_YAML"

run_test "Bond: mempool too small (fail)" \
    --interface-cfg-set net_bonding0.threads=1 \
    --interface-cfg-set net_bonding0.mempool-size=15 \
    --suricata-log-check-grep "mempool size is likely too small" \
    --expect-fail \
    "$BOND_YAML"

# Summary

echo ""
echo "=========================================="
echo "  DPDK test suite: ${PASS} passed, ${FAIL} failed"
echo "=========================================="
exit $FAIL
