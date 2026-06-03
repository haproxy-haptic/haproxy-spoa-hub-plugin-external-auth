#!/usr/bin/env bash
set -euo pipefail

# E2E test: full oauth2-proxy authentication flow via kind cluster.
#
# Components: HAProxy + haproxy-spoa-hub (with external-auth plugin),
# oauth2-proxy in auth middleware mode, mock-oauth2-server (auto-grants).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLUSTER_NAME="e2e-auth-$$"
NAMESPACE="e2e-auth"
HOST_PORT=${E2E_PORT:-$(shuf -i 20000-50000 -n 1)}

# In dind, the NodePort is on the docker host, not localhost
if [ -n "${DOCKER_HOST:-}" ]; then
    NODE_HOST=$(echo "$DOCKER_HOST" | sed -n 's|tcp://\([^:]*\):.*|\1|p')
    NODE_HOST=${NODE_HOST:-docker}
else
    NODE_HOST="localhost"
fi
BASE_URL="http://${NODE_HOST}:$HOST_PORT"
PASSED=0
FAILED=0
TMPDIR=$(mktemp -d)

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

assert_eq() {
    local actual="$1" expected="$2" msg="$3"
    if [ "$actual" = "$expected" ]; then
        echo "  PASS: $msg"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL: $msg (expected '$expected', got '$actual')"
        FAILED=$((FAILED + 1))
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" msg="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        echo "  PASS: $msg"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL: $msg (expected to contain '$needle')"
        echo "  Actual: $haystack"
        FAILED=$((FAILED + 1))
    fi
}

assert_not_eq() {
    local actual="$1" unexpected="$2" msg="$3"
    if [ "$actual" != "$unexpected" ]; then
        echo "  PASS: $msg"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL: $msg (expected not '$unexpected', got '$actual')"
        FAILED=$((FAILED + 1))
    fi
}

# ============================================================================
# Prerequisites
# ============================================================================

for cmd in kind kubectl docker curl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is required but not found"
        exit 1
    fi
done

# ============================================================================
# Create kind cluster
# ============================================================================

echo "=== Creating kind cluster '$CLUSTER_NAME' (host port $HOST_PORT) ==="

# In CI (dind), the Docker daemon runs in a separate container. We need the
# API server to be reachable from the CI job container via the "docker" hostname.
API_SERVER_ADDRESS="127.0.0.1"
if [ -n "${DOCKER_HOST:-}" ]; then
    API_SERVER_ADDRESS="0.0.0.0"
fi

cat > "$TMPDIR/kind-config.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerAddress: "$API_SERVER_ADDRESS"
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30080
        hostPort: $HOST_PORT
        protocol: TCP
EOF
kind create cluster --name "$CLUSTER_NAME" --config "$TMPDIR/kind-config.yaml" --wait 60s

# In dind, replace 0.0.0.0 in kubeconfig with the docker service hostname
if [ -n "${DOCKER_HOST:-}" ]; then
    DOCKER_HOST_NAME=$(echo "$DOCKER_HOST" | sed -n 's|tcp://\([^:]*\):.*|\1|p')
    DOCKER_HOST_NAME=${DOCKER_HOST_NAME:-docker}
    sed -i "s|server: https://0\.0\.0\.0:|server: https://${DOCKER_HOST_NAME}:|" "$HOME/.kube/config"
    # The kind-generated cert is for 0.0.0.0/localhost, not the docker hostname
    kubectl config set-cluster "kind-${CLUSTER_NAME}" --insecure-skip-tls-verify=true
fi

# ============================================================================
# Build and load hub+plugin image
# ============================================================================

echo "=== Building hub+plugin image ==="
docker build \
    -t e2e-hub:latest \
    -f "$SCRIPT_DIR/Dockerfile.hub" \
    "$REPO_DIR"

echo "=== Loading images into kind ==="
# Side-load every image the manifests reference (besides the locally-built
# e2e-hub) so pod startup never waits on a live registry pull. A slow or
# rate-limited ghcr.io/quay.io/docker.io pull would otherwise stall pod
# readiness past the wait timeout (observed once on mock-oidc). Images are
# discovered from the manifests so this stays correct when a tag is bumped.
mapfile -t DEP_IMAGES < <(
    awk '/^[[:space:]]*image:[[:space:]]/ {print $2}' "$SCRIPT_DIR"/manifests/*.yaml |
        grep -vxF 'e2e-hub:latest' | sort -u
)
for img in "${DEP_IMAGES[@]}"; do
    docker pull "$img"
done
kind load docker-image e2e-hub:latest "${DEP_IMAGES[@]}" --name "$CLUSTER_NAME"

# ============================================================================
# Deploy manifests
# ============================================================================

echo "=== Deploying manifests ==="
# Patch oauth2-proxy manifest with dynamic host and port for redirect URLs
sed "s/localhost:8080/${NODE_HOST}:$HOST_PORT/g" \
    "$SCRIPT_DIR/manifests/oauth2-proxy.yaml" > "$TMPDIR/oauth2-proxy.yaml"

kubectl apply -f "$SCRIPT_DIR/manifests/namespace.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/configmaps.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/mock-oidc.yaml"
kubectl apply -f "$TMPDIR/oauth2-proxy.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/haproxy-hub.yaml"

# ============================================================================
# Wait for pods
# ============================================================================

# Wait for a pod to become ready, dumping cluster diagnostics on timeout. The
# cleanup trap tears the cluster down on exit, so any startup failure must be
# captured here or it is lost (as happened on the silent mock-oidc timeout).
wait_ready() {
    local selector="$1"
    if kubectl wait --for=condition=ready pod -l "$selector" -n "$NAMESPACE" --timeout=120s; then
        return 0
    fi
    echo "FAIL: pods matching '$selector' did not become ready in time"
    echo "--- pods ---"
    kubectl get pods -o wide -n "$NAMESPACE" || true
    echo "--- describe ---"
    kubectl describe pods -n "$NAMESPACE" || true
    echo "--- events ---"
    kubectl get events -n "$NAMESPACE" --sort-by=.lastTimestamp || true
    echo "--- logs ---"
    kubectl logs -l "$selector" -n "$NAMESPACE" --all-containers --prefix --tail=100 || true
    exit 1
}

echo "=== Waiting for pods ==="
wait_ready app=mock-oidc
wait_ready app=oauth2-proxy
wait_ready app=haproxy-hub

echo "=== Waiting for HAProxy to accept connections ==="
for i in $(seq 1 30); do
    if curl -sf --max-time 2 "$BASE_URL/oauth2/ping" >/dev/null 2>&1; then
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "FAIL: HAProxy did not become ready"
        kubectl logs -l app=haproxy-hub -n "$NAMESPACE" --all-containers
        exit 1
    fi
    sleep 1
done

# ============================================================================
# Test 1: Unauthenticated request returns redirect
# ============================================================================

echo ""
echo "=== Test 1: Unauthenticated request returns redirect ==="
HTTP_CODE=$(curl -s -o "$TMPDIR/test1-body.txt" -D "$TMPDIR/test1-headers.txt" \
    -w '%{http_code}' --max-time 10 "$BASE_URL/app")
assert_eq "$HTTP_CODE" "302" "unauthenticated request returns 302"

LOCATION=$(grep -i '^location:' "$TMPDIR/test1-headers.txt" | tr -d '\r' | head -1)
assert_contains "$LOCATION" "/oauth2/start" "redirect points to oauth2 sign-in"

# ============================================================================
# Test 2: Full OAuth flow produces authenticated response
# ============================================================================

echo ""
echo "=== Test 2: Full OAuth flow (auto-grant) ==="
RESPONSE=$(curl -s -L -c "$TMPDIR/cookies.txt" -b "$TMPDIR/cookies.txt" \
    --max-time 30 --max-redirs 10 "$BASE_URL/app" 2>&1)

assert_contains "$RESPONSE" "allowed=true" "authenticated response contains allowed=true"
assert_contains "$RESPONSE" "user=" "authenticated response contains user field"
assert_contains "$RESPONSE" "email=" "authenticated response contains email field"

# ============================================================================
# Test 3: Authenticated request with cookie succeeds
# ============================================================================

echo ""
echo "=== Test 3: Subsequent authenticated request with cookie ==="
HTTP_CODE=$(curl -s -o "$TMPDIR/test3-body.txt" -b "$TMPDIR/cookies.txt" \
    -w '%{http_code}' --max-time 10 "$BASE_URL/another-path")
assert_eq "$HTTP_CODE" "200" "cookie-authenticated request returns 200"

BODY=$(cat "$TMPDIR/test3-body.txt")
assert_contains "$BODY" "allowed=true" "cookie-authenticated response is allowed"

# ============================================================================
# Test 4: Fail-closed when auth service is down
# ============================================================================

echo ""
echo "=== Test 4: Fail-closed with auth service down ==="
kubectl scale deployment oauth2-proxy --replicas=0 -n "$NAMESPACE"
kubectl wait --for=delete pod -l app=oauth2-proxy -n "$NAMESPACE" --timeout=60s 2>/dev/null || true
sleep 2

HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$BASE_URL/app")
assert_not_eq "$HTTP_CODE" "200" "request denied when auth service is down (got $HTTP_CODE)"

# Restore oauth2-proxy
kubectl scale deployment oauth2-proxy --replicas=1 -n "$NAMESPACE"
kubectl wait --for=condition=ready pod -l app=oauth2-proxy -n "$NAMESPACE" --timeout=120s

# ============================================================================
# Hub logs inspection
# ============================================================================

echo ""
echo "=== Hub logs ==="
HUB_LOGS=$(kubectl logs -l app=haproxy-hub -n "$NAMESPACE" -c hub 2>&1 || true)
echo "$HUB_LOGS" | tail -20

assert_contains "$HUB_LOGS" "plugin completed" "hub logs confirm plugin processed requests"

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="

if [ "$FAILED" -gt 0 ]; then
    echo ""
    echo "=== Debug: all pod logs ==="
    kubectl logs -l app=haproxy-hub -n "$NAMESPACE" --all-containers 2>&1 | tail -50
    echo "--- oauth2-proxy logs ---"
    kubectl logs -l app=oauth2-proxy -n "$NAMESPACE" --tail=100 2>&1 | grep -v '/ping'
    echo "--- mock-oidc logs ---"
    kubectl logs -l app=mock-oidc -n "$NAMESPACE" 2>&1 | tail -20
    exit 1
fi

echo "All e2e tests passed."
