#!/usr/bin/env bash
usage='Usage: bash deployment/openshell/install-kubeconfig.sh
Use the admin KUBECONFIG to install restricted Gateway credentials and check RBAC.'
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
require_root
need kubectl
: "${KUBECONFIG:?export administrator KUBECONFIG first}"
kubectl create namespace openshell --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deployment/openshell/gateway-rbac.yaml
for attempt in $(seq 1 60); do
  if test -n "$(kubectl -n openshell get secret openshell-gateway-token \
      -o jsonpath='{.data.token}')" && \
     test -n "$(kubectl -n openshell get secret openshell-gateway-token \
      -o jsonpath='{.data.ca\.crt}')"; then
    break
  fi
  sleep 2
done
test -n "$(kubectl -n openshell get secret openshell-gateway-token \
  -o jsonpath='{.data.token}')"
test -n "$(kubectl -n openshell get secret openshell-gateway-token \
  -o jsonpath='{.data.ca\.crt}')"
GATEWAY_KUBECONFIG=/etc/openshell-confidential/kubeconfig
ACK_API_SERVER="$(kubectl config view --minify \
  -o jsonpath='{.clusters[0].cluster.server}')"
case "$ACK_API_SERVER" in https://*) ;; *) exit 1 ;; esac
kubectl -n openshell get secret openshell-gateway-token \
  -o jsonpath='{.data.ca\.crt}' | base64 -d > /etc/openshell-confidential/ack-ca.pem
test -s /etc/openshell-confidential/ack-ca.pem
chown root:openshell-gateway /etc/openshell-confidential/ack-ca.pem
chmod 0644 /etc/openshell-confidential/ack-ca.pem
install -o root -g openshell-gateway -m 0640 /dev/null "$GATEWAY_KUBECONFIG"
kubectl --kubeconfig "$GATEWAY_KUBECONFIG" config set-cluster ack \
  --server="$ACK_API_SERVER" \
  --certificate-authority=/etc/openshell-confidential/ack-ca.pem \
  --embed-certs=true
set +x
kubectl --kubeconfig "$GATEWAY_KUBECONFIG" config set-credentials \
  openshell-gateway --token="$(kubectl -n openshell get secret \
    openshell-gateway-token -o jsonpath='{.data.token}' | base64 -d)" >/dev/null
kubectl --kubeconfig "$GATEWAY_KUBECONFIG" config set-context openshell \
  --cluster=ack --user=openshell-gateway --namespace=openshell
kubectl --kubeconfig "$GATEWAY_KUBECONFIG" config use-context openshell
chown root:openshell-gateway "$GATEWAY_KUBECONFIG"
chmod 0640 "$GATEWAY_KUBECONFIG"
for check in \
  'get persistentvolumeclaims -n openshell' \
  'get runtimeclass/kata-remote' \
  'get services -n openshell' \
  'create services -n openshell' \
  'delete services -n openshell'; do
  test "$(kubectl --kubeconfig /etc/openshell-confidential/kubeconfig \
    auth can-i $check)" = yes
done
runuser -u openshell-gateway -- env \
  KUBECONFIG=/etc/openshell-confidential/kubeconfig \
  /usr/local/bin/openshell-gateway \
  --config /etc/openshell-confidential/gateway.toml config preflight
kubectl apply -f deployment/openshell/network-fence.example.yaml
kubectl -n openshell get networkpolicy confidential-ingress-default-deny -o yaml
