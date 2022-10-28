#!/usr/bin/env bash

set -e

binpath=${vault_install_dir}/vault

fail() {
  echo "$1" 1>&2
  return 1
}

test -x "$binpath" || fail "unable to locate vault binary at $binpath"

# Fetch secondary token
$binpath write sys/replication/performance/primary/secondary-token id=enos-repl-1 |sed -n '/^wrapping_token:/p' /tmp/secondary_token.out |awk '{print $2}'
