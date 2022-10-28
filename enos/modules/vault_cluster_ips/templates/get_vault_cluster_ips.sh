#!/usr/bin/env bash

set -e

binpath=${vault_install_dir}/vault

fail() {
  echo "$1" 1>&2
  return 1
}

test -x "$binpath" || fail "unable to locate vault binary at $binpath"

export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='${vault_token}'

export leader_ip=$("$binpath" operator raft list-peers |grep leader |awk '{print $2}' |awk -F":" '{print $1}')
export follower_ips=$("$binpath" operator raft list-peers |grep follower |awk '{print $2}'|awk -F":" '{print $1}')
export follower_1=$(echo $follower_ips |awk '{print 1}')
export follower_2=$(echo $follower_ips |awk '{print 2}')

