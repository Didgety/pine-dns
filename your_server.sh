#!/bin/sh

exec cargo run \
    --quiet \
    --release \
    --target-dir=/tmp/pine-dns-target \
    --manifest-path $(dirname $0)/Cargo.toml -- "$@"