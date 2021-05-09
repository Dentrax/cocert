#!/usr/bin/env bats

set -o errexit; set -o nounset; set -o pipefail;

setup_file() {
     export XDG_CACHE_HOME="$(mktemp -d)"
     export CMD="$XDG_CACHE_HOME/cocert"
     cp *.exp $XDG_CACHE_HOME
     cp *.key $XDG_CACHE_HOME
     run go build -o "$CMD" ../.
}

teardown_file() {
    rm -rf "$XDG_CACHE_HOME"
}

setup() {
    pushd $XDG_CACHE_HOME
}

teardown() {
    popd
}

@test "main: should run" {
  run ${CMD}
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "generate: should success" {
    run ./generate.exp
    stat cocert.pub
    echo "$output"
    [ "$status" -eq 0 ]
}

@test "decrypt: should success" {
  run ${CMD} decrypt -f cocert0.key -k 0 -o cocert0.key.decrypted
  echo -n "1" | ${CMD} decrypt -f cocert1.key -o cocert1.key.decrypted
  echo -n "2" | ${CMD} decrypt -f cocert2.key -o cocert2.key.decrypted
  stat cocert0.key.decrypted
  stat cocert1.key.decrypted
  stat cocert2.key.decrypted
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "encrypt: should success" {
  run ${CMD} encrypt -f cocert0.key.decrypted -k 0 -o cocert0.key.encrypted
  stat cocert0.key.encrypted
  [ "$status" -eq 0 ]
}

@test "combine: should success" {
    run ./combine.exp
    stat combined.key
    echo "$output"
    [ "$status" -eq 0 ]
    [[ $output = *"Combined"* ]]
}

@test "combine: should success for unencrypted" {
    run bash -c "echo -n "123" | ${CMD} combine -F cocert1.key.decrypted -F cocert2.key.decrypted -o private.key"
    echo "$output"
    stat private.key
    [ "$status" -eq 0 ]
    [[ $output = *"Combined"* ]]
}

@test "sign: should success combine" {
  run ./sign.exp
  stat combine.signature
  echo "$output"
  [ "$status" -eq 0 ]
  [[ "$output" = *"Signed:"* ]]
}

@test "sign: should success pk" {
  run ./sign_pk.exp
  stat combined.signature
  echo "$output"
  [ "$status" -eq 0 ]
  [[ "$output" = *"Signed:"* ]]
}

@test "verify: should success" {
  run ${CMD} verify -f cocert.pub -p "Foo Bar Baz" -s combine.signature
  echo "$output"
  [ "$status" -eq 0 ]
  [[ "$output" = *"Verified."* ]]
}

@test "split: should success for cosign key" {
  run ./split.exp
  echo "$output"
  [ "$status" -eq 0 ]
}

@test "combine: should success for splitted cosign key" {
    run ./combine_splitted.exp
    stat combined_splitted.key
    echo "$output"
    [ "$status" -eq 0 ]
    [[ $output = *"Combined"* ]]
}