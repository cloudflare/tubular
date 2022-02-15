#!/bin/bash
# Test the current package under a different kernel.
# Requires virtme and qemu to be installed.
# Examples:
#     Run all tests on a 5.4 kernel
#     $ ./run-tests.sh 5.4
#     Run a subset of tests:
#     $ ./run-tests.sh 5.4 go test ./link

set -euo pipefail

script="$(realpath "$0")"
readonly script

# This script is a bit like a Matryoshka doll since it keeps re-executing itself
# in various different contexts:
#
#   1. invoked by the user like run-tests.sh 5.4
#   2. invoked by go test like run-tests.sh --exec-vm
#   3. invoked by init in the vm like run-tests.sh --exec-test
#
# This allows us to use all available CPU on the host machine to compile our
# code, and then only use the VM to execute the test. This is because the VM
# is usually slower at compiling than the host.
if [[ "${1:-}" = "--exec-vm" ]]; then
  shift

  input="$1"
  shift

  # Use sudo if /dev/kvm isn't accessible by the current user.
  sudo=""
  if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    sudo="sudo"
  fi
  readonly sudo

  testdir="$(dirname "$1")"
  output="$(mktemp -d)"
  printf -v cmd "%q " "$@"

  if [[ "$(stat -c '%t:%T' -L /proc/$$/fd/0)" == "1:3" ]]; then
    # stdin is /dev/null, which doesn't play well with qemu. Use a fifo as a
    # blocking substitute.
    mkfifo "${output}/fake-stdin"
    # Open for reading and writing to avoid blocking.
    exec 0<> "${output}/fake-stdin"
    rm "${output}/fake-stdin"
  fi

  $sudo virtme-run --kimg "${input}/bzImage" --memory 512M --pwd \
  --rwdir="${testdir}=${testdir}" \
  --rodir=/run/input="${input}" \
  --rwdir=/run/output="${output}" \
  --script-sh "PATH=\"$PATH\" \"$script\" --exec-test $cmd" \
  --qemu-opts -smp 2 # need at least two CPUs for some tests

  if [[ ! -e "${output}/success" ]]; then
    exit 1
  fi

  $sudo rm -r "$output"
  exit 0
elif [[ "${1:-}" = "--exec-test" ]]; then
  shift

  mount -t bpf bpf /sys/fs/bpf
  mount -t tracefs tracefs /sys/kernel/debug/tracing

  # Allow writing out coverage files from unpriviliged test binaries.
  chmod -R o+w /tmp/go-build*

  dmesg -C
  if ! "$@"; then
    dmesg
    exit 1
  fi
  touch "/run/output/success"
  exit 0
fi

readonly kernel_version="${1:-}"
if [[ -z "${kernel_version}" ]]; then
  echo "Expecting kernel version as first argument"
  exit 1
fi
shift

readonly kernel="linux-${kernel_version}.bz"
readonly input="$(mktemp -d)"
readonly tmp_dir="${TMPDIR:-/tmp}"

fetch() {
  echo Fetching "${1}"
  pushd "${tmp_dir}" > /dev/null
  curl -s -L -O --fail -z "${1}" "https://github.com/cilium/ci-kernels/raw/master/${1}"
  local ret=$?
  popd > /dev/null
  return $ret
}

fetch "${kernel}"
cp "${tmp_dir}/${kernel}" "${input}/bzImage"

export GOFLAGS=-mod=readonly
export CGO_ENABLED=0

echo Testing on "${kernel_version}"
"${GO:-go}" test -exec "$script --exec-vm $input" "$@"
echo "Test successful on ${kernel_version}"

rm -r "${input}"
