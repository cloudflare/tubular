package internal

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go tube ebpf/inet-kern.c -- -mcpu=v2 -O2 -g -nostdinc -Wall -Werror -Iebpf/include
