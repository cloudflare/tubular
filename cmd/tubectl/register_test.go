package main

import (
	"strings"
	"testing"
)

func TestRegisterFailsWithoutLabel(t *testing.T) {
	netns := mustReadyNetNS(t)

	_, err := testTubectl(t, netns, "register")
	if err == nil {
		t.Fatal("expected register to fail")
	}
	if !strings.Contains(err.Error(), "missing arguments") {
		t.Fatal("unexpected register error: ", err)
	}
}

func TestRegisterFailsWithoutSocket(t *testing.T) {
}

func TestRegisterFailsForNonSocket(t *testing.T) {
}

func TestRegisterFailsForDualStackSocket(t *testing.T) {
}

func TestRegisterFailsForUnixSocket(t *testing.T) {
}

func TestRegisterFailsForConnectedTCPSocket(t *testing.T) {
}

func TestRegisterFailsForConnectedUDPSocket(t *testing.T) {
}

func TestRegisterTCPv4(t *testing.T) {
}

func TestRegisterTCPv6(t *testing.T) {
}

func TestRegisterUDPv4(t *testing.T) {
}

func TestRegisterUDPv6(t *testing.T) {
}

func TestUnregisterFailsWithoutLabelOrSocketCookie(t *testing.T) {
}

func TestUnregisterFailsForInvalidLabel(t *testing.T) {
}

func TestUnregisterFailsForInvalidSocketCookie(t *testing.T) {
}

func TestUnregisterValidLabelAndSocketCookie(t *testing.T) {
}

// Tests for sequences of commands

func TestSequenceRegisterReregister(t *testing.T) {
}

func TestSequenceUnregisterUnregister(t *testing.T) {
}

func TestSequenceRegisterUnregisterReregister(t *testing.T) {
}

// TODO: Passing multiple sockets
