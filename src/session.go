package main

import (
	"github.com/google/gopacket/layers"
)

// SessionKey represents the 5-tuple for tracking sent packets
type SessionKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   layers.IPProtocol
}
