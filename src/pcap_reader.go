package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// readPcapTemplates reads packets from a pcap file and filters for IP/IPv6 packets
func readPcapTemplates(filename string) ([]gopacket.Packet, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening pcap file: %w", err)
	}
	defer handle.Close()

	var templates []gopacket.Packet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if packet.Layer(layers.LayerTypeIPv4) != nil || packet.Layer(layers.LayerTypeIPv6) != nil {
			templates = append(templates, packet)
		} else {
			log.Printf("Skipping non-IP/IPv6 packet from pcap file.")
		}
	}
	return templates, nil
}
