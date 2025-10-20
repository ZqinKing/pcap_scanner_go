package main

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// sendPackets sends packets to target IPs
func sendPackets(wg *sync.WaitGroup, ifaceName string, srcIP net.IP, targetIPs []net.IP, templates []gopacket.Packet, sentSessions map[SessionKey]struct{}, mu *sync.Mutex, senderDone chan struct{}, captureEnabled bool) {
	defer wg.Done()
	defer close(senderDone)

	handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.NextPacket)
	if err != nil {
		log.Fatalf("Error opening interface %s for sending: %v", ifaceName, err)
	}
	defer handle.Close()

	log.Printf("Starting packet sending from %s to %d target IPs...", srcIP.String(), len(targetIPs))

	for _, targetIP := range targetIPs {
		for _, templatePacket := range templates {
			// Create a new packet from the template to modify
			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}

			// Extract layers from the template
			var ethLayer *layers.Ethernet
			var ip4Layer *layers.IPv4
			var ip6Layer *layers.IPv6
			var tcpLayer *layers.TCP
			var udpLayer *layers.UDP

			for _, layer := range templatePacket.Layers() {
				switch layerType := layer.LayerType(); layerType {
				case layers.LayerTypeEthernet:
					ethLayer = layer.(*layers.Ethernet)
				case layers.LayerTypeIPv4:
					ip4Layer = layer.(*layers.IPv4)
				case layers.LayerTypeIPv6:
					ip6Layer = layer.(*layers.IPv6)
				case layers.LayerTypeTCP:
					tcpLayer = layer.(*layers.TCP)
				case layers.LayerTypeUDP:
					udpLayer = layer.(*layers.UDP)
				}
			}

			// Modify IP layer
			if ip4Layer != nil {
				ip4Layer.SrcIP = srcIP
				ip4Layer.DstIP = targetIP
				ip4Layer.Checksum = 0 // gopacket will recompute
			} else if ip6Layer != nil {
				ip6Layer.SrcIP = srcIP
				ip6Layer.DstIP = targetIP
			} else {
				log.Printf("Warning: Packet template has no IPv4 or IPv6 layer, skipping modification for this packet.")
				continue
			}

			// Re-serialize the packet
			var err error
			if ethLayer != nil {
				err = gopacket.SerializeLayers(buffer, options, ethLayer, ip4Layer, ip6Layer, tcpLayer, udpLayer, gopacket.Payload(templatePacket.ApplicationLayer().Payload()))
			} else {
				// If no Ethernet layer, assume raw IP packet
				err = gopacket.SerializeLayers(buffer, options, ip4Layer, ip6Layer, tcpLayer, udpLayer, gopacket.Payload(templatePacket.ApplicationLayer().Payload()))
			}

			if err != nil {
				log.Printf("Error serializing packet: %v", err)
				continue
			}

			// Store session key if capture is enabled
			if captureEnabled {
				key := SessionKey{
					SrcIP: srcIP.String(),
					DstIP: targetIP.String(),
				}
				if tcpLayer != nil {
					key.SrcPort = uint16(tcpLayer.SrcPort)
					key.DstPort = uint16(tcpLayer.DstPort)
					key.Proto = layers.IPProtocolTCP
				} else if udpLayer != nil {
					key.SrcPort = uint16(udpLayer.SrcPort)
					key.DstPort = uint16(udpLayer.DstPort)
					key.Proto = layers.IPProtocolUDP
				} else if ip4Layer != nil {
					key.Proto = ip4Layer.Protocol
				} else if ip6Layer != nil {
					key.Proto = ip6Layer.NextHeader
				}

				mu.Lock()
				sentSessions[key] = struct{}{}
				mu.Unlock()
			}

			// Send the packet
			if err := handle.WritePacketData(buffer.Bytes()); err != nil {
				log.Printf("Error sending packet: %v", err)
			} else {
				// log.Printf("Sent packet from %s to %s", srcIP.String(), targetIP.String())
			}
			time.Sleep(10 * time.Millisecond) // Small delay to avoid overwhelming the network
		}
	}
	log.Println("Sender finished sending all packets.")
}
