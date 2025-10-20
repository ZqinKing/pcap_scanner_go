package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// listenForResponses listens for incoming packets and saves matching responses
func listenForResponses(wg *sync.WaitGroup, ifaceName string, srcIP net.IP, sentSessions map[SessionKey]struct{}, mu *sync.Mutex, senderDone chan struct{}) {
	defer wg.Done()

	// Open interface for capturing
	handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.NextPacket)
	if err != nil {
		log.Fatalf("Error opening interface %s for capturing: %v", ifaceName, err)
	}
	defer handle.Close()

	// Apply BPF filter to only capture traffic destined for our srcIP
	filter := fmt.Sprintf("dst host %s", srcIP.String())
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}
	log.Printf("Listening for responses on %s with filter: %s", ifaceName, filter)

	// Create pcap writer for responses
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	outputPcapFile := fmt.Sprintf("capture_%s.pcap", timestamp)
	f, err := os.Create(outputPcapFile)
	if err != nil {
		log.Fatalf("Error creating output pcap file: %v", err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(uint32(1600), handle.LinkType()); err != nil {
		log.Fatalf("Error writing pcap file header: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Loop for capturing packets
	for {
		select {
		case packet := <-packetSource.Packets():
			// Parse incoming packet
			var ip4Layer *layers.IPv4
			var ip6Layer *layers.IPv6
			var tcpLayer *layers.TCP
			var udpLayer *layers.UDP

			for _, layer := range packet.Layers() {
				switch layerType := layer.LayerType(); layerType {
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

			// Construct reverse session key
			var incomingKey SessionKey
			if ip4Layer != nil {
				incomingKey.SrcIP = ip4Layer.DstIP.String() // Our sent DstIP is now their SrcIP
				incomingKey.DstIP = ip4Layer.SrcIP.String() // Our sent SrcIP is now their DstIP
				incomingKey.Proto = ip4Layer.Protocol
			} else if ip6Layer != nil {
				incomingKey.SrcIP = ip6Layer.DstIP.String()
				incomingKey.DstIP = ip6Layer.SrcIP.String()
				incomingKey.Proto = ip6Layer.NextHeader
			} else {
				continue // Not an IP packet, ignore
			}

			if tcpLayer != nil {
				incomingKey.SrcPort = uint16(tcpLayer.DstPort) // Our sent DstPort is now their SrcPort
				incomingKey.DstPort = uint16(tcpLayer.SrcPort) // Our sent SrcPort is now their DstPort
			} else if udpLayer != nil {
				incomingKey.SrcPort = uint16(udpLayer.DstPort)
				incomingKey.DstPort = uint16(udpLayer.SrcPort)
			}

			// Check if this is a response to a packet we sent
			mu.Lock()
			_, found := sentSessions[incomingKey]
			mu.Unlock()

			if found {
				log.Printf("Matched response from %s to %s. Saving to %s", incomingKey.DstIP, incomingKey.SrcIP, outputPcapFile)
				if err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
					log.Printf("Error writing packet to pcap file: %v", err)
				}
				// Optionally remove from map to avoid duplicate matches for the same session
				// mu.Lock()
				// delete(sentSessions, incomingKey)
				// mu.Unlock()
			}

		case <-senderDone:
			// Sender has finished, wait a bit for any delayed responses, then exit
			log.Println("Sender finished. Waiting for final responses...")
			time.Sleep(5 * time.Second) // Give some time for last responses
			log.Println("Listener shutting down.")
			return
		}
	}
}
