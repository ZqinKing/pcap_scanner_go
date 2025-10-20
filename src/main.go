package main

import (
	"flag"
	"log"
	"net"
	"sync"
)

// Global variables for command-line flags
var (
	srcIPStr   = flag.String("srcIP", "", "Source IP address (IPv4 or IPv6)")
	targetSpec = flag.String("target", "", "Target IP(s) in CIDR (10.0.0.0/24), Range (10.0.0.1-10.0.0.100), or Single IP (10.0.0.1) format")
	pcapFile   = flag.String("pcap", "", "Path to the pcap file to use as a packet template")
	ifaceName  = flag.String("iface", "", "The network interface to send and receive packets on (e.g., eth0)")
	capture    = flag.Bool("capture", false, "Enable response capture and save to a timestamped pcap file")
)

func main() {
	flag.Parse()

	// Validate required flags
	if *srcIPStr == "" || *targetSpec == "" || *pcapFile == "" || *ifaceName == "" {
		flag.Usage()
		log.Fatal("Error: All required flags (-srcIP, -target, -pcap, -iface) must be provided.")
	}

	// Parse source IP
	srcIP := net.ParseIP(*srcIPStr)
	if srcIP == nil {
		log.Fatalf("Error: Invalid source IP address: %s", *srcIPStr)
	}

	// Generate target IPs
	targetIPs, err := parseTargetSpec(*targetSpec)
	if err != nil {
		log.Fatalf("Error parsing target specification: %v", err)
	}
	if len(targetIPs) == 0 {
		log.Fatal("Error: No target IPs generated from the provided specification.")
	}

	// Read packet templates from pcap file
	templates, err := readPcapTemplates(*pcapFile)
	if err != nil {
		log.Fatalf("Error reading pcap templates: %v", err)
	}
	if len(templates) == 0 {
		log.Fatal("Error: No valid IP/IPv6 packet templates found in the pcap file.")
	}

	// Setup for sending and capturing
	var wg sync.WaitGroup
	sentSessions := make(map[SessionKey]struct{}) // Track sent packets for matching responses
	var mu sync.Mutex                             // Mutex for sentSessions map

	// Channel to signal when sender is done
	senderDone := make(chan struct{})

	// Start listener goroutine if capture is enabled
	if *capture {
		wg.Add(1)
		go listenForResponses(&wg, *ifaceName, srcIP, sentSessions, &mu, senderDone)
	}

	// Start sender goroutine
	wg.Add(1)
	go sendPackets(&wg, *ifaceName, srcIP, targetIPs, templates, sentSessions, &mu, senderDone, *capture)

	// Wait for all goroutines to finish
	wg.Wait()
	log.Println("Scanning complete.")
}
