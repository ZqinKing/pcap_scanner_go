package main

import (
	"fmt"
	"net"
	"strings"
)

// parseTargetSpec parses the target IP specification (CIDR, Range, or Single IP)
func parseTargetSpec(spec string) ([]net.IP, error) {
	var ips []net.IP

	if strings.Contains(spec, "/") { // CIDR
		ip, ipNet, err := net.ParseCIDR(spec)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %w", err)
		}
		for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
			ips = append(ips, net.IP(ip))
		}
	} else if strings.Contains(spec, "-") { // Range
		parts := strings.Split(spec, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid IP range format: %s", spec)
		}
		startIP := net.ParseIP(parts)
		endIP := net.ParseIP(parts)
		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("invalid IP in range: %s", spec)
		}
		if len(startIP) != len(endIP) {
			return nil, fmt.Errorf("IP versions mismatch in range: %s", spec)
		}

		for ip := startIP; bytesCompare(ip, endIP) <= 0; inc(ip) {
			ips = append(ips, net.IP(ip))
		}
	} else { // Single IP
		ip := net.ParseIP(spec)
		if ip == nil {
			return nil, fmt.Errorf("invalid single IP: %s", spec)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// inc increments an IP address
func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// bytesCompare compares two byte slices
func bytesCompare(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
