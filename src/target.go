/*
Copyright (C) 2025 ZqinKing <ZqinKing23@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


package main

import (
	"fmt"
	"net"
	"strings"
)

// parseTargetSpec 解析目标IP规范 (CIDR, 范围, 或单个IP)
func parseTargetSpec(spec string) ([]net.IP, error) {
	var ips []net.IP

	if strings.Contains(spec, "/") { // CIDR 格式
		ip, ipNet, err := net.ParseCIDR(spec)
		if err != nil {
			return nil, fmt.Errorf("无效的CIDR格式: %w", err)
		}
		for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
			ips = append(ips, net.IP(ip))
		}
	} else if strings.Contains(spec, "-") { // IP 范围格式
		parts := strings.Split(spec, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("无效的IP范围格式: %s", spec)
		}
		startIP := net.ParseIP(parts[0])
		endIP := net.ParseIP(parts[1])
		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("IP范围中包含无效IP: %s", spec)
		}
		if len(startIP) != len(endIP) {
			return nil, fmt.Errorf("IP范围中IP版本不匹配: %s", spec)
		}

		for ip := startIP; bytesCompare(ip, endIP) <= 0; inc(ip) {
			ips = append(ips, net.IP(ip))
		}
	} else { // 单个IP格式
		ip := net.ParseIP(spec)
		if ip == nil {
			return nil, fmt.Errorf("无效的单个IP: %s", spec)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// inc 递增IP地址
func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// bytesCompare 比较两个字节切片
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
