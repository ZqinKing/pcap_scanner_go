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
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// getInterfaceMAC 获取指定网络接口的 MAC 地址
func getInterfaceMAC(ifaceName string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("无法找到网络接口 %s: %v", ifaceName, err)
	}
	return iface.HardwareAddr, nil
}

// resolveNextHopIP 根据目标 IP 解析下一跳 IP 地址
// 这将通过读取 /proc/net/route 来模拟路由表查询
func resolveNextHopIP(destIP net.IP) (net.IP, error) {
	if destIP.IsLoopback() {
		return destIP, nil
	}

	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("无法打开 /proc/net/route: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // 跳过标题行

	var bestMatchNextHop net.IP
	var bestMatchMask net.IPMask

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}

		// Flags (标志位) - 必须是 UP 状态
		flags, err := strconv.ParseInt(fields[3], 16, 64)
		if err != nil || (flags&0x0001) == 0 { // 检查 RTF_UP 标志
			continue
		}

		// Destination (目标网络地址)
		destHex := fields[1]
		destBytes, err := hexToBytes(destHex)
		if err != nil {
			continue
		}
		routeDest := net.IP(destBytes)

		// Genmask (子网掩码)
		maskHex := fields[7]
		maskBytes, err := hexToBytes(maskHex)
		if err != nil {
			continue
		}
		mask := net.IPMask(maskBytes)

		// 检查目标 IP 是否在此路由范围内
		if destIP.Mask(mask).Equal(routeDest) {
			// 如果找到一个更具体的路由（掩码更长），则更新最佳匹配
			if bestMatchNextHop == nil || bytesToUint32(mask) > bytesToUint32(bestMatchMask) {
				bestMatchMask = mask
				gwHex := fields[2]
				gwBytes, err := hexToBytes(gwHex)
				if err != nil {
					continue // 如果网关解析失败，跳过此条目
				}
				gateway := net.IP(gwBytes)

				// 如果网关是 0.0.0.0，说明是本地网络，下一跳是目标 IP 本身
				if gateway.Equal(net.IPv4zero) {
					bestMatchNextHop = destIP
				} else {
					bestMatchNextHop = gateway
				}
			}
		}
	}

	if bestMatchNextHop != nil {
		return bestMatchNextHop, nil
	}

	return nil, fmt.Errorf("无法解析目标 IP %s 的下一跳", destIP.String())
}

// resolveMACFromARPTable 从 ARP 表中解析 MAC 地址
// 这将通过读取 /proc/net/arp 来模拟 ARP 表查询
func resolveMACFromARPTable(ip net.IP) (net.HardwareAddr, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("无法打开 /proc/net/arp: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // 跳过标题行

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		// IP address (IP 地址)
		arpIP := net.ParseIP(fields[0]) // IP address is the first field
		if arpIP == nil || !arpIP.Equal(ip) {
			continue
		}

		// MAC address (MAC 地址)
		macStr := fields[3] // MAC address is the fourth field
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			return nil, fmt.Errorf("解析 MAC 地址 %s 时出错: %v", macStr, err)
		}
		return mac, nil
	}

	return nil, fmt.Errorf("在 ARP 表中找不到 IP %s 的 MAC 地址", ip.String())
}

// hexToBytes 将十六进制字符串转换为字节切片 (例如 "0100007F" -> []byte{127, 0, 0, 1})
func hexToBytes(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		return nil, fmt.Errorf("十六进制字符串长度无效: %s", hexStr)
	}
	bytes := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		val, err := strconv.ParseUint(hexStr[i:i+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("解析十六进制字节时出错: %v", err)
		}
		bytes[i/2] = byte(val)
	}
	// 反转字节切片，因为 Linux 路由表是小端序
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
	return bytes, nil
}

// bytesToUint32 将字节切片转换为 uint32
func bytesToUint32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	// net.IPMask 内部是大端序
	return binary.BigEndian.Uint32(b)
}

// resolveDestMAC 解析目标 IP 的目的 MAC 地址
func resolveDestMAC(destIP net.IP) (net.HardwareAddr, error) {
	// 1. 获取下一跳 IP
	nextHopIP, err := resolveNextHopIP(destIP)
	if err != nil {
		return nil, fmt.Errorf("解析下一跳 IP 时出错: %v", err)
	}

	// 2. 从 ARP 表中查找下一跳 IP 的 MAC 地址
	destMAC, err := resolveMACFromARPTable(nextHopIP)
	if err != nil {
		// 如果 ARP 表中没有，可能需要发送 ARP 请求，但目前我们只依赖现有 ARP 表
		return nil, fmt.Errorf("无法从 ARP 表中解析下一跳 IP %s 的 MAC 地址: %v", nextHopIP.String(), err)
	}

	return destMAC, nil
}
