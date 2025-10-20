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
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// readPcapTemplates 从pcap文件中读取报文并过滤出IP/IPv6报文
func readPcapTemplates(filename string) ([]gopacket.Packet, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("打开pcap文件时出错: %w", err)
	}
	defer handle.Close()

	var templates []gopacket.Packet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if packet.Layer(layers.LayerTypeIPv4) != nil || packet.Layer(layers.LayerTypeIPv6) != nil {
			templates = append(templates, packet)
		} else {
			log.Printf("跳过pcap文件中的非IP/IPv6报文。")
		}
	}
	return templates, nil
}
