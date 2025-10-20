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
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// sendPackets 向目标IP发送报文
func sendPackets(wg *sync.WaitGroup, ifaceName string, srcIP net.IP, targetIPs []net.IP, templates []gopacket.Packet, sentSessions map[SessionKey]struct{}, mu *sync.Mutex, senderDone chan struct{}, captureEnabled bool, pps int) {
	defer wg.Done()
	defer close(senderDone)

	// 获取源 MAC 地址
	srcMAC, err := getInterfaceMAC(ifaceName)
	if err != nil {
		log.Fatalf("获取接口 %s 的 MAC 地址时出错: %v", ifaceName, err)
	}

	// 打开网络接口进行发送
	handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("打开接口 %s 进行发送时出错: %v", ifaceName, err)
	}
	defer handle.Close()

	log.Printf("开始从 %s 向 %d 个目标IP发送报文...", srcIP.String(), len(targetIPs))

	var ticker *time.Ticker
	if pps > 0 {
		// 计算每个报文的发送间隔
		packetInterval := time.Second / time.Duration(pps)
		ticker = time.NewTicker(packetInterval)
		defer ticker.Stop()
		log.Printf("发包速率限制为每秒 %d 个报文。", pps)
	} else {
		log.Println("未设置发包速率限制。")
	}

	for _, targetIP := range targetIPs {
		// 解析目标 MAC 地址
		destMAC, err := resolveDestMAC(ifaceName, targetIP)
		if err != nil {
			log.Printf("解析目标 IP %s 的 MAC 地址时出错: %v, 跳过此目标。", targetIP.String(), err)
			continue
		}

		for _, templatePacket := range templates {
			// 如果设置了速率限制，则等待下一个滴答
			if pps > 0 {
				<-ticker.C
			}

			// 从模板创建新报文以进行修改
			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{
				FixLengths:       true, // 自动修正长度字段
				ComputeChecksums: true, // 自动计算校验和
			}

			// 从模板中提取各层
			var ip4Layer *layers.IPv4
			var ip6Layer *layers.IPv6
			var tcpLayer *layers.TCP
			var udpLayer *layers.UDP

			for _, layer := range templatePacket.Layers() {
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

			// 修改IP层
			if ip4Layer != nil {
				ip4Layer.SrcIP = srcIP
				ip4Layer.DstIP = targetIP
				ip4Layer.Checksum = 0 // gopacket将重新计算
			} else if ip6Layer != nil {
				ip6Layer.SrcIP = srcIP
				ip6Layer.DstIP = targetIP
			} else {
				log.Printf("警告: 报文模板没有IPv4或IPv6层，跳过此报文的修改。")
				continue
			}

			// 关联网络层以计算校验和，并重置校验和字段
			if tcpLayer != nil {
				if ip4Layer != nil {
					tcpLayer.SetNetworkLayerForChecksum(ip4Layer)
				} else if ip6Layer != nil {
					tcpLayer.SetNetworkLayerForChecksum(ip6Layer)
				}
				tcpLayer.Checksum = 0 // 强制gopacket重新计算校验和
			} else if udpLayer != nil {
				if ip4Layer != nil {
					udpLayer.SetNetworkLayerForChecksum(ip4Layer)
				} else if ip6Layer != nil {
					udpLayer.SetNetworkLayerForChecksum(ip6Layer)
				}
				udpLayer.Checksum = 0 // 强制gopacket重新计算校验和
			}

			// 构建新的以太网层
			ethLayer := &layers.Ethernet{
				SrcMAC: srcMAC,
				DstMAC: destMAC,
				EthernetType: layers.EthernetTypeIPv4, // 假设是IPv4，如果需要IPv6，则需要根据实际情况判断
			}
			if ip6Layer != nil {
				ethLayer.EthernetType = layers.EthernetTypeIPv6
			}

			// 重新序列化报文
			// 构建要序列化的层列表
			var layersToSerialize []gopacket.SerializableLayer
			layersToSerialize = append(layersToSerialize, ethLayer)
			if ip4Layer != nil {
				layersToSerialize = append(layersToSerialize, ip4Layer)
			}
			if ip6Layer != nil {
				layersToSerialize = append(layersToSerialize, ip6Layer)
			}
			if tcpLayer != nil {
				layersToSerialize = append(layersToSerialize, tcpLayer)
			}
			if udpLayer != nil {
				layersToSerialize = append(layersToSerialize, udpLayer)
			}

			// 添加应用层载荷（如果存在）
			if appLayer := templatePacket.ApplicationLayer(); appLayer != nil {
				layersToSerialize = append(layersToSerialize, gopacket.Payload(appLayer.Payload()))
			}

			// 重新序列化报文
			err = gopacket.SerializeLayers(buffer, options, layersToSerialize...)
			if err != nil {
				log.Printf("序列化报文时出错: %v", err)
				continue
			}

			// 如果启用了捕获功能，则存储会话键
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

			// 发送报文
			if err := handle.WritePacketData(buffer.Bytes()); err != nil {
				log.Printf("发送报文时出错: %v", err)
			} else {
				// log.Printf("已从 %s 发送报文到 %s", srcIP.String(), targetIP.String())
			}
			// 如果未设置速率限制，则保留小延迟以避免网络过载
			if pps == 0 {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	log.Println("发送器完成所有报文发送。")
}
