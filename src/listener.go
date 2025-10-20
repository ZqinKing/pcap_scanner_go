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
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// listenForResponses 监听传入报文并保存匹配的响应
func listenForResponses(wg *sync.WaitGroup, ifaceName string, srcIP net.IP, sentSessions map[SessionKey]struct{}, mu *sync.Mutex, senderDone chan struct{}) {
	defer wg.Done()

	// 打开网络接口进行捕获
	handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("打开接口 %s 进行捕获时出错: %v", ifaceName, err)
	}
	defer handle.Close()

	// 应用BPF过滤器，只捕获发往我们源IP的流量
	filter := fmt.Sprintf("dst host %s", srcIP.String())
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("设置BPF过滤器时出错: %v", err)
	}
	log.Printf("正在 %s 上监听响应，过滤器: %s", ifaceName, filter)

	// 为响应创建pcap写入器
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	outputPcapFile := fmt.Sprintf("capture_%s.pcap", timestamp)
	f, err := os.Create(outputPcapFile)
	if err != nil {
		log.Fatalf("创建输出pcap文件时出错: %v", err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(uint32(1600), handle.LinkType()); err != nil {
		log.Fatalf("写入pcap文件头时出错: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// 循环捕获报文
	for {
		select {
		case packet := <-packetSource.Packets():
			// 解析传入报文
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

			// 构造反向会话键
			var incomingKey SessionKey
			if ip4Layer != nil {
				incomingKey.SrcIP = ip4Layer.DstIP.String() // 我们发送的目标IP现在是它们的源IP
				incomingKey.DstIP = ip4Layer.SrcIP.String() // 我们发送的源IP现在是它们的目标IP
				incomingKey.Proto = ip4Layer.Protocol
			} else if ip6Layer != nil {
				incomingKey.SrcIP = ip6Layer.DstIP.String()
				incomingKey.DstIP = ip6Layer.SrcIP.String()
				incomingKey.Proto = ip6Layer.NextHeader
			} else {
				continue // 不是IP报文，忽略
			}

			if tcpLayer != nil {
				incomingKey.SrcPort = uint16(tcpLayer.DstPort) // 我们发送的目标端口现在是它们的源端口
				incomingKey.DstPort = uint16(tcpLayer.SrcPort) // 我们发送的源端口现在是它们的目标端口
			} else if udpLayer != nil {
				incomingKey.SrcPort = uint16(udpLayer.DstPort)
				incomingKey.DstPort = uint16(udpLayer.SrcPort)
			}

			// 检查这是否是我们发送的报文的响应
			mu.Lock()
			_, found := sentSessions[incomingKey]
			mu.Unlock()

			if found {
				log.Printf("匹配到来自 %s 到 %s 的响应。保存到 %s", incomingKey.DstIP, incomingKey.SrcIP, outputPcapFile)
				if err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
					log.Printf("写入pcap文件时出错: %v", err)
				}
				// 可选: 从map中删除以避免同一会话的重复匹配
				// mu.Lock()
				// delete(sentSessions, incomingKey)
				// mu.Unlock()
			}

		case <-senderDone:
			// 发送器已完成，等待一些延迟的响应，然后退出
			log.Println("发送器完成。等待最终响应...")
			time.Sleep(5 * time.Second) // 留出一些时间给最后的响应
			log.Println("监听器正在关闭。")
			return
		}
	}
}
