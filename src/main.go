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
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
)

// 版本信息，在编译时通过 ldflags 注入
var version = "dev"

// 命令行参数的全局变量
var (
	srcIPStr   = flag.String("srcIP", "", "源IP地址 (IPv4 或 IPv6)")
	targetSpec = flag.String("target", "", "目标IP地址，支持CIDR (10.0.0.0/24), 范围 (10.0.0.1-10.0.0.100), 或单个IP (10.0.0.1) 格式。多个目标请用分号分隔 (例如: \"10.0.1.0/24;192.168.1.0-192.168.1.2;172.16.0.1\")。注意：当使用分号分隔多个目标时，请务必将整个参数值用引号括起来。")
	pcapFile   = flag.String("pcap", "", "用作报文模板的pcap文件路径")
	ifaceName  = flag.String("iface", "", "用于发送和接收报文的网络接口 (例如: eth0)")
	capture    = flag.Bool("capture", false, "启用响应捕获，并将匹配的响应保存到带时间戳的pcap文件中")
	pps        = flag.Int("pps", 0, "每秒发送的报文数量 (0 表示不限制)")
	showVersion = flag.Bool("version", false, "显示版本信息并退出")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("pcap_scanner_go 版本: %s\n", version)
		return
	}

	// 验证所有必需的命令行参数是否已提供
	if *targetSpec == "" || *pcapFile == "" || *ifaceName == "" {
		flag.Usage()
		log.Fatal("错误: 必须提供所有必需的参数 (-target, -pcap, -iface)。")
	}

	var srcIP net.IP
	if *srcIPStr != "" {
		// 解析用户提供的源IP地址
		srcIP = net.ParseIP(*srcIPStr)
		if srcIP == nil {
			log.Fatalf("错误: 无效的源IP地址: %s", *srcIPStr)
		}
	} else {
		// 如果未提供srcIP，则尝试从网络接口获取第一个IPv4地址
		iface, err := net.InterfaceByName(*ifaceName)
		if err != nil {
			log.Fatalf("错误: 无法找到网络接口 %s: %v", *ifaceName, err)
		}

		addrs, err := iface.Addrs()
		if err != nil {
			log.Fatalf("错误: 无法获取接口 %s 的地址: %v", *ifaceName, err)
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil { // 找到第一个IPv4地址
					srcIP = ipnet.IP
					log.Printf("未指定源IP，使用接口 %s 的第一个IPv4地址: %s", *ifaceName, srcIP.String())
					break
				}
			}
		}

		if srcIP == nil {
			log.Fatalf("错误: 在接口 %s 上未找到可用的IPv4地址。请手动指定 -srcIP。", *ifaceName)
		}
	}

	// 生成目标IP地址列表
	targetIPs, err := parseTargetSpec(*targetSpec)
	if err != nil {
		log.Fatalf("错误解析目标IP规范: %v", err)
	}
	if len(targetIPs) == 0 {
		log.Fatal("错误: 未从提供的规范生成任何目标IP。")
	}

	// 从pcap文件中读取报文模板
	templates, err := readPcapTemplates(*pcapFile)
	if err != nil {
		log.Fatalf("错误读取pcap模板: %v", err)
	}
	if len(templates) == 0 {
		log.Fatal("错误: 在pcap文件中未找到任何有效的IP/IPv6报文模板。")
	}

	// 设置发送和捕获的同步机制
	var wg sync.WaitGroup
	sentSessions := make(map[SessionKey]struct{}) // 用于跟踪已发送报文的5元组，以便匹配响应
	var mu sync.Mutex                             // 用于保护sentSessions map的互斥锁

	// 用于通知发送器完成的通道
	senderDone := make(chan struct{})

	// 如果启用了捕获功能，则启动监听器goroutine
	if *capture {
		wg.Add(1)
		go listenForResponses(&wg, *ifaceName, srcIP, sentSessions, &mu, senderDone)
	}

	// 启动发送器goroutine
	wg.Add(1)
	go sendPackets(&wg, *ifaceName, srcIP, targetIPs, templates, sentSessions, &mu, senderDone, *capture, *pps)

	// 等待所有goroutine完成
	wg.Wait()
	log.Println("扫描完成。")
}
