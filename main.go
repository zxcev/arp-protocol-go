package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
	"unsafe"
)

const (
	ETH_P_ALL = 0x0003
	ETH_P_ARP = 0x0806
)

type ARPHeader struct {
	HWType    uint16
	ProtoType uint16
	HWSize    uint8
	ProtoSize uint8
	OpCode    uint16
	SenderMAC [6]byte
	SenderIP  [4]byte
	TargetMAC [6]byte
	TargetIP  [4]byte
}

func main() {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ETH_P_ALL)))
	if err != nil {
		log.Fatal("Socket error:", err)
	}
	defer syscall.Close(fd)

	iface, err := net.InterfaceByName("eth0") // 사용할 인터페이스 이름으로 변경하세요
	if err != nil {
		log.Fatal("InterfaceByName error:", err)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(ETH_P_ALL),
		Ifindex:  iface.Index,
	}

	err = syscall.Bind(fd, &addr)
	if err != nil {
		log.Fatal("Bind error:", err)
	}

	buf := make([]byte, 1500)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			log.Println("Recvfrom error:", err)
			continue
		}

		if n < 42 { // 이더넷 헤더(14) + ARP 헤더(28) 최소 크기
			continue
		}

		etherType := binary.BigEndian.Uint16(buf[12:14])
		if etherType == ETH_P_ARP {
			arp := parseARP(buf[14:])
			printARPPacket(arp, n-14) // 이더넷 헤더 크기(14)를 뺀 길이
		}
	}
}

func parseARP(data []byte) ARPHeader {
	var arp ARPHeader
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&arp.HWType))[:], binary.BigEndian.Uint16(data[0:2]))
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&arp.ProtoType))[:], binary.BigEndian.Uint16(data[2:4]))
	arp.HWSize = data[4]
	arp.ProtoSize = data[5]
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&arp.OpCode))[:], binary.BigEndian.Uint16(data[6:8]))
	copy(arp.SenderMAC[:], data[8:14])
	copy(arp.SenderIP[:], data[14:18])
	copy(arp.TargetMAC[:], data[18:24])
	copy(arp.TargetIP[:], data[24:28])
	return arp
}

func printARPPacket(arp ARPHeader, length int) {
	now := time.Now()
	timestamp := now.Format("15:04:05.000000")

	var opString string
	if arp.OpCode == 1 {
		opString = "Request who-has"
	} else if arp.OpCode == 2 {
		opString = "Reply"
	} else {
		opString = fmt.Sprintf("Unknown operation (%d)", arp.OpCode)
	}

	fmt.Printf("%s ARP, %s %s tell %s, length %d\n",
		timestamp,
		opString,
		net.IP(arp.TargetIP[:]),
		net.IP(arp.SenderIP[:]),
		length)
}

func htons(host uint16) uint16 {
	return (host<<8)&0xff00 | host>>8
}
