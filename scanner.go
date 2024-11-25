package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/uuid"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

var cancelScan = make(chan bool)
var cleanUp = make(chan bool)

type PacketSummary struct {
	ID           uuid.UUID
	Timestamp    time.Time
	SrcIP        string
	DstIP        string
	SrcPort      uint16
	DstPort      uint16
	SrcMac       string
	DstMac       string
	SeqNumber    uint32
	Protocol     string
	Length       int
	Info         string
	ReadableData string
	Bytes        []byte
}

func ScanDevice(device, bpf string, ctx context.Context) {
	snapshotLen := int32(4096)
	promiscuous := false
	timeout := 30 * time.Second

	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Printf("Error opening device: %v\n", err)
		return
	}
	defer handle.Close()

	if bpf != "all" {
		// Set the BPF filter
		err = handle.SetBPFFilter(bpf)
		if err != nil {
			log.Printf("Error setting BPF filter: %v\n", err)
			return
		}
	}

	// Capture packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			summary := extractPacketSummary(packet)
			// fmt.Print("Summary", summary)
			// Emit the packet summary to the frontend
			runtime.EventsEmit(ctx, "packet", summary)
		case <-cancelScan:
			return

		case <-cleanUp:
			return
		}
	}
}

func extractPacketSummary(packet gopacket.Packet) PacketSummary {
	var summary PacketSummary

	defer func() {
		err := recover()
		if err != nil {
			// Log and recover from potential parsing issues
			log.Printf("Error parsing packet: %v\n", err)
		}
	}()

	summary.ID = uuid.New()

	// Set timestamp
	summary.Timestamp = packet.Metadata().Timestamp

	// Get the packet length
	summary.Length = len(packet.Data())

	// Store raw bytes
	summary.Bytes = packet.Data()

	// Parse network layer for IP and MAC information
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		src, dst := netLayer.NetworkFlow().Endpoints()
		summary.SrcIP = src.String()
		summary.DstIP = dst.String()
	}

	// Parse Ethernet layer for MAC addresses
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		summary.SrcMac = eth.SrcMAC.String()
		summary.DstMac = eth.DstMAC.String()
	}

	// Parse TCP layer for detailed info
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		summary.SrcPort = uint16(tcp.SrcPort)
		summary.DstPort = uint16(tcp.DstPort)
		summary.SeqNumber = tcp.Seq

		// Detect SYN/ACK
		if tcp.SYN && tcp.ACK {
			summary.Info = "SYN/ACK Packet"
		} else if tcp.SYN {
			summary.Info = "SYN Packet"
		} else if tcp.ACK {
			summary.Info = "ACK Packet"
		} else {
			summary.Info = "TCP Packet"
		}
	}

	// Determine the transport protocol
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		switch transportLayer.LayerType() {
		case layers.LayerTypeTCP:
			summary.Protocol = "TCP"
		case layers.LayerTypeUDP:
			summary.Protocol = "UDP"
		case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
			summary.Protocol = "ICMP"
		default:
			summary.Protocol = transportLayer.LayerType().String()
		}
	}

	// Create a readable summary
	summary.ReadableData = packet.Dump()

	// Add a general readable info
	summary.Info = fmt.Sprintf(
		"%s %s -> %s [%s] (%d bytes)",
		summary.Info,
		summary.SrcIP,
		summary.DstIP,
		summary.Protocol,
		summary.Length,
	)

	return summary
}

func FindDevices() ([]pcap.Interface, error) {
	interfaces, err := pcap.FindAllDevs()
	return interfaces, err
}
