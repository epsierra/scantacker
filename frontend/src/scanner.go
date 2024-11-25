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

type PacketSummary struct {
	ID              uuid.UUID
	Timestamp       time.Time
	SrcIP           string
	DstIP           string
	SrcPort         uint16
	DstPort         uint16
	Protocol        string
	Length          int
	ReadableSummary string
	Bytes           []byte
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

	// Set the BPF filter
	err = handle.SetBPFFilter(bpf)
	if err != nil {
		log.Printf("Error setting BPF filter: %v\n", err)
		return
	}

	// Capture packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Extract detailed information
		summary := extractPacketSummary(packet)
		// fmt.Print("Summary", summary)
		// Emit the packet summary to the frontend
		runtime.EventsEmit(ctx, "packet", summary)
	}
}

func extractPacketSummary(packet gopacket.Packet) PacketSummary {
	var summary PacketSummary

	defer func() {
		err := recover()
		if err != nil {
			// do nothing
		}
	}()

	summary.ID = uuid.New()

	// Set timestamp
	summary.Timestamp = packet.Metadata().Timestamp

	// Get the packet length
	summary.Length = len(packet.Data())

	// Store raw bytes
	summary.Bytes = packet.Data()

	// Parse layers
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		src, dst := netLayer.NetworkFlow().Endpoints()
		summary.SrcIP = src.String()
		summary.DstIP = dst.String()
	}

	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		src, dst := transportLayer.TransportFlow().Endpoints()
		summary.SrcPort = uint16(src.EndpointType())
		summary.DstPort = uint16(dst.EndpointType())

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

	// Add a readable summary
	summary.ReadableSummary = fmt.Sprintf(
		"%s -> %s [%s] (%d bytes)",
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
