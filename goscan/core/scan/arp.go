package scan

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ARPResult represents the result of an ARP scan
type ARPResult struct {
	IP        string
	MAC       string
	Timestamp time.Time
}

// ARPScanner handles ARP scanning operations
type ARPScanner struct {
	Interface *net.Interface
	Results   []ARPResult
}

// NewARPScanner creates a new ARP scanner instance
func NewARPScanner(iface *net.Interface) *ARPScanner {
	return &ARPScanner{
		Interface: iface,
		Results:   make([]ARPResult, 0),
	}
}

// Scan performs an ARP scan on the specified network
func (s *ARPScanner) Scan(network *net.IPNet) error {
	// Get the first IP in the network
	ip := network.IP.To4()
	if ip == nil {
		return fmt.Errorf("not an IPv4 network")
	}

	// Create a new packet handle
	handle, err := pcap.OpenLive(s.Interface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("error opening interface: %v", err)
	}
	defer handle.Close()

	// Create ARP packet
	eth := layers.Ethernet{
		SrcMAC:       s.Interface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.Interface.HardwareAddr),
		SourceProtAddress: []byte(ip),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(ip),
	}

	// Set up buffer and options for serialization
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Serialize the packet
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return fmt.Errorf("error serializing packet: %v", err)
	}

	// Send the packet
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return fmt.Errorf("error sending packet: %v", err)
	}

	// Set up packet capture
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(5 * time.Second)

	// Listen for ARP responses
	for {
		select {
		case packet := <-packetSource.Packets():
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp := arpLayer.(*layers.ARP)
				if arp.Operation == layers.ARPReply {
					result := ARPResult{
						IP:        net.IP(arp.SourceProtAddress).String(),
						MAC:       net.HardwareAddr(arp.SourceHwAddress).String(),
						Timestamp: time.Now(),
					}
					s.Results = append(s.Results, result)
				}
			}
		case <-timeout:
			return nil
		}
	}
}

// GetResults returns the ARP scan results
func (s *ARPScanner) GetResults() []ARPResult {
	return s.Results
} 