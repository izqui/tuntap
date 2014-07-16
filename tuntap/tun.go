// Package tuntap provides a portable interface to create and use
// TUN/TAP virtual network interfaces.
//
// Note that while this package lets you create the interface and pass
// packets to/from it, it does not provide an API to configure the
// interface. Interface configuration is a very large topic and should
// be dealt with separately.
package tuntap

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	_ "unsafe"
)

type DevKind int

const (
	// Receive/send layer routable 3 packets (IP, IPv6...). Notably,
	// you don't receive link-local multicast with this interface
	// type.
	DevTun DevKind = iota
	// Receive/send Ethernet II frames. You receive all packets that
	// would be visible on an Ethernet link, including broadcast and
	// multicast traffic.
	DevTap
)

const (
	ipHeaderLength = 40
	ipHeaderMeta   = 4
)

type IPPacket struct {
	// The Ethernet type of the packet. Commonly seen values are
	// 0x8000 for IPv4 and 0x86dd for IPv6.
	Protocol int
	// True if the packet was too large to be read completely.
	Truncated bool
	// The raw bytes of the Ethernet payload (for DevTun) or the full
	// Ethernet frame (for DevTap).
	Header  IPHeader
	Payload []byte
}

type IPHeader struct {
	Data []byte
}

func (h IPHeader) Version() int {

	i := h.Data[0] >> 4

	return int(i)
}

type Interface struct {
	name string
	//file net.Conn
	file *os.File
	meta bool
}

// Disconnect from the tun/tap interface.
//
// If the interface isn't configured to be persistent, it is
// immediately destroyed by the kernel.
func (t *Interface) Close() error {
	return t.file.Close()
}

// The name of the interface. May be different from the name given to
// Open(), if the latter was a pattern.
func (t *Interface) Name() string {
	return t.name
}

// Read a single packet from the kernel.
func (t *Interface) ReadPacket() (*IPPacket, error) {
	buf := make([]byte, 10000)

	n, err := t.file.Read(buf)
	if err != nil {
		return nil, err
	}

	var pkt *IPPacket

	start := 0
	if t.meta {
		start = ipHeaderMeta
	}

	if n < start+ipHeaderLength {

		return nil, errors.New("Not a IPv6 packet")
	}

	pkt = &IPPacket{Header: IPHeader{Data: buf[start : start+ipHeaderLength]}, Payload: buf[start+ipHeaderLength : n]}

	/*pkt.Protocol = int(binary.BigEndian.Uint16(buf[2:4]))
	flags := int(*(*uint16)(unsafe.Pointer(&buf[0])))
	if flags&flagTruncated != 0 {
		pkt.Truncated = true
	}*/

	return pkt, nil
}

// Send a single packet to the kernel.
func (t *Interface) WritePacket(pkt *IPPacket) error {
	// If only we had writev(), I could do zero-copy here...
	buf := make([]byte, len(pkt.Payload)+4)
	binary.BigEndian.PutUint16(buf[2:4], uint16(pkt.Protocol))
	copy(buf[4:], pkt.Payload)

	var n int
	var err error
	if t.meta {
		n, err = t.file.Write(buf)
	} else {
		n, err = t.file.Write(pkt.Payload)
	}
	if err != nil {
		return err
	}
	if n != len(buf) {
		return io.ErrShortWrite
	}
	return nil
}

// Open connects to the specified tun/tap interface.
//
// If the specified device has been configured as persistent, this
// simply looks like a "cable connected" event to observers of the
// interface. Otherwise, the interface is created out of thin air.
//
// ifPattern can be an exact interface name, e.g. "tun42", or a
// pattern containing one %d format specifier, e.g. "tun%d". In the
// latter case, the kernel will select an available interface name and
// create it.
//
// meta determines whether the tun/tap header fields in Packet will be
// used.
//
// Returns a TunTap object with channels to send/receive packets, or
// nil and an error if connecting to the interface failed.
func Open(ifPattern string, kind DevKind, meta bool) (*Interface, error) {
	file, err := openDevice(ifPattern)
	if err != nil {
		return nil, err
	}

	ifName, err := createInterface(file, ifPattern, kind, meta)
	if err != nil {
		file.Close()
		return nil, err
	}

	return &Interface{ifName, file, meta}, nil
}
