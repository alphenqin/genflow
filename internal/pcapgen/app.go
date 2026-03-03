package pcapgen

import (
	"bytes"
	"math/rand"

	"github.com/google/gopacket/layers"
)

type appKind string

const (
	appHTTP  appKind = "http"
	appHTTPS appKind = "https"
	appDNS   appKind = "dns"
	appQUIC  appKind = "quic"
	appNTP   appKind = "ntp"
	appSTUN  appKind = "stun"
	appIPSEC appKind = "ipsec"
	appSSDP  appKind = "ssdp"
	appMDNS  appKind = "mdns"
	appSSH   appKind = "ssh"
	appRDP   appKind = "rdp"
	appSMB   appKind = "smb"
	appDB    appKind = "db"
	appOther appKind = "other"
)

func buildAppPayload(r *rand.Rand, plan PacketPlan, isResponse bool, payloadLen int) []byte {
	if payloadLen <= 0 {
		return nil
	}
	app := identifyApp(plan)
	template := appTemplate(app, isResponse)
	if len(template) == 0 {
		return nil
	}
	if len(template) >= payloadLen {
		return template[:payloadLen]
	}
	payload := make([]byte, payloadLen)
	copy(payload, template)
	if _, err := r.Read(payload[len(template):]); err != nil {
		return template
	}
	return payload
}

func identifyApp(plan PacketPlan) appKind {
	switch plan.Proto {
	case layers.IPProtocolUDP:
		switch plan.DstPort {
		case 53:
			return appDNS
		case 443:
			return appQUIC
		case 123:
			return appNTP
		case 3478:
			return appSTUN
		case 500, 4500:
			return appIPSEC
		case 1900:
			return appSSDP
		case 5353:
			return appMDNS
		default:
			return appOther
		}
	case layers.IPProtocolTCP:
		switch plan.DstPort {
		case 80, 8080:
			return appHTTP
		case 443, 8443:
			return appHTTPS
		case 22:
			return appSSH
		case 3389:
			return appRDP
		case 445:
			return appSMB
		case 3306, 5432, 6379:
			return appDB
		default:
			return appOther
		}
	case layers.IPProtocolICMPv4:
		return appOther
	default:
		return appOther
	}
}

func appTemplate(app appKind, isResponse bool) []byte {
	switch app {
	case appHTTP:
		if isResponse {
			return []byte("HTTP/1.1 200 OK\r\nServer: genflux\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, world!")
		}
		return []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: genflux\r\nAccept: */*\r\n\r\n")
	case appHTTPS:
		if isResponse {
			return []byte{0x16, 0x03, 0x03, 0x00, 0x2a, 0x02, 0x00, 0x00, 0x26, 0x03, 0x03, 0x5b, 0x90, 0x11, 0x22, 0x33, 0x44}
		}
		return []byte{0x16, 0x03, 0x01, 0x00, 0x30, 0x01, 0x00, 0x00, 0x2c, 0x03, 0x03, 0x5b, 0x90, 0xaa, 0xbb, 0xcc, 0xdd}
	case appDNS:
		if isResponse {
			return []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01}
		}
		return []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01}
	case appQUIC:
		return []byte("QUIC")
	case appNTP:
		return bytes.Repeat([]byte{0x1b}, 48)
	case appSTUN:
		return []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}
	case appIPSEC:
		return []byte{0x01, 0x10, 0x02, 0x00}
	case appSSDP:
		return []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n")
	case appMDNS:
		return []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case appSSH:
		return []byte("SSH-2.0-OpenSSH_8.2\r\n")
	case appRDP:
		return []byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00}
	case appSMB:
		return []byte{0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00}
	case appDB:
		return []byte("SELECT 1;")
	default:
		return nil
	}
}
