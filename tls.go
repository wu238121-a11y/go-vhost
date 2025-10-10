// Portions of the TLS code are:
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TLS virtual hosting

package vhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
)

const (
	maxPlaintext    = 16384        // maximum plaintext payload length
	maxCiphertext   = 16384 + 2048 // maximum ciphertext payload length
	recordHeaderLen = 5            // record header length
	maxHandshake    = 65536        // maximum handshake we support (protocol max is 16 MB)
)

type alert uint8

const (
	alertUnexpectedMessage alert = 10
	alertRecordOverflow    alert = 22
	alertInternalError     alert = 80
)

var alertText = map[alert]string{
	alertUnexpectedMessage: "unexpected message",
	alertRecordOverflow:    "record overflow",
	alertInternalError:     "internal error",
}

func (e alert) String() string {
	s, ok := alertText[e]
	if ok {
		return s
	}
	return "alert(" + strconv.Itoa(int(e)) + ")"
}

func (e alert) Error() string {
	return e.String()
}

// TLS record types.
type recordType uint8

const (
	recordTypeHandshake recordType = 22
)

// TLS handshake message types.
const (
	typeClientHello uint8 = 1
)

// TLS extension numbers
var (
	extensionServerName      uint16 = 0
	extensionStatusRequest   uint16 = 5
	extensionSupportedCurves uint16 = 10
	extensionSupportedPoints uint16 = 11
	extensionALPN            uint16 = 16
	extensionSessionTicket   uint16 = 35
	extensionNextProtoNeg    uint16 = 13172 // not IANA assigned
)

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP uint8 = 1
)

// A Conn represents a secured connection.
// It implements the net.Conn interface.
type TLSConn struct {
	*sharedConn
	ClientHelloMsg *ClientHelloMsg
	ja4            string // Cache for the full JA4 fingerprint
	ja4A           string // Cache for JA4 part A
	ja4B           string // Cache for JA4 part B
	ja4C           string // Cache for JA4 part C
	ja4Raw         string // Cache for the raw JA4 string
}

// TLS parses the ClientHello message on conn and returns
// a new, unread connection with metadata for virtual host muxing
func TLS(conn net.Conn) (tlsConn *TLSConn, err error) {
	c, rd := newShared(conn)

	tlsConn = &TLSConn{sharedConn: c}
	if tlsConn.ClientHelloMsg, err = readClientHello(rd); err != nil {
		return
	}

	return
}

func (c *TLSConn) Host() string {
	if c.ClientHelloMsg == nil {
		return ""
	}
	return c.ClientHelloMsg.ServerName
}

// computeJA4 ensures JA4 components are calculated and cached.
func (c *TLSConn) computeJA4() {
	if c.ja4 != "" {
		return // Already computed
	}
	if c.ClientHelloMsg == nil {
		return
	}
	c.ja4A, c.ja4B, c.ja4C, c.ja4Raw = calculateJA4Components(c.ClientHelloMsg)
	c.ja4 = c.ja4A + "_" + c.ja4B + "_" + c.ja4C
}

// JA4 returns the full JA4 fingerprint.
func (c *TLSConn) JA4() string {
	c.computeJA4()
	return c.ja4
}

// JA4A returns the 'A' component of the JA4 fingerprint.
func (c *TLSConn) JA4A() string {
	c.computeJA4()
	return c.ja4A
}

// JA4B returns the 'B' component of the JA4 fingerprint.
func (c *TLSConn) JA4B() string {
	c.computeJA4()
	return c.ja4B
}

// JA4C returns the 'C' component of the JA4 fingerprint.
func (c *TLSConn) JA4C() string {
	c.computeJA4()
	return c.ja4C
}

// JA4Raw returns the raw concatenated string used in JA4 calculation
// for debugging or verification purposes.
func (c *TLSConn) JA4Raw() string {
	c.computeJA4()
	return c.ja4Raw
}

func (c *TLSConn) Free() {
	c.ClientHelloMsg = nil
	c.ja4 = ""
	c.ja4A = ""
	c.ja4B = ""
	c.ja4C = ""
	c.ja4Raw = ""
}

// calculateJA4Components computes the JA4 fingerprint components and raw string from a ClientHello message
// based on the specification at https://foxio.io/ja4/
func calculateJA4Components(msg *ClientHelloMsg) (ja4A, ja4B, ja4C, ja4Raw string) {
	// Transport (hardcoded to t for TCP; use q for QUIC if needed)
	q := "t"

	// TLS version - use highest supported if available, else legacy
	d := tlsVersionToString(msg.Vers)
	if len(msg.SupportedVersions) > 0 {
		var maxVer uint16
		for _, ver := range msg.SupportedVersions {
			if ver > maxVer {
				maxVer = ver
			}
		}
		d = tlsVersionToString(maxVer)
	}

	// SNI flag
	s := "0"
	if msg.ServerName != "" {
		if isDomain(msg.ServerName) {
			s = "d"
		} else {
			s = "i"
		}
	}

	// Filter GREASE
	isGrease := func(v uint16) bool {
		return (v & 0x0f0f) == 0x0a0a
	}

	// Sorted, filtered ciphers
	ciphers := []uint16{}
	for _, suite := range msg.CipherSuites {
		if !isGrease(suite) {
			ciphers = append(ciphers, suite)
		}
	}
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	cipherStr := []string{}
	for _, suite := range ciphers {
		cipherStr = append(cipherStr, fmt.Sprintf("%04x", suite))
	}
	cipherStrJoined := strings.Join(cipherStr, ",")

	// Hash for b
	hashB := sha256.Sum256([]byte(cipherStrJoined))
	ja4B = hex.EncodeToString(hashB[:6])

	// Sorted, filtered extensions
	exts := []uint16{}
	for _, ext := range msg.Extensions {
		if !isGrease(ext) {
			exts = append(exts, ext)
		}
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })

	// ALPN
	alpn := append([]string{}, msg.AlpnProtocols...)
	sort.Strings(alpn)
	alpnStrJoined := strings.Join(alpn, ",")
	alpnFirst2 := "00"
	if len(alpn) > 0 {
		first := strings.ToLower(alpn[0])
		if len(first) >= 2 {
			alpnFirst2 = first[0:2]
		} else {
			alpnFirst2 = first + "0"
		}
	}

	// Sorted, filtered sigalgs
	sigalgs := []uint16{}
	for _, alg := range msg.SignatureAlgorithms {
		if !isGrease(alg) {
			sigalgs = append(sigalgs, alg)
		}
	}
	sort.Slice(sigalgs, func(i, j int) bool { return sigalgs[i] < sigalgs[j] })
	sigStr := []string{}
	for _, alg := range sigalgs {
		sigStr = append(sigStr, fmt.Sprintf("%04x", alg))
	}
	sigStrJoined := strings.Join(sigStr, ",")

	// Sorted, filtered curves
	curves := []uint16{}
	for _, curve := range msg.SupportedCurves {
		if !isGrease(curve) {
			curves = append(curves, curve)
		}
	}
	sort.Slice(curves, func(i, j int) bool { return curves[i] < curves[j] })
	curvesStr := []string{}
	for _, curve := range curves {
		curvesStr = append(curvesStr, fmt.Sprintf("%04x", curve))
	}
	curvesStrJoined := strings.Join(curvesStr, ",")

	// Sorted points
	pointsStr := []string{}
	for _, point := range msg.SupportedPoints {
		pointsStr = append(pointsStr, fmt.Sprintf("%02x", point))
	}
	pointsStrJoined := strings.Join(pointsStr, ",")

	// Sorted, filtered versions
	versions := []uint16{}
	for _, ver := range msg.SupportedVersions {
		if !isGrease(ver) {
			versions = append(versions, ver)
		}
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	versionsStr := []string{}
	for _, ver := range versions {
		versionsStr = append(versionsStr, fmt.Sprintf("%04x", ver))
	}
	versionsStrJoined := strings.Join(versionsStr, ",")

	// Raw for c hash
	cRaw := alpnStrJoined
	if sigStrJoined != "" {
		cRaw += "_" + sigStrJoined
	}
	if curvesStrJoined != "" {
		cRaw += "_" + curvesStrJoined
	}
	if pointsStrJoined != "" {
		cRaw += "_" + pointsStrJoined
	}
	if versionsStrJoined != "" {
		cRaw += "_" + versionsStrJoined
	}

	// Hash for c
	hashC := sha256.Sum256([]byte(cRaw))
	ja4C = hex.EncodeToString(hashC[:6])

	// Part a
	numCiphers := fmt.Sprintf("%02d", len(ciphers))
	numExt := fmt.Sprintf("%02d", len(exts))
	ja4A = q + d + s + numCiphers + numExt + alpnFirst2

	// Raw string for debugging
	ja4Raw = ja4A + "_" + cipherStrJoined + "_" + cRaw

	return ja4A, ja4B, ja4C, ja4Raw
}

// tlsVersionToString converts TLS version to JA4 format
func tlsVersionToString(version uint16) string {
	switch version {
	case 0x0301:
		return "10"
	case 0x0302:
		return "11"
	case 0x0303:
		return "12"
	case 0x0304:
		return "13"
	default:
		return fmt.Sprintf("%02x", version-0x0300)
	}
}

// isDomain checks if a string is a domain name (not an IP)
func isDomain(name string) bool {
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

// A block is a simple data buffer.
type block struct {
	data []byte
	off  int // index for Read
}

// resize resizes block to be n bytes, growing if necessary.
func (b *block) resize(n int) {
	if n > cap(b.data) {
		b.reserve(n)
	}
	b.data = b.data[0:n]
}

// reserve makes sure that block contains a capacity of at least n bytes.
func (b *block) reserve(n int) {
	if cap(b.data) >= n {
		return
	}
	m := cap(b.data)
	if m == 0 {
		m = 1024
	}
	for m < n {
		m *= 2
	}
	data := make([]byte, len(b.data), m)
	copy(data, b.data)
	b.data = data
}

// readFromUntil reads from r into b until b contains at least n bytes
// or else returns an error.
func (b *block) readFromUntil(r io.Reader, n int) error {
	// quick case
	if len(b.data) >= n {
		return nil
	}

	// read until have enough.
	b.reserve(n)
	for {
		m, err := r.Read(b.data[len(b.data):cap(b.data)])
		b.data = b.data[0 : len(b.data)+m]
		if len(b.data) >= n {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *block) Read(p []byte) (n int, err error) {
	n = copy(p, b.data[b.off:])
	b.off += n
	return
}

// newBlock allocates a new block
func newBlock() *block {
	return new(block)
}

// splitBlock splits a block after the first n bytes,
// returning a block with those n bytes and a
// block with the remainder.  the latter may be nil.
func splitBlock(b *block, n int) (*block, *block) {
	if len(b.data) <= n {
		return b, nil
	}
	bb := newBlock()
	bb.resize(len(b.data) - n)
	copy(bb.data, b.data[n:])
	b.data = b.data[0:n]
	return b, bb
}

// readHandshake reads the next handshake message from
// the record layer.
func readClientHello(rd io.Reader) (*ClientHelloMsg, error) {
	var nextBlock *block  // raw input, right off the wire
	var hand bytes.Buffer // handshake data waiting to be read

	// readRecord reads the next TLS record from the connection
	// and updates the record layer state.
	readRecord := func() error {
		// Caller must be in sync with connection:
		// handshake data if handshake not yet completed,
		// else application data.  (We don't support renegotiation.)
		if nextBlock == nil {
			nextBlock = newBlock()
		}
		b := nextBlock

		// Read header, payload.
		if err := b.readFromUntil(rd, recordHeaderLen); err != nil {
			return err
		}

		typ := recordType(b.data[0])

		// No valid TLS record has a type of 0x80, however SSLv2 handshakes
		// start with a uint16 length where the MSB is set and the first record
		// is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
		// an SSLv2 client.
		if typ == 0x80 {
			err := errors.New("tls: unsupported SSLv2 handshake received")
			return err
		}

		vers := uint16(b.data[1])<<8 | uint16(b.data[2])
		n := int(b.data[3])<<8 | int(b.data[4])
		if n > maxCiphertext {
			err := alertRecordOverflow
			return err
		}

		// First message, be extra suspicious:
		// this might not be a TLS client.
		// Bail out before reading a full 'body', if possible.
		// The current max version is 3.4 (TLS 1.3).
		// If the version is >= 16.0, it's probably not real.
		// Modern browsers can send large ClientHello messages with many extensions.
		if typ != recordTypeHandshake {
			err := alertUnexpectedMessage
			return err
		}
		if vers >= 0x1000 {
			err := alertUnexpectedMessage
			return err
		}

		if err := b.readFromUntil(rd, recordHeaderLen+n); err != nil {
			return err
		}

		// Process message.
		b, nextBlock = splitBlock(b, recordHeaderLen+n)
		b.off = recordHeaderLen
		data := b.data[b.off:]
		if len(data) > maxPlaintext {
			err := alertRecordOverflow
			return err
		}

		// DEBUG: show first bytes of the record payload we append to handshake buffer
		show := 32
		if len(data) < show {
			show = len(data)
		}

		hand.Write(data)
		return nil
	}

	if err := readRecord(); err != nil {
		return nil, err
	}

	data := hand.Bytes()
	if len(data) < 4 {
		err := alertUnexpectedMessage
		return nil, err
	}
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshake {
		err := alertInternalError
		return nil, err
	}
	for hand.Len() < 4+n {
		if err := readRecord(); err != nil {
			return nil, err
		}
	}

	data = hand.Next(4 + n)
	if data[0] != typeClientHello {
		err := alertUnexpectedMessage
		return nil, err
	}

	msg := new(ClientHelloMsg)
	if !msg.unmarshal(data) {
		err := alertUnexpectedMessage
		return nil, err
	}
	return msg, nil
}

type ClientHelloMsg struct {
	Raw                 []byte
	Vers                uint16
	Random              []byte
	SessionId           []byte
	CipherSuites        []uint16
	CompressionMethods  []uint8
	NextProtoNeg        bool
	ServerName          string
	OcspStapling        bool
	SupportedCurves     []uint16
	SupportedPoints     []uint8
	TicketSupported     bool
	SessionTicket       []uint8
	AlpnProtocols       []string
	SignatureAlgorithms []uint16
	SupportedVersions   []uint16
	Extensions          []uint16
}

func (m *ClientHelloMsg) unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}
	m.Raw = data
	m.Vers = uint16(data[4])<<8 | uint16(data[5])
	m.Random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return false
	}
	m.SessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 2 {
		return false
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return false
	}
	numCipherSuites := cipherSuiteLen / 2
	m.CipherSuites = make([]uint16, numCipherSuites)
	for i := 0; i < numCipherSuites; i++ {
		m.CipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return false
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return false
	}
	m.CompressionMethods = data[1 : 1+compressionMethodsLen]

	data = data[1+compressionMethodsLen:]

	m.NextProtoNeg = false
	m.ServerName = ""
	m.OcspStapling = false
	m.TicketSupported = false
	m.SessionTicket = nil
	m.AlpnProtocols = nil
	m.SignatureAlgorithms = nil
	m.SupportedVersions = nil
	m.Extensions = nil

	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		return true
	}
	if len(data) < 2 {
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		if extensionsLength > len(data) {
			return false
		}
		// Proceed but only parse the declared extensionsLength bytes
		data = data[:extensionsLength]
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}

		m.Extensions = append(m.Extensions, extension)

		switch extension {
		case extensionServerName:
			if length < 2 {
			} else {
				numNames := int(data[0])<<8 | int(data[1])
				d := data[2:]
				foundName := false
				for i := 0; i < numNames; i++ {
					if len(d) < 3 {
						break
					}
					nameType := d[0]
					nameLen := int(d[1])<<8 | int(d[2])
					d = d[3:]
					if len(d) < nameLen {
						break
					}
					if nameType == 0 {
						m.ServerName = string(d[0:nameLen])
						foundName = true
						break
					}
					d = d[nameLen:]
				}
				if !foundName {
					// No valid host name found, but continue parsing other extensions
				}
			}
		case extensionNextProtoNeg:
			if length > 0 {
			} else {
				m.NextProtoNeg = true
			}
		case extensionStatusRequest:
			m.OcspStapling = length > 0 && data[0] == statusTypeOCSP
		case extensionSupportedCurves:
			// http://tools.ietf.org/html/rfc4492#section-5.5.1
			if length < 2 {
			} else {
				l := int(data[0])<<8 | int(data[1])
				if l%2 == 1 || length != l+2 {
				} else {
					numCurves := l / 2
					m.SupportedCurves = make([]uint16, numCurves)
					d := data[2:]
					for i := 0; i < numCurves; i++ {
						m.SupportedCurves[i] = uint16(d[0])<<8 | uint16(d[1])
						d = d[2:]
					}
				}
			}
		case extensionSupportedPoints:
			// http://tools.ietf.org/html/rfc4492#section-5.5.2
			if length < 1 {
			} else {
				l := int(data[0])
				if length != l+1 {
				} else {
					m.SupportedPoints = make([]uint8, l)
					copy(m.SupportedPoints, data[1:])
				}
			}
		case extensionSessionTicket:
			// http://tools.ietf.org/html/rfc5077#section-3.2
			m.TicketSupported = true
			m.SessionTicket = data[:length]
		case extensionALPN:
			if length < 2 {
			} else {
				l := int(data[0])<<8 | int(data[1])
				if l != length-2 {
				} else {
					d := data[2:length]
					for len(d) != 0 {
						stringLen := int(d[0])
						d = d[1:]
						if stringLen == 0 || stringLen > len(d) {
							break
						}
						protocol := string(d[:stringLen])
						m.AlpnProtocols = append(m.AlpnProtocols, protocol)
						d = d[stringLen:]
					}
				}
			}
		case 13: // extension signature_algorithms
			if length < 2 {
			} else {
				l := int(data[0])<<8 | int(data[1])
				if l%2 == 1 || l+2 != length {
				} else {
					num := l / 2
					m.SignatureAlgorithms = make([]uint16, num)
					d := data[2:]
					for i := 0; i < num; i++ {
						m.SignatureAlgorithms[i] = uint16(d[0])<<8 | uint16(d[1])
						d = d[2:]
					}
				}
			}
		case 43: // extension supported_versions
			if length < 1 {
			} else {
				l := int(data[0])
				if l%2 == 1 || l+1 != length {
				} else {
					num := l / 2
					m.SupportedVersions = make([]uint16, num)
					d := data[1:]
					for i := 0; i < num; i++ {
						m.SupportedVersions[i] = uint16(d[0])<<8 | uint16(d[1])
						d = d[2:]
					}
				}
			}
		default:
		}
		data = data[length:]
	}

	return true
}
