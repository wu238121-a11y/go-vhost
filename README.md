# go-vhost
go-vhost is a simple library that lets you implement virtual hosting functionality for different protocols (HTTP and TLS so far). go-vhost has a high-level and a low-level interface. The high-level interface lets you wrap existing net.Listeners with "muxer" objects. You can then Listen() on a muxer for a particular virtual host name of interest which will return to you a net.Listener for just connections with the virtual hostname of interest.

The lower-level go-vhost interface are just functions which extract the name/routing information for the given protocol and return an object implementing net.Conn which works as if no bytes had been consumed.

### [API Documentation](https://godoc.org/github.com/inconshreveable/go-vhost)

### Usage
```go
l, _ := net.Listen("tcp", *listen)

// start multiplexing on it
mux, _ := vhost.NewHTTPMuxer(l, muxTimeout)

// listen for connections to different domains
for _, v := range virtualHosts {
	vhost := v

	// vhost.Name is a virtual hostname like "foo.example.com"
	muxListener, _ := mux.Listen(vhost.Name())

	go func(vh virtualHost, ml net.Listener) {
		for {
			conn, _ := ml.Accept()
			go vh.Handle(conn)
		}
	}(vhost, muxListener)
}

for {
	conn, err := mux.NextError()

	switch err.(type) {
	case vhost.BadRequest:
		log.Printf("got a bad request!")
		conn.Write([]byte("bad request"))
	case vhost.NotFound:
		log.Printf("got a connection for an unknown vhost")
		conn.Write([]byte("vhost not found"))
	case vhost.Closed:
		log.Printf("closed conn: %s", err)
	default:
		if conn != nil {
			conn.Write([]byte("server error"))
		}
	}

	if conn != nil {
		conn.Close()
	}
}
```
### Low-level API usage
```go
// accept a new connection
conn, _ := listener.Accept()

// parse out the HTTP request and the Host header
if vhostConn, err = vhost.HTTP(conn); err != nil {
	panic("Not a valid http connection!")
}

fmt.Printf("Target Host: ", vhostConn.Host())
// Target Host: example.com

// vhostConn contains the entire request as if no bytes had been consumed
bytes, _ := ioutil.ReadAll(vhostConn)
fmt.Printf("%s", bytes)
// GET / HTTP/1.1
// Host: example.com
// User-Agent: ...
// ...
```

### Advanced introspection
The entire HTTP request headers are available for inspection in case you want to mux on something besides the Host header:
```go
// parse out the HTTP request and the Host header
if vhostConn, err = vhost.HTTP(conn); err != nil {
	panic("Not a valid http connection!")
}

httpVersion := vhost.Request.MinorVersion
customRouting := vhost.Request.Header["X-Custom-Routing-Header"]
```

Likewise for TLS, you can look at detailed information about the ClientHello message:
```go
if vhostConn, err = vhost.TLS(conn); err != nil {
	panic("Not a valid TLS connection!")
}

cipherSuites := vhost.ClientHelloMsg.CipherSuites
sessionId := vhost.ClientHelloMsg.SessionId
```

##### Memory reduction with Free
After you're done muxing, you probably don't need to inspect the header data anymore, so you can make it available for garbage collection:

```go
// look up the upstream host
upstreamHost := hostMapping[vhostConn.Host()]

// free up the muxing data
vhostConn.Free()

// vhostConn.Host() == ""
// vhostConn.Request == nil (HTTP)
// vhostConn.ClientHelloMsg == nil (TLS)
```

### Example of using the new JA4 functionality

```go

conn, err := listener.Accept()
if err != nil {
    log.Printf("Error accepting connection: %v", err)
    continue
}

// Parse TLS connection
tlsConn, err := vhost.TLS(conn)
if err != nil {
    log.Printf("Not a valid TLS connection: %v", err)
    conn.Close()
    continue
}

// Existing functionality - get SNI
hostname := tlsConn.Host()
log.Printf("Connection for hostname: %s", hostname)

// New functionality - get JA4 fingerprint
ja4Fingerprint := tlsConn.JA4()
log.Printf("JA4 fingerprint: %s", ja4Fingerprint)

// Optional: get raw JA4 string for debugging
ja4Raw := tlsConn.JA4Raw()
log.Printf("JA4 raw: %s", ja4Raw)

// New functionality - get specific JA4 components
// These allow selective logging of parts: A (protocol basics), B (cipher hash), C (handshake details)
ja4A := tlsConn.JA4A()
ja4B := tlsConn.JA4B()
ja4C := tlsConn.JA4C()
log.Printf("JA4 A part: %s", ja4A)  // e.g., "t13d1311h2" - transport, version, SNI, counts, ALPN prefix
log.Printf("JA4 B part: %s", ja4B)  // e.g., "8daaf6152771" - truncated SHA256 of sorted ciphers
log.Printf("JA4 C part: %s", ja4C)  // e.g., "02713d6af862" - truncated SHA256 of ALPN, sigalgs, curves, points, versions

// Use for targeted analytics, e.g., log only B for cipher patterns
recordCipherHash(hostname, ja4B)

// When done, free resources
tlsConn.Free()