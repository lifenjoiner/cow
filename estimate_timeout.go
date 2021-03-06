package main

import (
	"io"
	"net"
	"time"
)

// For once blocked site, use min dial/read timeout to make switching to
// parent proxy faster.
const minDialTimeout = 3 * time.Second
const minReadTimeout = 4 * time.Second
const defaultDialTimeout = 5 * time.Second
const defaultReadTimeout = 5 * time.Second
const maxTimeout = 15 * time.Second

var dialTimeout = defaultDialTimeout
var handshakeTimeout = defaultReadTimeout

// estimateTimeout tries to fetch a url and adjust timeout value according to
// how much time is spent on connect and fetch. This avoids incorrectly
// considering non-blocked sites as blocked when network connection is bad.
func estimateTimeout(host string, payload []byte) {
	//debug.Println("estimating timeout")
	buf := connectBuf.Get()
	defer connectBuf.Put(buf)
	var est time.Duration
	start := time.Now()
	c, err := net.Dial("tcp", host+":80")
	if err != nil {
		errl.Printf("estimateTimeout: can't connect to %s: %v, network has problem?\n",
			host, err)
		goto onErr
	}
	defer c.Close()

	est = time.Now().Sub(start) * 5
	// debug.Println("estimated dialTimeout:", est)
	if est > maxTimeout {
		est = maxTimeout
	}
	if est > config.DialTimeout {
		dialTimeout = est
		debug.Println("new dial timeout:", dialTimeout)
	} else if dialTimeout != config.DialTimeout {
		dialTimeout = config.DialTimeout
		debug.Println("new dial timeout:", dialTimeout)
	}

	start = time.Now()
	// include time spent on sending request, reading all content to make it a
	// little longer

	if _, err = c.Write(payload); err != nil {
		errl.Println("estimateTimeout: error sending request:", err)
		goto onErr
	}
	for err == nil {
		_, err = c.Read(buf)
	}
	if err != io.EOF {
		errl.Printf("estimateTimeout: error getting %s: %v, network has problem?\n",
			host, err)
		goto onErr
	}
	est = time.Now().Sub(start) * 10
	// debug.Println("estimated read timeout:", est)
	if est > maxTimeout {
		est = maxTimeout
	}
	if est > time.Duration(config.HandshakeTimeout) {
		handshakeTimeout = est
	} else if handshakeTimeout != config.HandshakeTimeout {
		handshakeTimeout = config.HandshakeTimeout
	}
	debug.Println("new read timeout:", handshakeTimeout)
	return
onErr:
	dialTimeout += 2 * time.Second
	handshakeTimeout += 2 * time.Second
}

func runEstimateTimeout() {
	handshakeTimeout = config.HandshakeTimeout
	dialTimeout = config.DialTimeout

	payload := []byte("HEAD / HTTP/1.1\r\nHost: "+ config.EstimateTarget +"\r\n\r\n")

	for {
		estimateTimeout(config.EstimateTarget, payload)
		time.Sleep(time.Minute)
	}
}

// Guess network status based on doing HTTP request to estimateSite
func networkBad() bool {
	return (handshakeTimeout != config.HandshakeTimeout) ||
		(dialTimeout != config.DialTimeout)
}
