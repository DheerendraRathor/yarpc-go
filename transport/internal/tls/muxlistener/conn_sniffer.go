// Copyright (c) 2022 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package muxlistener

import (
	"bytes"
	"net"
	"runtime/debug"
	"time"

	"go.uber.org/zap"
)

// connSniffer wraps the connection and enables muxlistener to sniff inital bytes from the
// connection efficiently.
type connSniffer struct {
	net.Conn

	logger           *zap.Logger
	counter          int
	readData         bytes.Buffer
	writeData        bytes.Buffer
	firstReadAt      time.Time
	firstWriteAt     time.Time
	lastReadStartAt  time.Time
	lastReadEndAt    time.Time
	lastWriteStartAt time.Time
	lastWriteEndAt   time.Time
	stopRead         bool
	stackTrace       []byte

	// set to true when sniffing mode is disabled.
	disableSniffing bool
	// buf stores bytes read from the underlying connection when in sniffing
	// mode. When sniffing mode is disabled, buffered bytes is returned.
	buf bytes.Buffer
}

func newConnectionSniffer(conn net.Conn, l *zap.Logger) *connSniffer {
	return &connSniffer{Conn: conn, logger: l, readData: bytes.Buffer{}}
}

func (c *connSniffer) Write(b []byte) (int, error) {
	if (c.firstWriteAt == time.Time{}) {
		c.firstWriteAt = time.Now()
	}

	c.lastWriteStartAt = time.Now()
	defer func() {
		c.lastWriteEndAt = time.Now()
	}()
	n, err := c.Conn.Write(b)
	if !c.stopRead {
		c.writeData.Write(b[:n])
	}
	return n, err
}

// Read returns bytes read from the underlying connection. When sniffing is
// true, data read from the connection is stored in the buffer. When sniffing
// mode is disabled, data is first read from the buffer and once the buffer is
// empty the underlying connection is read.
func (c *connSniffer) Read(b []byte) (int, error) {
	if (c.firstReadAt == time.Time{}) {
		c.firstReadAt = time.Now()
	}

	c.lastReadStartAt = time.Now()
	defer func() {
		c.lastReadEndAt = time.Now()
	}()

	if c.disableSniffing && c.buf.Len() != 0 {
		// Read from the buffer when sniffing is disabled and buffer is not empty.
		n, err := c.buf.Read(b)
		if err != nil {
			c.logger.Error("error from reading sniffing buffer", zap.Error(err))
		}
		if c.buf.Len() == 0 {
			// Release memory as we don't need buffer anymore.
			c.buf = bytes.Buffer{}
		}
		return n, nil
	}

	n, err := c.Conn.Read(b)
	if !c.stopRead {
		c.readData.Write(b[:n])
	}
	if err != nil {
		// if !c.stopRead {
		// 	c.logger.Error(
		// 		"error in reading data from connection",
		// 		zap.Binary("readData", c.readData.Bytes()),
		// 		zap.Binary("writeData", c.writeData.Bytes()),
		// 		zap.Int("readSize", n),
		// 		zap.Int("counterVal", c.counter),
		// 		zap.Error(err),
		// 	)
		// }
		c.stackTrace = debug.Stack()
		return n, err
	}

	// Store in buffer when sniffing.
	if !c.disableSniffing {
		c.logger.Info(
			"Sniffed some data",
			zap.Int("counter", c.counter),
			zap.Int("readSize", n),
			zap.Binary("sniffedData", b[:n]),
		)
		c.counter++
		c.buf.Write(b[:n])
	}
	return n, nil
}

func (c *connSniffer) stopSniffing() {
	c.disableSniffing = true
}

func (c *connSniffer) stopReading() {
	c.stopRead = true
	// release memory
	c.readData = bytes.Buffer{}
	c.writeData = bytes.Buffer{}
}

func (c *connSniffer) ReadBytes() []byte {
	if c == nil {
		return nil
	}

	return c.readData.Bytes()
}

func (c *connSniffer) WriteBytes() []byte {
	if c == nil {
		return nil
	}

	return c.writeData.Bytes()
}

func (c *connSniffer) InnerStack() []byte {
	if c == nil {
		return nil
	}

	return c.stackTrace
}
