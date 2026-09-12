package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gobwas/httphead"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsflate"
	"github.com/gobwas/ws/wsutil"
)

const nitroCompressionName = "Arbitrum-permessage-deflate"

var nitroDictionary = nitroStaticCompressorDictionary()

// 一条连接只有一个读者；订阅、主动 ping 和被动 pong 共用写锁，防止帧交错。
type feedConn struct {
	net.Conn
	reader       wsutil.Reader
	messageState wsflate.MessageState
	compressed   bool
	writeMu      sync.Mutex
	messageLimit int64
	messagesRead uint64
}

func dialFeed(ctx context.Context, url string, nextSequenceNumber uint64) (*feedConn, error) {
	header := make(http.Header)
	header.Set("Arbitrum-Feed-Client-Version", "2")
	header.Set("Arbitrum-Requested-Sequence-Number", strconv.FormatUint(nextSequenceNumber, 10))

	// 仅改变本次请求的扩展名，不修改 wsflate 包的全局变量。
	offer := wsflate.DefaultParameters.Option()
	offer.Name = []byte(nitroCompressionName)
	dialer := ws.Dialer{
		Header:     ws.HandshakeHeaderHTTP(header),
		Extensions: []httphead.Option{offer},
		Timeout:    45 * time.Second,
		TLSConfig:  &tls.Config{MinVersion: tls.VersionTLS12},
	}
	conn, buffered, handshake, err := dialer.Dial(ctx, url)
	if err != nil {
		return nil, err
	}
	compressed := false
	for _, extension := range handshake.Extensions {
		if !extension.Equal(offer) || compressed {
			_ = conn.Close()
			return nil, fmt.Errorf("unexpected feed compression negotiation: %s", extension.Name)
		}
		compressed = true
	}

	var source io.Reader = conn
	if buffered != nil {
		// 握手响应可能与首帧一起到达。继续使用这个 reader，不能丢弃已预读的字节。
		source = buffered
	}
	c := &feedConn{Conn: conn, compressed: compressed, messageLimit: MaxMessageSize}
	c.reader = wsutil.Reader{
		Source:         source,
		State:          ws.StateClientSide,
		CheckUTF8:      !compressed,
		MaxFrameSize:   MaxMessageSize,
		OnIntermediate: c.handleControl,
	}
	if compressed {
		c.reader.State |= ws.StateExtended
		c.reader.Extensions = []wsutil.RecvExtension{&c.messageState}
	}
	return c, nil
}

func (c *feedConn) compressionName() string {
	if c.compressed {
		return nitroCompressionName
	}
	return "none"
}

func (c *feedConn) WriteMessage(op ws.OpCode, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
		return err
	}
	// 客户端帧必须带 mask；即使协商压缩，也允许发送未压缩的数据帧。
	return wsutil.WriteClientMessage(c.Conn, op, payload)
}

func (c *feedConn) handleControl(header ws.Header, payload io.Reader) error {
	if err := c.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
		return err
	}
	return wsutil.ControlFrameHandler(c.Conn, ws.StateClientSide)(header, payload)
}

func (c *feedConn) ReadMessage() (ws.OpCode, []byte, error) {
	for {
		// 有正常数据或控制帧就说明连接存活，不依赖服务端主动返回 pong。
		if err := c.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
			return 0, nil, err
		}
		header, err := c.reader.NextFrame()
		if err != nil {
			return 0, nil, feedReadError(err)
		}
		if header.OpCode.IsControl() {
			if err := c.handleControl(header, &c.reader); err != nil {
				return 0, nil, err
			}
			if err := c.reader.Discard(); err != nil {
				return 0, nil, feedReadError(err)
			}
			continue
		}

		// wsutil.Reader 负责拼接分片，也会处理分片之间的 ping/close。
		isCompressed := c.compressed && c.messageState.IsCompressed()
		payload, err := readFeedPayload(&c.reader, c.messageLimit)
		if err != nil {
			return 0, nil, feedReadError(err)
		}
		if isCompressed {
			// Nitro 使用固定字典，不是 Gorilla 内置的普通 permessage-deflate。
			decoder := wsflate.NewReader(bytes.NewReader(payload), func(r io.Reader) wsflate.Decompressor {
				return flate.NewReaderDict(r, nitroDictionary)
			})
			payload, err = readFeedPayload(decoder, c.messageLimit)
			closeErr := decoder.Close()
			if err != nil {
				return 0, nil, fmt.Errorf("decode Nitro compressed message: %w", err)
			}
			if closeErr != nil {
				return 0, nil, closeErr
			}
		}
		if header.OpCode == ws.OpText && !utf8.Valid(payload) {
			return 0, nil, fmt.Errorf("feed text message is not valid UTF-8")
		}
		c.messagesRead++
		return header.OpCode, payload, nil
	}
}

// 同时限制压缩前后的完整消息大小，不能只限制单个分片或压缩后的体积。
func readFeedPayload(r io.Reader, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("feed message exceeds %d byte limit", limit)
	}
	return payload, nil
}

func feedReadError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("websocket: close 1006 (abnormal closure): %w", err)
	}
	return err
}
