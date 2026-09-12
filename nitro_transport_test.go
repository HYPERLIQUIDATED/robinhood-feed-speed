package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/httphead"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsflate"
	"github.com/gobwas/ws/wsutil"
)

func testFeedServer(t *testing.T, compressed bool, serve func(net.Conn, *bufio.ReadWriter, *http.Request)) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Arbitrum-Feed-Client-Version") != "2" {
			t.Error("missing Nitro client version")
		}
		upgrader := ws.HTTPUpgrader{}
		if compressed {
			upgrader.Negotiate = func(offer httphead.Option) (httphead.Option, error) {
				want := wsflate.DefaultParameters.Option()
				want.Name = []byte(nitroCompressionName)
				if !offer.Equal(want) {
					return httphead.Option{}, nil
				}
				return want, nil
			}
		}
		conn, buffered, handshake, err := upgrader.Upgrade(r, w)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if compressed && len(handshake.Extensions) != 1 {
			t.Error("Nitro compression not negotiated")
			return
		}
		serve(conn, buffered, r)
	}))
	t.Cleanup(server.Close)
	return "ws" + strings.TrimPrefix(server.URL, "http")
}

// 使用 Nitro 的实际编码方式：固定字典、flate.Close 和 RSV1，而非普通压缩的空字典。
func compressedFeedFrame(t *testing.T, payload []byte) ws.Frame {
	t.Helper()
	var encoded bytes.Buffer
	fw, err := flate.NewWriterDict(&encoded, flate.BestCompression, nitroDictionary)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	frame := ws.NewTextFrame(encoded.Bytes())
	frame.Header, err = wsflate.SetBit(frame.Header)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestFeedCompressedAndPlain(t *testing.T) {
	payload := []byte(`{"version":1,"messages":[{"sequenceNumber":123,"blockHash":"0xabc"}]}`)
	compressedFrame := compressedFeedFrame(t, payload)
	for _, compressed := range []bool{true, false} {
		t.Run(fmt.Sprintf("compressed=%t", compressed), func(t *testing.T) {
			url := testFeedServer(t, compressed, func(conn net.Conn, _ *bufio.ReadWriter, r *http.Request) {
				if r.Header.Get("Arbitrum-Requested-Sequence-Number") != "123" || r.URL.RawQuery != "token=test%2Bvalue" {
					t.Error("sequence header or URL query changed")
				}
				first := ws.NewTextFrame(payload)
				if compressed {
					first = compressedFrame
				}
				_ = ws.WriteFrame(conn, first)
				// 协商后仍然允许同连接发送未压缩的帧，状态不能沿用上一条的 RSV1。
				_ = ws.WriteFrame(conn, ws.NewBinaryFrame(payload))
			})
			conn, err := dialFeed(context.Background(), url+"?token=test%2Bvalue", 123)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if conn.compressed != compressed {
				t.Fatalf("compressed=%t", conn.compressed)
			}
			for _, wantOp := range []ws.OpCode{ws.OpText, ws.OpBinary} {
				op, got, err := conn.ReadMessage()
				if err != nil || op != wantOp || !bytes.Equal(got, payload) {
					t.Fatalf("op=%v payload=%q err=%v", op, got, err)
				}
			}
			if conn.messagesRead != 2 {
				t.Fatalf("messagesRead=%d", conn.messagesRead)
			}
		})
	}
}

func TestFeedInitialConnectionOmitsSequenceHeader(t *testing.T) {
	url := testFeedServer(t, false, func(conn net.Conn, _ *bufio.ReadWriter, r *http.Request) {
		// 复现实际 relay 行为：握手完成后拒绝没有有效游标的显式序号请求。
		if _, present := r.Header[http.CanonicalHeaderKey("Arbitrum-Requested-Sequence-Number")]; present {
			return
		}
		_ = ws.WriteFrame(conn, ws.NewTextFrame([]byte(`{"version":1,"messages":[]}`)))
	})
	conn, err := dialFeed(context.Background(), url, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("initial connection failed: %v", err)
	}
}

func TestFeedFragmentedCompressionWithPing(t *testing.T) {
	payload := []byte(strings.Repeat(`{"version":1,"messages":[{"sequenceNumber":123}]}`, 20))
	frame := compressedFeedFrame(t, payload)
	first := ws.NewFrame(ws.OpText, false, frame.Payload[:len(frame.Payload)/2])
	first.Header.Rsv = frame.Header.Rsv
	last := ws.NewFrame(ws.OpContinuation, true, frame.Payload[len(frame.Payload)/2:])
	pong := make(chan error, 1)
	url := testFeedServer(t, true, func(conn net.Conn, buffered *bufio.ReadWriter, _ *http.Request) {
		_ = ws.WriteFrame(conn, first)
		_ = ws.WriteFrame(conn, ws.NewPingFrame([]byte("alive")))
		_ = ws.WriteFrame(conn, last)
		response, err := ws.ReadFrame(buffered.Reader)
		if err == nil {
			ws.Cipher(response.Payload, response.Header.Mask, 0)
			if response.Header.OpCode != ws.OpPong || !bytes.Equal(response.Payload, []byte("alive")) {
				err = fmt.Errorf("invalid pong: %+v", response)
			}
		}
		pong <- err
	})
	conn, err := dialFeed(context.Background(), url, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, got, err := conn.ReadMessage()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("fragmented message: len=%d err=%v", len(got), err)
	}
	if err := <-pong; err != nil {
		t.Fatal(err)
	}
}

func TestFeedLimitsAndInvalidCompression(t *testing.T) {
	for _, tc := range []struct {
		name       string
		compressed bool
		frame      ws.Frame
	}{
		{"plain-limit", false, ws.NewTextFrame(bytes.Repeat([]byte("x"), 1024))},
		{"decoded-limit", true, compressedFeedFrame(t, bytes.Repeat([]byte("x"), 1024))},
		{"invalid-flate", true, func() ws.Frame {
			frame := ws.NewTextFrame([]byte{0xff, 0xff, 0xff})
			frame.Header, _ = wsflate.SetBit(frame.Header)
			return frame
		}()},
		{"unnegotiated-rsv1", false, compressedFeedFrame(t, []byte("hello"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url := testFeedServer(t, tc.compressed, func(conn net.Conn, _ *bufio.ReadWriter, _ *http.Request) {
				_ = ws.WriteFrame(conn, tc.frame)
			})
			conn, err := dialFeed(context.Background(), url, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.messageLimit = 64
			if _, _, err := conn.ReadMessage(); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestFeedHandshakeBufferedFirstFrame(t *testing.T) {
	frame := compressedFeedFrame(t, []byte(`{"version":1,"messages":[]}`))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		var wire bytes.Buffer
		fmt.Fprintf(&wire, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Extensions: %s; server_no_context_takeover; client_no_context_takeover\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]), nitroCompressionName)
		_ = ws.WriteFrame(&wire, frame)
		// 整个握手与压缩首帧由同一次 Write 发出。
		_, _ = conn.Write(wire.Bytes())
	}))
	defer server.Close()
	conn, err := dialFeed(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, payload, err := conn.ReadMessage()
	if err != nil || string(payload) != `{"version":1,"messages":[]}` {
		t.Fatalf("buffered frame: %q %v", payload, err)
	}
}

func TestFeedReconnectAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name string
		seq  uint64
	}{{"a", 42}, {"b", 99}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			requests := make(chan string, 8)
			payload := []byte(fmt.Sprintf(`{"version":1,"messages":[{"sequenceNumber":%d,"blockHash":"0xabc"},{"sequenceNumber":1,"blockHash":"0xdef"}]}`, tc.seq))
			frame := compressedFeedFrame(t, payload)
			url := testFeedServer(t, true, func(conn net.Conn, _ *bufio.ReadWriter, r *http.Request) {
				sequence := r.Header.Get("Arbitrum-Requested-Sequence-Number")
				requests <- sequence
				if sequence == "" {
					_ = ws.WriteFrame(conn, frame)
					return // 模拟 EOF 后的自动重连。
				}
				var b [1]byte
				_, _ = conn.Read(b[:])
			})
			done := make(chan struct{})
			go func() {
				defer close(done)
				runWebsocketSource(ctx, NewTracker(time.Minute, []string{tc.name}), sourceConfig{
					Name: tc.name, URL: url, ReconnectInterval: time.Millisecond,
				}, false)
			}()
			for _, want := range []string{"", fmt.Sprint(tc.seq + 1)} {
				select {
				case got := <-requests:
					if got != want {
						t.Fatalf("sequence=%s want=%s", got, want)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("no reconnect")
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("cancellation did not stop reader")
			}
		})
	}
}

func TestFeedConcurrentClientWrites(t *testing.T) {
	const count = 20
	checked := make(chan error, 1)
	url := testFeedServer(t, false, func(_ net.Conn, buffered *bufio.ReadWriter, _ *http.Request) {
		for i := 0; i < count; i++ {
			frame, err := ws.ReadFrame(buffered.Reader)
			if err != nil {
				checked <- err
				return
			}
			if !frame.Header.Masked {
				checked <- fmt.Errorf("unmasked client frame")
				return
			}
			ws.Cipher(frame.Payload, frame.Header.Mask, 0)
			if string(frame.Payload) != "payload" {
				checked <- fmt.Errorf("interleaved writes")
				return
			}
		}
		checked <- nil
	})
	conn, err := dialFeed(context.Background(), url, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := conn.WriteMessage(ws.OpText, []byte("payload")); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := <-checked; err != nil {
		t.Fatal(err)
	}
}

func TestFeedCloseAndAbruptEOF(t *testing.T) {
	for _, graceful := range []bool{false, true} {
		t.Run(fmt.Sprint(graceful), func(t *testing.T) {
			url := testFeedServer(t, false, func(conn net.Conn, buffered *bufio.ReadWriter, _ *http.Request) {
				if graceful {
					_ = ws.WriteFrame(conn, ws.NewCloseFrame(ws.NewCloseFrameBody(ws.StatusNormalClosure, "done")))
					_, _ = ws.ReadFrame(buffered.Reader)
				}
			})
			conn, err := dialFeed(context.Background(), url, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_, _, err = conn.ReadMessage()
			if graceful {
				if closed, ok := err.(wsutil.ClosedError); !ok || closed.Code != ws.StatusNormalClosure {
					t.Fatalf("close error=%v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "1006") {
				t.Fatalf("EOF error=%v", err)
			}
		})
	}
}

func TestNitroDictionaryBytes(t *testing.T) {
	// 期望值来自固定版本的上游 dictionary.go，不是重新生成的训练字典。
	got := fmt.Sprintf("%x", sha256.Sum256(nitroDictionary))
	const want = "d96272e5e58bd299c3466bc2c519e210afd192d897a4456c4c88322f8d563fa9"
	if len(nitroDictionary) != 20023 || got != want {
		t.Fatalf("dictionary changed: bytes=%d sha256=%s", len(nitroDictionary), got)
	}
}

func TestConsumeFeedCancellationWhileWaitingForData(t *testing.T) {
	url := testFeedServer(t, true, func(conn net.Conn, _ *bufio.ReadWriter, _ *http.Request) {
		var b [1]byte
		_, _ = conn.Read(b[:])
	})
	conn, err := dialFeed(context.Background(), url, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		var next uint64
		done <- consumeWebsocket(ctx, NewTracker(time.Minute, []string{"test"}), conn, sourceConfig{Name: "test"}, false, &next)
	}()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected canceled connection read to fail")
		}
	case <-time.After(time.Second):
		t.Fatal("reader was not interrupted")
	}
}
