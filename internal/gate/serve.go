package gate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"unicode/utf8"

	"github.com/travisennis/cake-safety-judge/internal/protocol"
)

const maxConcurrentChecks = 8

// ErrFrameTooLarge reports a frame over the 1 MiB limit.
var ErrFrameTooLarge = errors.New("protocol frame exceeds 1 MiB")

// BuildFunc initializes an engine from the init frame.
type BuildFunc func(protocol.InitFrame) (*Engine, error)

type frameWriter struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

func newFrameWriter(writer io.Writer) *frameWriter {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return &frameWriter{encoder: encoder}
}

func (w *frameWriter) write(value any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.encoder.Encode(value)
}

// Serve runs the long-lived stdio protocol until shutdown or closed stdin.
func Serve(in io.Reader, out io.Writer, log io.Writer, build BuildFunc) error {
	reader := bufio.NewReaderSize(in, 64<<10)
	writer := newFrameWriter(out)

	raw, err := readFrame(reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		_ = writer.write(protocolError("0", err))
		return err
	}
	frame, err := protocol.Decode(raw)
	if err != nil {
		_ = writer.write(protocolError(frameID(raw), err))
		return err
	}
	init, ok := frame.(*protocol.InitFrame)
	if !ok {
		err := errors.New("serve requires an init frame first")
		_ = writer.write(protocolError("0", err))
		return err
	}
	engine, err := build(*init)
	if err != nil {
		_ = writer.write(initError(err))
		return nil
	}
	if log != nil {
		engine.SetDiagnosticWriter(log)
	}
	ready := protocol.ReadyFrame{
		Protocol: protocol.Version,
		Type:     "ready",
		ID:       "init",
		Name:     "safety",
		Version:  Version,
		Warnings: engine.Warnings,
	}
	if err := writer.write(ready); err != nil {
		return err
	}

	var workers sync.WaitGroup
	var activeMu sync.Mutex
	active := map[string]bool{}
	semaphore := make(chan struct{}, maxConcurrentChecks)
	var writeErr error
	var writeMu sync.Mutex

	recordWriteError := func(err error) {
		if err == nil {
			return
		}
		writeMu.Lock()
		if writeErr == nil {
			writeErr = err
		}
		writeMu.Unlock()
	}

	for {
		raw, err := readFrame(reader)
		if errors.Is(err, io.EOF) {
			workers.Wait()
			writeMu.Lock()
			defer writeMu.Unlock()
			return writeErr
		}
		if err != nil {
			recordWriteError(writer.write(protocolError("0", err)))
			workers.Wait()
			return err
		}
		frame, err := protocol.Decode(raw)
		if err != nil {
			recordWriteError(writer.write(protocolError(frameID(raw), err)))
			workers.Wait()
			return err
		}
		switch value := frame.(type) {
		case *protocol.ShutdownFrame:
			workers.Wait()
			writeMu.Lock()
			defer writeMu.Unlock()
			return writeErr
		case *protocol.CheckFrame:
			activeMu.Lock()
			duplicate := active[value.ID]
			active[value.ID] = true
			activeMu.Unlock()
			if duplicate {
				err := fmt.Errorf("duplicate check id %q", value.ID)
				recordWriteError(writer.write(protocolError(value.ID, err)))
				workers.Wait()
				return err
			}
			check := value
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() {
					activeMu.Lock()
					delete(active, check.ID)
					activeMu.Unlock()
				}()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()
				decision, failure := engine.Evaluate(context.Background(), *check)
				if failure != nil {
					recordWriteError(writer.write(failure))
					return
				}
				recordWriteError(writer.write(decision))
			}()
		default:
			err := fmt.Errorf("unexpected %s frame during serve", frameType(raw))
			recordWriteError(writer.write(protocolError(frameID(raw), err)))
			workers.Wait()
			return err
		}
	}
}

func protocolError(id string, err error) *protocol.ErrorFrame {
	if id == "" {
		id = "0"
	}
	message := err.Error()
	if len(message) > 1024 {
		message = message[:1024]
	}
	return &protocol.ErrorFrame{
		Protocol: protocol.Version,
		Type:     "error",
		ID:       id,
		Class:    "protocol",
		Message:  message,
	}
}

func initError(err error) *protocol.ErrorFrame {
	message := err.Error()
	if len(message) > 1024 {
		message = message[:1024]
	}
	return &protocol.ErrorFrame{
		Protocol: protocol.Version,
		Type:     "error",
		ID:       "init",
		Class:    "config",
		Message:  message,
	}
}

func frameID(raw []byte) string {
	var probe struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "0"
	}
	if probe.ID == "" || len(probe.ID) > 64 {
		return "0"
	}
	return probe.ID
}

func frameType(raw []byte) string {
	var probe struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil || probe.Type == "" {
		return "unknown"
	}
	return probe.Type
}

// readFrame reads one newline-delimited frame, enforcing the 1 MiB limit.
func readFrame(reader *bufio.Reader) ([]byte, error) {
	var buffer []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(buffer)+len(chunk) > protocol.MaxFrameBytes+1 {
			return nil, ErrFrameTooLarge
		}
		buffer = append(buffer, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			if len(buffer) == 0 {
				return nil, io.EOF
			}
			break
		}
		if err != nil {
			return nil, err
		}
		break
	}
	buffer = bytes.TrimSuffix(buffer, []byte("\n"))
	buffer = bytes.TrimSuffix(buffer, []byte("\r"))
	if len(buffer) == 0 {
		return nil, errors.New("empty frame")
	}
	if len(buffer) > protocol.MaxFrameBytes {
		return nil, ErrFrameTooLarge
	}
	if !utf8.Valid(buffer) {
		return nil, errors.New("frame is not valid UTF-8")
	}
	return buffer, nil
}
