package goproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

// WebSocket frame opcodes
const (
	TextMessage   = 1
	BinaryMessage = 2
	CloseMessage  = 8
	PingMessage   = 9
	PongMessage   = 10
)

type WSMessage struct {
	opcode     byte
	mask       bool
	maskingKey []byte
	data       []byte
}

func readWebSocketMessage(conn net.Conn) (WSMessage, error) {
	// Read the first 2 bytes of the frame
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return WSMessage{}, err
	}

	fin := header[0] & 0x80
	opcode := header[0] & 0x0F
	mask := header[1] & 0x80
	payloadLen := header[1] & 0x7F

	if fin == 0 {
		return WSMessage{}, fmt.Errorf("fragmented frames not supported")
	}

	// Determine the payload length
	var extendedPayloadLen uint64
	if payloadLen == 126 {
		extendedPayload := make([]byte, 2)
		if _, err := io.ReadFull(conn, extendedPayload); err != nil {
			return WSMessage{}, err
		}
		extendedPayloadLen = uint64(binary.BigEndian.Uint16(extendedPayload))
	} else if payloadLen == 127 {
		extendedPayload := make([]byte, 8)
		if _, err := io.ReadFull(conn, extendedPayload); err != nil {
			return WSMessage{}, err
		}
		extendedPayloadLen = binary.BigEndian.Uint64(extendedPayload)
	} else {
		extendedPayloadLen = uint64(payloadLen)
	}

	// Read the masking key if present
	var maskingKey []byte
	if mask != 0 {
		maskingKey = make([]byte, 4)
		if _, err := io.ReadFull(conn, maskingKey); err != nil {
			return WSMessage{}, err
		}
	}

	// Read the payload data
	payloadData := make([]byte, extendedPayloadLen)
	if _, err := io.ReadFull(conn, payloadData); err != nil {
		return WSMessage{}, err
	}

	// Unmask the payload data if necessary
	if mask != 0 {
		for i := uint64(0); i < extendedPayloadLen; i++ {
			payloadData[i] ^= maskingKey[i%4]
		}
	}

	msg := WSMessage{
		opcode:     opcode,
		mask:       mask != 0,
		maskingKey: maskingKey,
		data:       payloadData,
	}
	return msg, nil
}

func applyWebSocketMask(payloadData []byte, maskingKey []byte) []byte {
	maskedData := make([]byte, len(payloadData))
	for i := 0; i < len(payloadData); i++ {
		maskedData[i] = payloadData[i] ^ maskingKey[i%4]
	}
	return maskedData
}

func handleWebSocketConnection(clientConn, targetConn *tls.Conn) {
	clientNetConn := wrapTLSConn(clientConn)
	targetNetConn := wrapTLSConn(targetConn)
	errChan := make(chan error, 2)

	go func() {
		for {
			message, err := readWebSocketMessage(clientNetConn)
			if err != nil {
				errChan <- err
				log.Printf("Error reading from client: %v", err)
				return
			}
			log.Printf("[Client to Target] Opcode: %d, Message: %s", message.opcode, string(message.data))
			if err := writeWebsocketMessage(targetNetConn, message); err != nil {
				errChan <- err
				log.Printf("Error writing to target: %v", err)
				return
			}
		}
	}()

	go func() {
		for {
			message, err := readWebSocketMessage(targetNetConn)
			if err != nil {
				errChan <- err
				log.Printf("Error reading from target: %v", err)
				return
			}
			log.Printf("[Target to Client] Opcode: %d, Message: %s", message.opcode, string(message.data))
			if err := writeWebsocketMessage(clientNetConn, message); err != nil {
				errChan <- err
				log.Printf("Error writing to client: %v", err)
				return
			}
		}
	}()

	<-errChan
}

func wrapTLSConn(conn *tls.Conn) net.Conn {
	return conn
}

func writeWebsocketMessage(conn net.Conn, msg WSMessage) error {
	var buffer bytes.Buffer

	// First byte: FIN bit set (0x80) and the opcode
	buffer.WriteByte(0x80 | msg.opcode)

	// Second byte: Mask bit not set (0x00) and the payload length
	payloadLen := len(msg.data)
	if payloadLen <= 125 {
		buffer.WriteByte(byte(payloadLen))
	} else if payloadLen <= 65535 {
		buffer.WriteByte(126)
		binary.Write(&buffer, binary.BigEndian, uint16(payloadLen))
	} else {
		buffer.WriteByte(127)
		binary.Write(&buffer, binary.BigEndian, uint64(payloadLen))
	}

	// Payload data
	payload := msg.data
	if msg.mask {
		payload = applyWebSocketMask(msg.data, msg.maskingKey)
	}
	buffer.Write(payload)

	_, err := conn.Write(buffer.Bytes())
	return err
}

func constructWebSocketFrame(opcode byte, payload []byte) []byte {
	var buffer bytes.Buffer

	// First byte: FIN bit set (0x80) and the opcode
	buffer.WriteByte(0x80 | opcode)

	// Second byte: Mask bit not set (0x00) and the payload length
	payloadLen := len(payload)
	if payloadLen <= 125 {
		buffer.WriteByte(byte(payloadLen))
	} else if payloadLen <= 65535 {
		buffer.WriteByte(126)
		binary.Write(&buffer, binary.BigEndian, uint16(payloadLen))
	} else {
		buffer.WriteByte(127)
		binary.Write(&buffer, binary.BigEndian, uint64(payloadLen))
	}

	// Payload data
	buffer.Write(payload)

	return buffer.Bytes()
}
