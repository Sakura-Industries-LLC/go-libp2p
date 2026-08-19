package dntls

import (
	"encoding/binary"
	"io"

	pool "github.com/libp2p/go-buffer-pool"
	"golang.org/x/crypto/chacha20poly1305"
)

// MaxTransportMsgLength is the Noise-imposed maximum transport message length,
// inclusive of the MAC size (16 bytes, Poly1305 for noise-libp2p).
const MaxTransportMsgLength = 0xffff

// MaxPlaintextLength is the maximum payload size. It is MaxTransportMsgLength
// minus the MAC size. Payloads over this size will be automatically chunked.
const MaxPlaintextLength = MaxTransportMsgLength - chacha20poly1305.Overhead

// LengthPrefixLength is the length of the length prefix itself, which precedes
// all transport messages in order to delimit them. In bytes.
const LengthPrefixLength = 2

// Read reads from the secure connection, returning plaintext data in buf.
func (s *secureSession) Read(buf []byte) (int, error) {
	s.readLock.Lock()
	defer s.readLock.Unlock()

	if s.qbuf != nil {
		copied := copy(buf, s.qbuf[s.qseek:])
		s.qseek += copied
		if s.qseek == len(s.qbuf) {
			pool.Put(s.qbuf)
			s.qseek, s.qbuf = 0, nil
		}
		return copied, nil
	}

	nextMsgLen, err := s.readNextInsecureMsgLen()
	if err != nil {
		return 0, err
	}

	if len(buf) >= nextMsgLen {
		if err := s.readNextMsgInsecure(buf[:nextMsgLen]); err != nil {
			return 0, err
		}
		dbuf, err := s.decrypt(buf[:0], buf[:nextMsgLen])
		if err != nil {
			return 0, err
		}
		return len(dbuf), nil
	}

	cbuf := pool.Get(nextMsgLen)
	if err := s.readNextMsgInsecure(cbuf); err != nil {
		return 0, err
	}

	if s.qbuf, err = s.decrypt(cbuf[:0], cbuf); err != nil {
		return 0, err
	}

	s.qseek = copy(buf, s.qbuf)
	return s.qseek, nil
}

// Write encrypts the plaintext data and sends it on the secure connection.
func (s *secureSession) Write(data []byte) (int, error) {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()

	var (
		written int
		cbuf    []byte
		total   = len(data)
	)

	if total < MaxPlaintextLength {
		cbuf = pool.Get(total + chacha20poly1305.Overhead + LengthPrefixLength)
	} else {
		cbuf = pool.Get(MaxTransportMsgLength + LengthPrefixLength)
	}
	defer pool.Put(cbuf)

	for written < total {
		end := min(written+MaxPlaintextLength, total)

		b, err := s.encrypt(cbuf[:LengthPrefixLength], data[written:end])
		if err != nil {
			return 0, err
		}

		binary.BigEndian.PutUint16(b, uint16(len(b)-LengthPrefixLength))

		_, err = s.writeMsgInsecure(b)
		if err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (s *secureSession) readNextInsecureMsgLen() (int, error) {
	_, err := io.ReadFull(s.insecureReader, s.rlen[:])
	if err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(s.rlen[:])), err
}

func (s *secureSession) readNextMsgInsecure(buf []byte) error {
	_, err := io.ReadFull(s.insecureReader, buf)
	return err
}

func (s *secureSession) writeMsgInsecure(data []byte) (int, error) {
	return s.insecureConn.Write(data)
}
