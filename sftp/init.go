package sftp

import (
	"encoding/binary"
	"io"
	"sync"
)

// RequestID is the in-band identifier used to match replies to
// outstanding requests. The server echoes the request ID of the
// originating packet in every reply.
type RequestID uint32

// nextRequestID returns a fresh request ID, starting at 1. The
// returned value wraps around to 1 on overflow, never returning 0
// (which is reserved for server-initiated messages).
func nextRequestID(counter *uint32) RequestID {
	for {
		*counter++
		if *counter == 0 {
			*counter = 1
		}
		return RequestID(*counter)
	}
}

// NewRequestIDSource returns a function that yields a fresh request
// ID on every call. The source is safe for concurrent use.
func NewRequestIDSource() func() RequestID {
	var (
		mu sync.Mutex
		c  uint32
	)
	return func() RequestID {
		mu.Lock()
		defer mu.Unlock()
		for {
			c++
			if c == 0 {
				c = 1
			}
			return RequestID(c)
		}
	}
}

// Version is the highest SFTP protocol version this implementation
// supports. The protocol is versioned per draft-ietf-secsh-filexfer.
const Version = 3

// Init is the client-to-server version negotiation message. The
// payload is a single uint32 of the client's highest supported
// version.
type Init struct {
	Version uint32
}

// ServerVersion is the server-to-client reply to Init.
type ServerVersion struct {
	Version uint32
}

// ReadInit decodes a server's version reply.
func ReadInit(p Packet) (ServerVersion, error) {
	if len(p.Payload) < 4 {
		return ServerVersion{}, io.ErrUnexpectedEOF
	}
	return ServerVersion{Version: binary.BigEndian.Uint32(p.Payload)}, nil
}
