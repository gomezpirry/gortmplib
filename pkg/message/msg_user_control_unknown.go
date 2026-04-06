package message

import (
	"github.com/bluenviron/gortmplib/pkg/rawmessage"
)

// UserControlUnknown is a user control message with an unrecognized type.
// It is used to silently skip non-standard user control messages from servers
// that send extensions beyond the RTMP spec (e.g. type 32).
type UserControlUnknown struct {
	RawType UserControlType
	Body    []byte
}

func (m *UserControlUnknown) unmarshal(raw *rawmessage.Message) error {
	if len(raw.Body) >= 2 {
		m.RawType = UserControlType(uint16(raw.Body[0])<<8 | uint16(raw.Body[1]))
	}
	m.Body = raw.Body
	return nil
}

func (m UserControlUnknown) marshal() (*rawmessage.Message, error) {
	return &rawmessage.Message{
		ChunkStreamID: ControlChunkStreamID,
		Type:          uint8(TypeUserControl),
		Body:          m.Body,
	}, nil
}
