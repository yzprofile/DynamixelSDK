package protocol2

import (
	"testing"
)

func TestA(t *testing.T) {
	p := &PacketHandler{}
	p.WriteTxRx(nil, id)
}
