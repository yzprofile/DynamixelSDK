package dynamixel_sdk

import (
	"github.com/tarm/serial"
	"time"
)

const (
	LATENCY_TIMER = 16.0
)

type PortHandler struct {
	*serial.Port
	IsUsing         bool
	PacketStartTime int64
	PacketTimeout   int64
	BaudRate        int
	TxTimePerByte   float64
}

func (p *PortHandler) OpenPort(name string, baudrate int) error {
	c := &serial.Config{
		Name: name,
		Baud: baudrate,
	}
	port, err := serial.OpenPort(c)
	if err != nil {
		return err
	}

	p.Port = port
	p.BaudRate = baudrate
	p.TxTimePerByte = (1000.0 / float64(baudrate)) * 10.0

	return nil
}

func (p *PortHandler) SetPacketTimeout(plen int) {
	p.PacketStartTime = time.Now().UnixNano() / 1000
	p.PacketTimeout = int64((p.TxTimePerByte * float64(plen)) + (LATENCY_TIMER * 2.0) + 2.0)
}

func (p *PortHandler) SetPacketTimeoutMillis(msec int64) {
	p.PacketStartTime = time.Now().UnixNano() / 1000
	p.PacketTimeout = msec
}

func (p *PortHandler) IsPacketTimeout() bool {
	now := time.Now().UnixNano() / 1000
	diff := now - p.PacketStartTime
	if diff < 0 {
		p.PacketStartTime = now
	}

	if diff > p.PacketTimeout {
		p.PacketTimeout = 0
		return true
	}

	return false
}

func (p *PortHandler) GetBaudRate() int {
	return p.BaudRate
}
