package main

import (
	dxl "dynamixel_sdk"
	proto "dynamixel_sdk/protocol2"
	"fmt"
	"time"
)

func main() {
	fmt.Println("hello")
	port := &dxl.PortHandler{}
	fmt.Println(port)
	err := port.OpenPort("/dev/ttyACM0", 115200)
	fmt.Println(err)
	p := &proto.PacketHandler{}
	id := uint8(200)
	n, e := p.WriteTxRx(port, id, 50, 1, []byte{0})
	fmt.Println(n, e)
	time.Sleep(3 * time.Second)
	n, e = p.WriteTxRx(port, id, 50, 1, []byte{1})
	fmt.Println(n, e)
}
