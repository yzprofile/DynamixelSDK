package dynamixel_sdk

const (
	BROADCAST_ID = 0xFE // 254
	MAX_ID       = 0xFC // 252

	// Instruction for DXL Protocol
	INST_PING          = 1
	INST_READ          = 2
	INST_WRITE         = 3
	INST_REG_WRITE     = 4
	INST_ACTION        = 5
	INST_FACTORY_RESET = 6
	INST_CLEAR         = 16
	INST_SYNC_WRITE    = 131 // 0x83
	INST_BULK_READ     = 146 // 0x92
	// --- Only for 2.0 ---
	INST_REBOOT     = 8
	INST_STATUS     = 85  // 0x55
	INST_SYNC_READ  = 130 // 0x82
	INST_BULK_WRITE = 147 // 0x93

	// Communication Result
	COMM_SUCCESS       = 0     // tx or rx packet communication success
	COMM_PORT_BUSY     = -1000 // Port is busy (in use)
	COMM_TX_FAIL       = -1001 // Failed transmit instruction packet
	COMM_RX_FAIL       = -1002 // Failed get status packet
	COMM_TX_ERROR      = -2000 // Incorrect instruction packet
	COMM_RX_WAITING    = -3000 // Now recieving status packet
	COMM_RX_TIMEOUT    = -3001 // There is no status packet
	COMM_RX_CORRUPT    = -3002 // Incorrect status packet
	COMM_NOT_AVAILABLE = -9000 //
)

func DXL_MAKEWORD(a, b uint8) uint16 {
	return uint16((uint8((uint64(a)) & 0xff))) | (uint16(uint8((uint64(b))&0xff)))<<8
}

func DXL_MAKEDWORD(a, b uint16) uint32 {
	return uint32((uint16((uint64(a)) & 0xffff))) | (uint32(uint16((uint64(b))&0xffff)))<<16
}

func DXL_LOWORD(l uint32) uint16 {
	return ((uint16)(((uint64)(l)) & 0xffff))
}
func DXL_HIWORD(l uint32) uint16 {
	return ((uint16)((((uint64)(l)) >> 16) & 0xffff))
}
func DXL_LOBYTE(w uint16) uint8 {
	return ((uint8)(((uint64)(w)) & 0xff))
}
func DXL_HIBYTE(w uint16) uint8 {
	return ((uint8)((((uint64)(w)) >> 8) & 0xff))
}
