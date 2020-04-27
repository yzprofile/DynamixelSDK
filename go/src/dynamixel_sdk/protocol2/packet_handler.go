package protocol2

import (
	dxl "dynamixel_sdk"
	"fmt"
	"time"
)

const (
	TXPACKET_MAX_LEN = 1024
	RXPACKET_MAX_LEN = 1024

	///////////////// for Protocol 2.0 Packet /////////////////
	PKT_HEADER0     = 0
	PKT_HEADER1     = 1
	PKT_HEADER2     = 2
	PKT_RESERVED    = 3
	PKT_ID          = 4
	PKT_LENGTH_L    = 5
	PKT_LENGTH_H    = 6
	PKT_INSTRUCTION = 7
	PKT_ERROR       = 8
	PKT_PARAMETER0  = 8

	///////////////// Protocol 2.0 Error bit /////////////////
	ERRNUM_RESULT_FAIL = 1 // Failed to process the instruction packet.
	ERRNUM_INSTRUCTION = 2 // Instruction error
	ERRNUM_CRC         = 3 // CRC check error
	ERRNUM_DATA_RANGE  = 4 // Data range error
	ERRNUM_DATA_LENGTH = 5 // Data length error
	ERRNUM_DATA_LIMIT  = 6 // Data limit error
	ERRNUM_ACCESS      = 7 // Access error

	ERRBIT_ALERT = 128 //When the device has a problem, this bit is set to 1. Check "Device Status Check" value.
)

type PacketHandler struct{}

func (p *PacketHandler) GetTxRxResult(result int) string {
	switch result {
	case dxl.COMM_SUCCESS:
		return "[TxRxResult] Communication success."

	case dxl.COMM_PORT_BUSY:
		return "[TxRxResult] Port is in use!"

	case dxl.COMM_TX_FAIL:
		return "[TxRxResult] Failed transmit instruction packet!"

	case dxl.COMM_RX_FAIL:
		return "[TxRxResult] Failed get status packet from device!"

	case dxl.COMM_TX_ERROR:
		return "[TxRxResult] Incorrect instruction packet!"

	case dxl.COMM_RX_WAITING:
		return "[TxRxResult] Now recieving status packet!"

	case dxl.COMM_RX_TIMEOUT:
		return "[TxRxResult] There is no status packet!"

	case dxl.COMM_RX_CORRUPT:
		return "[TxRxResult] Incorrect status packet!"

	case dxl.COMM_NOT_AVAILABLE:
		return "[TxRxResult] Protocol does not support This function!"

	default:
		return ""
	}
}

func (p *PacketHandler) GetRxPacketError(error uint8) string {
	if error&ERRBIT_ALERT != 0 {
		return "[RxPacketError] Hardware error occurred. Check the error at Control Table (Hardware Error Status)!"
	}

	not_alert_error := int(error) & ^ERRBIT_ALERT

	switch not_alert_error {
	case 0:
		return ""

	case ERRNUM_RESULT_FAIL:
		return "[RxPacketError] Failed to process the instruction packet!"

	case ERRNUM_INSTRUCTION:
		return "[RxPacketError] Undefined instruction or incorrect instruction!"

	case ERRNUM_CRC:
		return "[RxPacketError] CRC doesn't match!"

	case ERRNUM_DATA_RANGE:
		return "[RxPacketError] The data value is out of range!"

	case ERRNUM_DATA_LENGTH:
		return "[RxPacketError] The data length does not match as expected!"

	case ERRNUM_DATA_LIMIT:
		return "[RxPacketError] The data value exceeds the limit value!"

	case ERRNUM_ACCESS:
		return "[RxPacketError] Writing or Reading is not available to target address!"

	default:
		return "[RxPacketError] Unknown error code!"
	}
}

func (p *PacketHandler) UpdateCRC(crc_accum uint16, data_blk []byte, data_blk_size uint16) uint16 {

	crc_table := [256]uint16{0x0000,
		0x8005, 0x800F, 0x000A, 0x801B, 0x001E, 0x0014, 0x8011,
		0x8033, 0x0036, 0x003C, 0x8039, 0x0028, 0x802D, 0x8027,
		0x0022, 0x8063, 0x0066, 0x006C, 0x8069, 0x0078, 0x807D,
		0x8077, 0x0072, 0x0050, 0x8055, 0x805F, 0x005A, 0x804B,
		0x004E, 0x0044, 0x8041, 0x80C3, 0x00C6, 0x00CC, 0x80C9,
		0x00D8, 0x80DD, 0x80D7, 0x00D2, 0x00F0, 0x80F5, 0x80FF,
		0x00FA, 0x80EB, 0x00EE, 0x00E4, 0x80E1, 0x00A0, 0x80A5,
		0x80AF, 0x00AA, 0x80BB, 0x00BE, 0x00B4, 0x80B1, 0x8093,
		0x0096, 0x009C, 0x8099, 0x0088, 0x808D, 0x8087, 0x0082,
		0x8183, 0x0186, 0x018C, 0x8189, 0x0198, 0x819D, 0x8197,
		0x0192, 0x01B0, 0x81B5, 0x81BF, 0x01BA, 0x81AB, 0x01AE,
		0x01A4, 0x81A1, 0x01E0, 0x81E5, 0x81EF, 0x01EA, 0x81FB,
		0x01FE, 0x01F4, 0x81F1, 0x81D3, 0x01D6, 0x01DC, 0x81D9,
		0x01C8, 0x81CD, 0x81C7, 0x01C2, 0x0140, 0x8145, 0x814F,
		0x014A, 0x815B, 0x015E, 0x0154, 0x8151, 0x8173, 0x0176,
		0x017C, 0x8179, 0x0168, 0x816D, 0x8167, 0x0162, 0x8123,
		0x0126, 0x012C, 0x8129, 0x0138, 0x813D, 0x8137, 0x0132,
		0x0110, 0x8115, 0x811F, 0x011A, 0x810B, 0x010E, 0x0104,
		0x8101, 0x8303, 0x0306, 0x030C, 0x8309, 0x0318, 0x831D,
		0x8317, 0x0312, 0x0330, 0x8335, 0x833F, 0x033A, 0x832B,
		0x032E, 0x0324, 0x8321, 0x0360, 0x8365, 0x836F, 0x036A,
		0x837B, 0x037E, 0x0374, 0x8371, 0x8353, 0x0356, 0x035C,
		0x8359, 0x0348, 0x834D, 0x8347, 0x0342, 0x03C0, 0x83C5,
		0x83CF, 0x03CA, 0x83DB, 0x03DE, 0x03D4, 0x83D1, 0x83F3,
		0x03F6, 0x03FC, 0x83F9, 0x03E8, 0x83ED, 0x83E7, 0x03E2,
		0x83A3, 0x03A6, 0x03AC, 0x83A9, 0x03B8, 0x83BD, 0x83B7,
		0x03B2, 0x0390, 0x8395, 0x839F, 0x039A, 0x838B, 0x038E,
		0x0384, 0x8381, 0x0280, 0x8285, 0x828F, 0x028A, 0x829B,
		0x029E, 0x0294, 0x8291, 0x82B3, 0x02B6, 0x02BC, 0x82B9,
		0x02A8, 0x82AD, 0x82A7, 0x02A2, 0x82E3, 0x02E6, 0x02EC,
		0x82E9, 0x02F8, 0x82FD, 0x82F7, 0x02F2, 0x02D0, 0x82D5,
		0x82DF, 0x02DA, 0x82CB, 0x02CE, 0x02C4, 0x82C1, 0x8243,
		0x0246, 0x024C, 0x8249, 0x0258, 0x825D, 0x8257, 0x0252,
		0x0270, 0x8275, 0x827F, 0x027A, 0x826B, 0x026E, 0x0264,
		0x8261, 0x0220, 0x8225, 0x822F, 0x022A, 0x823B, 0x023E,
		0x0234, 0x8231, 0x8213, 0x0216, 0x021C, 0x8219, 0x0208,
		0x820D, 0x8207, 0x0202,
	}

	for j := uint16(0); j < data_blk_size; j++ {
		i := (uint16(crc_accum>>8) ^ uint16(data_blk[j])) & 0xFF
		crc_accum = (crc_accum << 8) ^ crc_table[i]
	}

	return crc_accum
}

func (p *PacketHandler) AddStuffing(packet []uint8) {
	packet_length_in := dxl.DXL_MAKEWORD(packet[PKT_LENGTH_L], packet[PKT_LENGTH_H])
	packet_length_out := packet_length_in

	if packet_length_in < 8 {
		return
	}

	packet_length_before_crc := packet_length_in - 2
	for i := uint16(3); i < packet_length_before_crc; i++ {
		p := i + PKT_INSTRUCTION - 2
		if packet[p] == 0xFF && packet[p+1] == 0xFF && packet[p+2] == 0xFD {
			packet_length_out++
		}
	}

	if packet_length_in == packet_length_out {
		return
	}

	out_index := packet_length_out + 6 - 2
	in_index := packet_length_in + 6 - 2

	for out_index != in_index {
		if packet[in_index] == 0xFD && packet[in_index-1] == 0xFF && packet[in_index-2] == 0xFF {
			packet[out_index] = 0xFD // byte stuffing
			out_index--
			if out_index != in_index {
				packet[out_index] = packet[in_index]     // FD
				packet[out_index-1] = packet[in_index-1] // FF
				packet[out_index-2] = packet[in_index-2] // FF
				out_index = out_index - 3
				in_index = in_index - 3
			}
		} else {
			packet[out_index] = packet[in_index]
			out_index--
			in_index--
		}
	}

	packet[PKT_LENGTH_L] = dxl.DXL_LOBYTE(packet_length_out)
	packet[PKT_LENGTH_H] = dxl.DXL_HIBYTE(packet_length_out)
}

func (p *PacketHandler) RemoveStuffing(packet []uint8) {
	packet_length_in := dxl.DXL_MAKEWORD(packet[PKT_LENGTH_L], packet[PKT_LENGTH_H])
	packet_length_out := packet_length_in
	index := PKT_INSTRUCTION

	for i := uint16(0); i < packet_length_in-2; i++ {
		if packet[i+PKT_INSTRUCTION] == 0xFD &&
			packet[i+PKT_INSTRUCTION+1] == 0xFD &&
			packet[i+PKT_INSTRUCTION-1] == 0xFF &&
			packet[i+PKT_INSTRUCTION-2] == 0xFF { // FF FF FD FD
			packet_length_out--
		} else {
			packet[index] = packet[i+PKT_INSTRUCTION]
			index++
		}
	}

	packet[index] = packet[PKT_INSTRUCTION+packet_length_in-2]
	packet[index+1] = packet[PKT_INSTRUCTION+packet_length_in-1]
	packet[PKT_LENGTH_L] = dxl.DXL_LOBYTE(packet_length_out)
	packet[PKT_LENGTH_H] = dxl.DXL_HIBYTE(packet_length_out)
}

func (p *PacketHandler) TxPacket(port *dxl.PortHandler, txpacket []uint8) int {
	total_packet_length := uint16(0)
	written_packet_length := uint16(0)

	if port.IsUsing {
		return dxl.COMM_PORT_BUSY
	}
	port.IsUsing = true
	p.AddStuffing(txpacket)

	total_packet_length = dxl.DXL_MAKEWORD(txpacket[PKT_LENGTH_L], txpacket[PKT_LENGTH_H]) + 7
	if total_packet_length > TXPACKET_MAX_LEN {
		port.IsUsing = false
		return dxl.COMM_TX_ERROR
	}

	txpacket[PKT_HEADER0] = 0xFF
	txpacket[PKT_HEADER1] = 0xFF
	txpacket[PKT_HEADER2] = 0xFD
	txpacket[PKT_RESERVED] = 0x00

	crc := p.UpdateCRC(0, txpacket, total_packet_length-2)
	txpacket[total_packet_length-2] = dxl.DXL_LOBYTE(crc)
	txpacket[total_packet_length-1] = dxl.DXL_HIBYTE(crc)

	port.Flush()
	n, err := port.Write(txpacket)
	if err != nil {
		return dxl.COMM_TX_ERROR
	}
	written_packet_length = uint16(n)
	if total_packet_length != written_packet_length {
		port.IsUsing = false
		return dxl.COMM_TX_FAIL
	}

	return dxl.COMM_SUCCESS
}

func (p *PacketHandler) RxPacket(port *dxl.PortHandler) ([]byte, int) {
	result := dxl.COMM_RX_FAIL
	rxpacket := []byte{}

	rx_length := uint16(0)
	wait_length := uint16(11)

	for {
		buf := make([]byte, wait_length-rx_length)
		_, err := port.Read(buf)
		if err != nil {
			return nil, dxl.COMM_RX_CORRUPT
		}
		rxpacket = append(rxpacket, buf...)

		rx_length = uint16(len(rxpacket))
		if rx_length >= wait_length {
			idx := uint16(0)
			for idx = 0; idx < rx_length-3; idx++ {
				if (rxpacket[idx] == 0xFF) &&
					(rxpacket[idx+1] == 0xFF) &&
					(rxpacket[idx+2] == 0xFD) &&
					(rxpacket[idx+3] != 0xFD) {
					break
				}
			}

			if idx == 0 {
				if rxpacket[PKT_RESERVED] != 0x00 ||
					rxpacket[PKT_ID] > 0xFC ||
					dxl.DXL_MAKEWORD(rxpacket[PKT_LENGTH_L], rxpacket[PKT_LENGTH_H]) > RXPACKET_MAX_LEN ||
					rxpacket[PKT_INSTRUCTION] != 0x55 {
					rxpacket = rxpacket[1:]
					rx_length -= 1
					continue
				}

				if wait_length != dxl.DXL_MAKEWORD(rxpacket[PKT_LENGTH_L], rxpacket[PKT_LENGTH_H])+PKT_LENGTH_H+1 {
					wait_length = dxl.DXL_MAKEWORD(rxpacket[PKT_LENGTH_L], rxpacket[PKT_LENGTH_H]) + PKT_LENGTH_H + 1
					continue
				}

				if rx_length < wait_length {
					// check timeout
					if port.IsPacketTimeout() {
						if rx_length == 0 {
							result = dxl.COMM_RX_TIMEOUT
						} else {
							result = dxl.COMM_RX_CORRUPT
						}

						break
					} else {
						continue
					}
				}

				crc := dxl.DXL_MAKEWORD(rxpacket[wait_length-2], rxpacket[wait_length-1])
				if p.UpdateCRC(0, rxpacket, wait_length-2) == crc {
					result = dxl.COMM_SUCCESS
				} else {
					result = dxl.COMM_RX_CORRUPT
				}
				break

			} else {
				rxpacket = rxpacket[idx+1:]
				rx_length -= idx
			}
		} else {
			if port.IsPacketTimeout() {
				if rx_length == 0 {
					result = dxl.COMM_RX_TIMEOUT
				} else {
					result = dxl.COMM_RX_CORRUPT
				}
				break
			}
		}
		time.Sleep(0)
	}
	port.IsUsing = false

	if result == dxl.COMM_SUCCESS {
		p.RemoveStuffing(rxpacket)
	}

	return rxpacket, result
}

func (p *PacketHandler) TxRxPacket(port *dxl.PortHandler, txpacket []byte) ([]uint8, int, uint8) {
	var rxpacket []byte
	error := uint8(0)
	result := p.TxPacket(port, txpacket)
	if result != dxl.COMM_SUCCESS {
		return nil, result, error
	}

	if txpacket[PKT_INSTRUCTION] == dxl.INST_BULK_READ ||
		txpacket[PKT_INSTRUCTION] == dxl.INST_SYNC_READ {
		result = dxl.COMM_NOT_AVAILABLE
	}

	if txpacket[PKT_ID] == dxl.BROADCAST_ID || txpacket[PKT_INSTRUCTION] == dxl.INST_ACTION {
		port.IsUsing = false
		return nil, result, error
	}

	if txpacket[PKT_INSTRUCTION] == dxl.INST_READ {
		port.SetPacketTimeout(int(dxl.DXL_MAKEWORD(
			txpacket[PKT_PARAMETER0+2], txpacket[PKT_PARAMETER0+3],
		) + 11))
	} else {
		port.SetPacketTimeout(11)
	}

	for {
		rxpacket, result = p.RxPacket(port)
		if result != dxl.COMM_SUCCESS || txpacket[PKT_ID] == rxpacket[PKT_ID] {
			break
		}
	}

	if result == dxl.COMM_SUCCESS && txpacket[PKT_ID] == rxpacket[PKT_ID] {
		error = rxpacket[PKT_ERROR]
	}

	return rxpacket, result, error
}

func (p *PacketHandler) Ping(port *dxl.PortHandler, dxl_id uint8) (uint16, int, uint8) {
	model_number := uint16(0)
	txpacket := make([]byte, 10, 10)

	if dxl_id >= dxl.BROADCAST_ID {
		return model_number, dxl.COMM_NOT_AVAILABLE, 0
	}

	txpacket[PKT_ID] = dxl_id
	txpacket[PKT_LENGTH_L] = 3
	txpacket[PKT_LENGTH_H] = 0
	txpacket[PKT_INSTRUCTION] = dxl.INST_PING

	rxpacket, result, error := p.TxRxPacket(port, txpacket)
	if result == dxl.COMM_SUCCESS {
		model_number = dxl.DXL_MAKEWORD(rxpacket[PKT_PARAMETER0+1], rxpacket[PKT_PARAMETER0+2])
	}

	return model_number, result, error
}

func (p *PacketHandler) BroadcastPing(port *dxl.PortHandler) ([]uint8, int) {
	id_list := []uint8{}
	STATUS_LENGTH := uint16(14)

	rx_length := uint16(0)
	wait_length := STATUS_LENGTH * dxl.MAX_ID
	txpacket := make([]byte, 10, 10)
	rxpacket := []byte{}

	tx_time_per_byte := (1000.0 / port.GetBaudRate()) * 10.0

	txpacket[PKT_ID] = dxl.BROADCAST_ID
	txpacket[PKT_LENGTH_L] = 3
	txpacket[PKT_LENGTH_H] = 0
	txpacket[PKT_INSTRUCTION] = dxl.INST_PING

	result := p.TxPacket(port, txpacket)

	if result != dxl.COMM_SUCCESS {
		port.IsUsing = false
		return id_list, result
	}

	port.SetPacketTimeoutMillis(int64(
		(float64(wait_length) * float64(tx_time_per_byte)) + (3.0 * float64(dxl.MAX_ID)) + 16.0,
	))

	for {
		buf := make([]byte, wait_length-rx_length)
		n, err := port.Read(buf)
		if err != nil {
			return nil, dxl.COMM_RX_CORRUPT
		}
		rx_length = uint16(n)
		rxpacket = append(rxpacket, buf...)
		if port.IsPacketTimeout() {
			break
		}
	}

	port.IsUsing = false

	if rx_length == 0 {
		return id_list, dxl.COMM_RX_TIMEOUT
	}

	for {
		if rx_length < STATUS_LENGTH {
			return id_list, dxl.COMM_RX_CORRUPT
		}

		idx := uint16(0)
		for ; idx < rx_length-2; idx++ {
			if rxpacket[idx] == 0xFF &&
				rxpacket[idx+1] == 0xFF &&
				rxpacket[idx+2] == 0xFD {
				break
			}
		}

		if idx == 0 {
			crc := dxl.DXL_MAKEWORD(rxpacket[STATUS_LENGTH-2], rxpacket[STATUS_LENGTH-1])
			if p.UpdateCRC(0, rxpacket, STATUS_LENGTH-2) == crc {
				result = dxl.COMM_SUCCESS
				id_list = append(id_list, rxpacket[PKT_ID])
				rxpacket = rxpacket[STATUS_LENGTH+1:]
				rx_length = rx_length - STATUS_LENGTH
				if rx_length == 0 {
					return id_list, result
				}
			} else {
				result = dxl.COMM_RX_CORRUPT
				rxpacket = rxpacket[3+1:]
				rx_length = rx_length - 3
			}

		} else {
			rxpacket = rxpacket[idx+1:]
			rx_length = rx_length - idx
		}
	}

	return id_list, result
}

func (p *PacketHandler) Action(port *dxl.PortHandler, id uint8) int {
	txpacket := make([]byte, 10, 10)
	txpacket[PKT_ID] = id
	txpacket[PKT_LENGTH_L] = 3
	txpacket[PKT_LENGTH_H] = 0
	txpacket[PKT_INSTRUCTION] = dxl.INST_ACTION
	_, result, _ := p.TxRxPacket(port, txpacket)
	return result
}

func (p *PacketHandler) Reboot(port *dxl.PortHandler, id uint8) int {
	txpacket := make([]byte, 10, 10)
	txpacket[PKT_ID] = id
	txpacket[PKT_LENGTH_L] = 3
	txpacket[PKT_LENGTH_H] = 0
	txpacket[PKT_INSTRUCTION] = dxl.INST_REBOOT
	_, result, _ := p.TxRxPacket(port, txpacket)
	return result
}

func (p *PacketHandler) ClearMultiTurn(port *dxl.PortHandler, id uint8) int {
	txpacket := make([]byte, 15, 15)
	txpacket[PKT_ID] = id
	txpacket[PKT_LENGTH_L] = 8
	txpacket[PKT_LENGTH_H] = 0
	txpacket[PKT_INSTRUCTION] = dxl.INST_CLEAR
	txpacket[PKT_PARAMETER0+0] = 0x01
	txpacket[PKT_PARAMETER0+1] = 0x44
	txpacket[PKT_PARAMETER0+2] = 0x58
	txpacket[PKT_PARAMETER0+3] = 0x4C
	txpacket[PKT_PARAMETER0+4] = 0x22
	_, result, _ := p.TxRxPacket(port, txpacket)
	return result
}

func (p *PacketHandler) FactoryReset(port *dxl.PortHandler, id, option uint8) int {
	txpacket := make([]byte, 11, 11)
	txpacket[PKT_ID] = id
	txpacket[PKT_LENGTH_L] = 4
	txpacket[PKT_LENGTH_H] = 0
	txpacket[PKT_INSTRUCTION] = dxl.INST_FACTORY_RESET
	txpacket[PKT_PARAMETER0] = option
	_, result, _ := p.TxRxPacket(port, txpacket)
	return result
}

func (p *PacketHandler) ReadTx(port *dxl.PortHandler, id uint8, address, length uint16) int {
	txpacket := make([]byte, 14, 14)
	if id >= dxl.BROADCAST_ID {
		return dxl.COMM_NOT_AVAILABLE
	}

	txpacket[PKT_ID] = id
	txpacket[PKT_LENGTH_L] = 7
	txpacket[PKT_LENGTH_H] = 0
	txpacket[PKT_INSTRUCTION] = dxl.INST_READ
	txpacket[PKT_PARAMETER0+0] = dxl.DXL_LOBYTE(address)
	txpacket[PKT_PARAMETER0+1] = dxl.DXL_HIBYTE(address)
	txpacket[PKT_PARAMETER0+2] = dxl.DXL_LOBYTE(length)
	txpacket[PKT_PARAMETER0+3] = dxl.DXL_HIBYTE(length)

	_, result, _ := p.TxRxPacket(port, txpacket)
	if result == dxl.COMM_SUCCESS {
		port.SetPacketTimeout(int(length + 11))
	}
	return result
}

func (p *PacketHandler) ReadRx(port *dxl.PortHandler, id uint8, length uint16) ([]byte, int, uint8) {
	var rxpacket []byte
	result := dxl.COMM_TX_FAIL
	error := uint8(0)
	data := []byte{}
	for {
		rxpacket, result = p.RxPacket(port)
		if result != dxl.COMM_SUCCESS || rxpacket[PKT_ID] == id {
			break
		}
	}
	if result == dxl.COMM_SUCCESS && rxpacket[PKT_ID] == id {
		error = rxpacket[PKT_ERROR]
		data = append(data, rxpacket[PKT_PARAMETER0+1:PKT_PARAMETER0+1+length]...)
	}
	return data, result, error
}

func (p *PacketHandler) ReadTxRx(port *dxl.PortHandler, id uint8, address, length uint16) ([]byte, int, uint8) {
	txpacket := make([]byte, 14, 14)
	data := []byte{}
	if id >= dxl.BROADCAST_ID {
		return data, dxl.COMM_NOT_AVAILABLE, 0
	}

	txpacket[PKT_ID] = id
	txpacket[PKT_LENGTH_L] = 7
	txpacket[PKT_LENGTH_H] = 0
	txpacket[PKT_INSTRUCTION] = dxl.INST_READ
	txpacket[PKT_PARAMETER0+0] = dxl.DXL_LOBYTE(address)
	txpacket[PKT_PARAMETER0+1] = dxl.DXL_HIBYTE(address)
	txpacket[PKT_PARAMETER0+2] = dxl.DXL_LOBYTE(length)
	txpacket[PKT_PARAMETER0+3] = dxl.DXL_HIBYTE(length)

	rxpacket, result, error := p.TxRxPacket(port, txpacket)
	if result == dxl.COMM_SUCCESS {
		error = rxpacket[PKT_ERROR]
		data = append(data, rxpacket[PKT_PARAMETER0+1:PKT_PARAMETER0+1+length]...)
	}

	return data, result, error
}

func (p *PacketHandler) Read1ByteTx(port *dxl.PortHandler, id uint8, addr uint16) int {
	return p.ReadTx(port, id, addr, 1)
}

func (p *PacketHandler) Read1ByteRx(port *dxl.PortHandler, id uint8) (uint8, int, uint8) {
	data, result, error := p.ReadRx(port, id, 1)
	var data_read uint8 = 0
	if result == dxl.COMM_SUCCESS {
		data_read = data[0]
	}
	return data_read, result, error
}

func (p *PacketHandler) Read1ByteTxRx(port *dxl.PortHandler, id uint8, addr uint16) (uint8, int, uint8) {
	data, result, error := p.ReadTxRx(port, id, addr, 1)
	var data_read uint8 = 0
	if result == dxl.COMM_SUCCESS {
		data_read = data[0]
	}
	return data_read, result, error
}

func (p *PacketHandler) Read2ByteTx(port *dxl.PortHandler, id uint8, addr uint16) int {
	return p.ReadTx(port, id, addr, 2)
}

func (p *PacketHandler) Read2ByteRx(port *dxl.PortHandler, id uint8) (uint16, int, uint8) {
	data, result, error := p.ReadRx(port, id, 2)
	var data_read uint16 = 0
	if result == dxl.COMM_SUCCESS {
		data_read = dxl.DXL_MAKEWORD(data[0], data[1])
	}
	return data_read, result, error
}

func (p *PacketHandler) Read2ByteTxRx(port *dxl.PortHandler, id uint8, addr uint16) (uint16, int, uint8) {
	data, result, error := p.ReadTxRx(port, id, addr, 2)
	var data_read uint16 = 0
	if result == dxl.COMM_SUCCESS {
		data_read = dxl.DXL_MAKEWORD(data[0], data[1])
	}
	return data_read, result, error
}

func (p *PacketHandler) Read4ByteTx(port *dxl.PortHandler, id uint8, addr uint16) int {
	return p.ReadTx(port, id, addr, 2)
}

func (p *PacketHandler) Read4ByteRx(port *dxl.PortHandler, id uint8) (uint32, int, uint8) {
	data, result, error := p.ReadRx(port, id, 2)
	var data_read uint32 = 0
	if result == dxl.COMM_SUCCESS {
		data_read = dxl.DXL_MAKEDWORD(
			dxl.DXL_MAKEWORD(data[0], data[1]),
			dxl.DXL_MAKEWORD(data[2], data[3]),
		)
	}
	return data_read, result, error
}

func (p *PacketHandler) Read4ByteTxRx(port *dxl.PortHandler, id uint8, addr uint16) (uint32, int, uint8) {
	data, result, error := p.ReadTxRx(port, id, addr, 2)
	var data_read uint32 = 0
	if result == dxl.COMM_SUCCESS {
		data_read = dxl.DXL_MAKEDWORD(
			dxl.DXL_MAKEWORD(data[0], data[1]),
			dxl.DXL_MAKEWORD(data[2], data[3]),
		)
	}
	return data_read, result, error
}

func (p *PacketHandler) WriteTxOnly(port *dxl.PortHandler, id uint8, addr, length uint16, data []byte) int {
	txpacket := make([]byte, length+12, length+12)
	txpacket[PKT_ID] = id
	txpacket[PKT_LENGTH_L] = dxl.DXL_LOBYTE(length + 5)
	txpacket[PKT_LENGTH_H] = dxl.DXL_HIBYTE(length + 5)
	txpacket[PKT_INSTRUCTION] = dxl.INST_WRITE
	txpacket[PKT_PARAMETER0+0] = dxl.DXL_LOBYTE(addr)
	txpacket[PKT_PARAMETER0+1] = dxl.DXL_HIBYTE(addr)

	copy(txpacket[PKT_PARAMETER0+2:PKT_PARAMETER0+2+length], data[0:length])
	result := p.TxPacket(port, txpacket)
	port.IsUsing = false
	return result
}

func (p *PacketHandler) WriteTxRx(port *dxl.PortHandler, id uint8, addr, length uint16, data []byte) (int, uint8) {
	txpacket := make([]byte, length+12, length+12)
	txpacket[PKT_ID] = id
	txpacket[PKT_LENGTH_L] = dxl.DXL_LOBYTE(length + 5)
	txpacket[PKT_LENGTH_H] = dxl.DXL_HIBYTE(length + 5)
	txpacket[PKT_INSTRUCTION] = dxl.INST_WRITE
	txpacket[PKT_PARAMETER0+0] = dxl.DXL_LOBYTE(addr)
	txpacket[PKT_PARAMETER0+1] = dxl.DXL_HIBYTE(addr)

	copy(txpacket[PKT_PARAMETER0+2:PKT_PARAMETER0+2+length], data[0:length])

	fmt.Println(txpacket)

	_, result, error := p.TxRxPacket(port, txpacket)

	return result, error

}

func (p *PacketHandler) Write1ByteTxOnly(port *dxl.PortHandler, id uint8, addr uint16, data byte) int {
	return p.WriteTxOnly(port, id, addr, 1, []byte{data})
}

func (p *PacketHandler) Write1ByteTxRx(port *dxl.PortHandler, id uint8, addr, length uint16, data byte) (int, uint8) {
	return p.WriteTxRx(port, id, addr, 1, []byte{data})
}

func (p *PacketHandler) Write2ByteTxOnly(port *dxl.PortHandler, id uint8, addr uint16, data uint16) int {
	data_write := []byte{dxl.DXL_LOBYTE(data), dxl.DXL_HIBYTE(data)}
	return p.WriteTxOnly(port, id, addr, 2, data_write)
}

func (p *PacketHandler) Write2ByteTxRx(port *dxl.PortHandler, id uint8, addr, length uint16, data uint16) (int, uint8) {
	data_write := []byte{dxl.DXL_LOBYTE(data), dxl.DXL_HIBYTE(data)}
	return p.WriteTxRx(port, id, addr, 2, data_write)
}

func (p *PacketHandler) Write4ByteTxOnly(port *dxl.PortHandler, id uint8, addr uint16, data uint32) int {
	data_write := []byte{
		dxl.DXL_LOBYTE(dxl.DXL_LOWORD(data)),
		dxl.DXL_HIBYTE(dxl.DXL_LOWORD(data)),
		dxl.DXL_LOBYTE(dxl.DXL_HIWORD(data)),
		dxl.DXL_HIBYTE(dxl.DXL_HIWORD(data)),
	}
	return p.WriteTxOnly(port, id, addr, 4, data_write)
}

func (p *PacketHandler) Write4ByteTxRx(port *dxl.PortHandler, id uint8, addr, length uint16, data uint32) (int, uint8) {
	data_write := []byte{
		dxl.DXL_LOBYTE(dxl.DXL_LOWORD(data)),
		dxl.DXL_HIBYTE(dxl.DXL_LOWORD(data)),
		dxl.DXL_LOBYTE(dxl.DXL_HIWORD(data)),
		dxl.DXL_HIBYTE(dxl.DXL_HIWORD(data)),
	}
	return p.WriteTxRx(port, id, addr, 4, data_write)
}

func (p *PacketHandler) RegWriteTxOnly(port *dxl.PortHandler, id uint8, addr, length uint16, data []byte) int {
	txpacket := make([]byte, length+12, length+12)

	txpacket[PKT_ID] = id
	txpacket[PKT_LENGTH_L] = dxl.DXL_LOBYTE(length + 5)
	txpacket[PKT_LENGTH_H] = dxl.DXL_HIBYTE(length + 5)
	txpacket[PKT_INSTRUCTION] = dxl.INST_REG_WRITE
	txpacket[PKT_PARAMETER0+0] = dxl.DXL_LOBYTE(addr)
	txpacket[PKT_PARAMETER0+1] = dxl.DXL_HIBYTE(addr)

	copy(txpacket[PKT_PARAMETER0+2:PKT_PARAMETER0+2+length], data[0:length])
	result := p.TxPacket(port, txpacket)
	port.IsUsing = false

	return result
}

func (p *PacketHandler) RegWriteTxRx(port *dxl.PortHandler, id uint8, addr, length uint16, data []byte) (int, uint8) {
	txpacket := make([]byte, length+12, length+12)
	txpacket[PKT_ID] = id
	txpacket[PKT_LENGTH_L] = dxl.DXL_LOBYTE(length + 5)
	txpacket[PKT_LENGTH_H] = dxl.DXL_HIBYTE(length + 5)
	txpacket[PKT_INSTRUCTION] = dxl.INST_REG_WRITE
	txpacket[PKT_PARAMETER0+0] = dxl.DXL_LOBYTE(addr)
	txpacket[PKT_PARAMETER0+1] = dxl.DXL_HIBYTE(addr)

	copy(txpacket[PKT_PARAMETER0+2:PKT_PARAMETER0+2+length], data[0:length])
	_, result, error := p.TxRxPacket(port, txpacket)

	return result, error

}

func (p *PacketHandler) SyncReadTx(port *dxl.PortHandler, start_address uint16, data_length uint16, param []byte, param_length uint16) int {
	txpacket := make([]byte, param_length+14, param_length+14)

	txpacket[PKT_ID] = dxl.BROADCAST_ID
	txpacket[PKT_LENGTH_L] = dxl.DXL_LOBYTE(param_length + 7)
	txpacket[PKT_LENGTH_H] = dxl.DXL_HIBYTE(param_length + 7)
	txpacket[PKT_INSTRUCTION] = dxl.INST_SYNC_READ
	txpacket[PKT_PARAMETER0+0] = dxl.DXL_LOBYTE(start_address)
	txpacket[PKT_PARAMETER0+1] = dxl.DXL_HIBYTE(start_address)
	txpacket[PKT_PARAMETER0+2] = dxl.DXL_LOBYTE(data_length)
	txpacket[PKT_PARAMETER0+3] = dxl.DXL_HIBYTE(data_length)

	copy(txpacket[PKT_PARAMETER0+4:PKT_PARAMETER0+4+param_length], param[0:param_length])

	result := p.TxPacket(port, txpacket)
	if result == dxl.COMM_SUCCESS {
		port.SetPacketTimeout(int((11 + data_length) * param_length))
	}
	return result
}

func (p *PacketHandler) SyncWriteTxOnly(port *dxl.PortHandler, start_address uint16, data_length uint16, param []byte, param_length uint16) int {
	txpacket := make([]byte, param_length+14, param_length+14)

	txpacket[PKT_ID] = dxl.BROADCAST_ID
	txpacket[PKT_LENGTH_L] = dxl.DXL_LOBYTE(param_length + 7)
	txpacket[PKT_LENGTH_H] = dxl.DXL_HIBYTE(param_length + 7)
	txpacket[PKT_INSTRUCTION] = dxl.INST_SYNC_WRITE
	txpacket[PKT_PARAMETER0+0] = dxl.DXL_LOBYTE(start_address)
	txpacket[PKT_PARAMETER0+1] = dxl.DXL_HIBYTE(start_address)
	txpacket[PKT_PARAMETER0+2] = dxl.DXL_LOBYTE(data_length)
	txpacket[PKT_PARAMETER0+3] = dxl.DXL_HIBYTE(data_length)

	copy(txpacket[PKT_PARAMETER0+4:PKT_PARAMETER0+4+param_length], param[0:param_length])
	_, result, _ := p.TxRxPacket(port, txpacket)

	return result

}

func (p *PacketHandler) BulkReadTx(port *dxl.PortHandler, param []byte, param_length uint16) int {
	txpacket := make([]byte, param_length+10, param_length+10)

	txpacket[PKT_ID] = dxl.BROADCAST_ID
	txpacket[PKT_LENGTH_L] = dxl.DXL_LOBYTE(param_length + 3)
	txpacket[PKT_LENGTH_H] = dxl.DXL_HIBYTE(param_length + 3)
	txpacket[PKT_INSTRUCTION] = dxl.INST_BULK_READ

	copy(txpacket[PKT_PARAMETER0:PKT_PARAMETER0+param_length], param[0:param_length])
	result := p.TxPacket(port, txpacket)

	if result == dxl.COMM_SUCCESS {
		wait_length := uint16(0)
		i := uint16(0)
		for i < param_length {
			wait_length += dxl.DXL_MAKEWORD(param[i+3], param[i+4]) + 10
			i += 5
		}
		port.SetPacketTimeout(int(wait_length))
	}
	return result
}

func (p *PacketHandler) BulkWriteTxOnly(port *dxl.PortHandler, param []byte, param_length uint16) int {
	txpacket := make([]byte, param_length+10, param_length+10)

	txpacket[PKT_ID] = dxl.BROADCAST_ID
	txpacket[PKT_LENGTH_L] = dxl.DXL_LOBYTE(param_length + 3)
	txpacket[PKT_LENGTH_H] = dxl.DXL_HIBYTE(param_length + 3)
	txpacket[PKT_INSTRUCTION] = dxl.INST_BULK_WRITE

	copy(txpacket[PKT_PARAMETER0:PKT_PARAMETER0+param_length], param[0:param_length])
	_, result, _ := p.TxRxPacket(port, txpacket)
	return result
}
