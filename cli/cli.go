package cli

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"fmt"
	"gocli/myconstant"
	"io"
	"net"
	"strings"
	"time"

	"github.com/siddontang/mixer/sqlparser"
)

func CalcPassword(scramble, password []byte) []byte {
	if len(password) == 0 {
		return nil
	}

	// stage1Hash = SHA1(password)
	crypt := sha1.New()
	crypt.Write(password)
	stage1 := crypt.Sum(nil)

	// scrambleHash = SHA1(scramble + SHA1(stage1Hash))
	// inner Hash
	crypt.Reset()
	crypt.Write(stage1)
	hash := crypt.Sum(nil)

	// outer Hash
	crypt.Reset()
	crypt.Write(scramble)
	crypt.Write(hash)
	scramble = crypt.Sum(nil)

	// token = scrambleHash XOR stage1Hash
	for i := range scramble {
		scramble[i] ^= stage1[i]
	}
	return scramble
}

func GetConnection(protocal string, addr string) net.Conn {
	// 开始dial下地址
	conn, err := net.Dial(protocal, addr)
	if err != nil {
		fmt.Println(err)
	}
	conn.SetDeadline(time.Time{})
	return conn
}

func ReadPacket(br *bufio.Reader) (length int, payload []byte) {
	header := []byte{0, 0, 0, 0}
	var data []byte
	_, err := io.ReadFull(br, header)
	if err != nil {
		fmt.Println(err)
	}
	length = int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	// fmt.Printf("result header =%v\n", header)
	// fmt.Printf("result len =%v\n", length)

	payload = make([]byte, length)
	_, err = io.ReadFull(br, payload)

	if err != nil {
		fmt.Printf("read payload err =%v\n", err)
	}

	data = append(data, payload...)
	if length > 16777215 {
		ReadPacket(br)
	}
	// sequence := header[3]
	// fmt.Printf("sequence is =%v\n", sequence)

	return length, data
}

func ReadInitialHandshake(rw *ReaderWriter) (salt []byte) {

	_, payload := ReadPacket(rw.Br)

	_ = payload[0]

	// fmt.Printf("protocol_version %v\n", uint32(protocol_version))

	pos := 1
	index := bytes.IndexByte(payload, 00)
	_ = string(payload[pos:index])

	pos = index + 1
	// fmt.Printf("server version %v\n", server_version)

	c := payload[pos : pos+4]
	// fmt.Printf("connection bytes %v\n", c)

	_ = int(uint32(c[0]) | uint32(c[1])<<8 | uint32(c[2])<<16 | uint32(c[3])<<24)

	pos = pos + 4
	// fmt.Printf("connect_id %v\n", cid)

	salt = append(salt, payload[pos:pos+8]...)
	_ = (payload[pos : pos+8])
	pos = pos + 8
	// fmt.Printf("authplugindatapart_1 %v\n", authplugindatapart_1)

	_ = payload[pos]
	pos = pos + 1
	// fmt.Printf("filter %v\n", filter)

	_ = payload[pos : pos+2]
	pos = pos + 2
	// fmt.Printf("capability_flag_1 %v\n", capability_flag_1)

	if len(payload) > pos {
		_ = payload[pos]
		pos = pos + 1
		// fmt.Printf("character_set %v\n", character_set)

		_ = payload[pos : pos+2]
		pos = pos + 2
		// fmt.Printf("status %v\n", status)

		_ = payload[pos : pos+2]

		pos = pos + 2
		// fmt.Printf("capability_flag_2 %v\n", capability_flag_2)

		pos = pos + 10 + 1

		salt = append(salt, payload[pos:pos+12]...)

		//  fmt.Printf("salt %v\n", salt)
		return salt
	}
	return nil
}

func WriteHandshakeResponse41(rw *ReaderWriter, salt []byte) {
	var length int

	var err error
	var sequence byte
	capability := myconstant.CLIENT_PROTOCOL_41 | myconstant.CLIENT_SECURE_CONNECTION |
		myconstant.CLIENT_LONG_PASSWORD | myconstant.CLIENT_TRANSACTIONS | myconstant.CLIENT_LONG_FLAG

	length = 4 + 4 + 1 + 23

	user := "msandbox"
	password := "msandbox"
	db := "bai"
	length = length + len(user) + 1
	// fmt.Printf("salt calcpassword %v\n", salt)

	auth := CalcPassword(salt, []byte(password))

	length += 1 + len(auth)

	if len(db) > 0 {
		capability |= myconstant.CLIENT_CONNECT_WITH_DB

		length += len(db) + 1
	}

	data := make([]byte, length+4)

	data[4] = byte(capability)
	data[5] = byte(capability >> 8)
	data[6] = byte(capability >> 16)
	data[7] = byte(capability >> 24)

	// //Charset [1 byte]
	data[12] = byte(33)

	pos := 13 + 23

	pos += copy(data[pos:], user)

	// 1              length of auth-response
	pos++

	data[pos] = byte(len(auth))
	pos += 1 + copy(data[pos+1:], auth)

	if len(db) > 0 {
		pos += copy(data[pos:], db)
		//data[pos] = 0x00
	}

	length = len(data) - 4
	data[0] = byte(length)
	data[1] = byte(length >> 8)
	data[2] = byte(length >> 16)
	data[3] = sequence + 1
	_, err = rw.Wr.Write(data)

	if err != nil {
		fmt.Println("write fail" + err.Error())
	}

	// fmt.Printf("write data %v\n", data)
}

func ReadOkPacket(rw *ReaderWriter) {
	_, payload := ReadPacket(rw.Br)
	// fmt.Printf("packet length is =%v\n", length)

	if payload[0] == myconstant.OK_HEADER {
		// fmt.Println("ok")
	} else if payload[0] == myconstant.ERR_HEADER {
		code := payload[1:3]
		fmt.Printf("err code %v \n", code)
		// uint16是2个字节
		errcode := int(uint16(code[0]) | uint16(code[1])<<8)
		fmt.Printf("errcode code %v \n", errcode)
	}
}

func SendCommand(rw *ReaderWriter, command byte) {
	var err error
	ping := []byte{0x01, //1 bytes long
		0x00,
		0x00,
		0x00, //sequence
		command,
	}

	_, err = rw.Wr.Write(ping)

	if err != nil {
		fmt.Println("ping fail" + err.Error())
	}

	ReadOkPacket(rw)
}

func SendCommandArgs(rw *ReaderWriter, command byte, args string) {
	var err error
	var length = len(args) + 1

	data := make([]byte, length+4)
	// https://dev.mysql.com/doc/internals/en/com-init-db.html
	data[4] = command
	copy(data[5:], args)

	length = len(data) - 4
	data[0] = byte(length)
	data[1] = byte(length >> 8)
	data[2] = byte(length >> 16)
	data[3] = 0
	_, err = rw.Wr.Write(data)

	if err != nil {
		fmt.Println("data fail" + err.Error())
	}

	// readOkPacket(rw)
}

func Lengthencodedinteger(payload []byte) (res uint64, null bool) {
	if payload[0] == 0xfb {
		return 0, true
	}
	if payload[0] < 0xfb {
		return uint64(payload[0]), false
	} else if payload[0] == 0xfc {
		return uint64(uint64(payload[1]) | uint64(payload[2])<<8), false
	} else if payload[0] == 0xfd {
		return uint64(uint64(payload[1]) | uint64(payload[2])<<8 | uint64(payload[3])<<16), false
	} else if payload[0] == 0xfe {
		return uint64(uint64(payload[1]) | uint64(payload[2])<<8 | uint64(payload[3])<<16 | uint64(payload[4])<<24 | uint64(payload[5])<<32 | uint64(payload[6])<<40 | uint64(payload[7])<<48 | uint64(payload[8])<<56), false
	}
	return
}
func Readresult(rw *ReaderWriter) {

	_, payload := ReadPacket(rw.Br)

	// fmt.Printf("result payload =%v\n", payload)
	columnNumber, _ := Lengthencodedinteger(payload)
	col := make(map[string]byte, columnNumber)

	fmt.Println()
	ReadColumnDef(rw, col)

	// for key, _ := range col {
	// 	name := strings.Split(key, ".")[2]
	// 	fmt.Printf("|" + name + "|")
	// }
	fmt.Println()
	ReadColunValue(rw, columnNumber, col)

}

func ReadColumnDef(rw *ReaderWriter, col map[string]byte) {
	// 开始读取column Definition,读取到eof packet为止
	var err error
	for {
		_, payload := ReadPacket(rw.Br)
		if err != nil {
			fmt.Println("get column definition err", err.Error())
		}
		// fmt.Printf("column def %v\n", payload)
		// eof packet
		if payload[0] == myconstant.EOF_HEADER {
			break
		}

		pos := 4
		// schema_len := payload[pos]
		schema_len, _ := Lengthencodedinteger(payload[4:])
		// fmt.Printf("schema length is %v\n", schema_len)

		pos = pos + 1

		schema := payload[pos : pos+int(schema_len)]
		// fmt.Printf("schema %v\n", schema)
		// fmt.Printf("schema is %v\n", string(schema))
		pos = pos + int(schema_len)

		// table_len := payload[pos]
		table_len, _ := Lengthencodedinteger(payload[pos:])
		pos = pos + 1
		table := payload[pos : pos+int(table_len)]
		// fmt.Printf("table %v\n", table)
		// fmt.Printf("table is %v\n", string(table))
		pos = pos + int(table_len)

		// org_table_len := payload[pos]
		org_table_len, _ := Lengthencodedinteger(payload[pos:])

		pos = pos + 1
		_ = payload[pos : pos+int(org_table_len)]
		// fmt.Printf("org_table %v\n", org_table)
		// fmt.Printf("org_table is %v\n", string(org_table))
		pos = pos + int(org_table_len)

		// name_len := payload[pos]
		name_len, _ := Lengthencodedinteger(payload[pos:])

		pos = pos + 1
		name := payload[pos : pos+int(name_len)]
		// fmt.Printf("name %v\n", name)
		// fmt.Printf("name is %v\n", string(name))
		pos = pos + int(name_len)

		// org_name_len := payload[pos]
		org_name_len, _ := Lengthencodedinteger(payload[pos:])

		pos = pos + 1
		_ = payload[pos : pos+int(org_name_len)]
		// fmt.Printf("org_name %v\n", org_name)
		// fmt.Printf("org_name is %v\n", string(org_name))
		pos = pos + int(org_name_len)

		_ = payload[pos]
		pos = pos + 1
		// fmt.Printf("next_length %v\n", next_length)

		charsetbyte := payload[pos : pos+2]
		_ = int(uint16(charsetbyte[0]) | uint16(charsetbyte[1])<<8)
		pos = pos + 2
		// fmt.Printf("charset is %v\n", charset)

		columnlenbyte := payload[pos : pos+4]
		pos = pos + 4
		_ = int(uint32(columnlenbyte[0]) | uint32(columnlenbyte[1])<<8 | uint32(columnlenbyte[1])<<16 | uint32(columnlenbyte[1])<<24)
		// fmt.Printf("columnlen is %v\n", columnlen)

		ctype := payload[pos]
		pos = pos + 1
		// fmt.Printf("column type is %v\n", ctype)

		col[string(schema)+"."+string(table)+"."+string(name)] = ctype
		fmt.Printf(string(name) + "\t|")
		_ = payload[pos : pos+2]
		pos = pos + 2
		// fmt.Printf("flag is %v\n", flags)

		_ = payload[pos : pos+1]
		pos = pos + 1
		// fmt.Printf("decimals is %v\n", decimals)

		_ = payload[pos : pos+2]
		pos = pos + 2
		// fmt.Printf("filter is %v\n", filter)

		if len(payload) > pos {
			// default_len := payload[pos]
			default_len, _ := Lengthencodedinteger(payload[pos:])

			pos = pos + 1
			defaultval := payload[pos : pos+int(default_len)]
			fmt.Printf("default value is %v\n", defaultval)
		}

	}

}

func ReadColunValue(rw *ReaderWriter, columnNumber uint64, col map[string]byte) {
	var err error
	// 读取行内容 Each row is a packet,
	// fmt.Printf("the column number is %v\n", len(col))
	for {

		_, payload := ReadPacket(rw.Br)

		if err != nil {
			fmt.Println("get row content err", err.Error())
		}
		// fmt.Printf("row is %v\n", payload)
		if payload[0] == 254 {
			break
		}
		// 获取每一列的值

		pos := uint64(0)
		for j := 0; j < len(col); j++ {
			len, null := Lengthencodedinteger(payload[pos:])
			pos = pos + 1

			if null {
				fmt.Printf("null\t")
			} else {
				// fmt.Printf("the value len is %v\n", len)
				value := payload[pos : pos+len]
				pos = pos + len
				fmt.Printf("%v\t", string(value))
			}

		}
		fmt.Println()

	}
}

type ReaderWriter struct {
	Br *bufio.Reader
	Wr net.Conn
}

func HandleSelect(rw *ReaderWriter, sql string) (err error) {
	// 向服务器发送查询命令send query

	SendCommandArgs(rw, myconstant.COM_QUERY, sql)

	Readresult(rw)
	return nil
}
func HandleQuery(rw *ReaderWriter, sql string) (err error) {
	sql = strings.TrimRight(sql, ";")

	var stmt sqlparser.Statement
	stmt, err = sqlparser.Parse(sql)
	if err != nil {
		return fmt.Errorf(`parse sql "%s" error %v`, sql, err)
	}

	switch stmt.(type) {
	case *sqlparser.Select:
		return HandleSelect(rw, sql)

	default:
		return fmt.Errorf("statement %T not support now", stmt)
	}
}
