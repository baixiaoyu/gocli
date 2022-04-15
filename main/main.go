package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"gocli/cli"
	"gocli/myconstant"
)

func main() {

	var host string
	var port string
	flag.StringVar(&port, "p", "3306", "specify port to use.  defaults to 3306.")
	flag.StringVar(&host, "h", "127.0.0.1", "specify host to use.  defaults to 127.0.0.1.")
	flag.Parse()
	addr := host + ":" + port

	conn := cli.GetConnection("tcp", addr)
	var br = bufio.NewReaderSize(conn, 1024)
	rw := &cli.ReaderWriter{Br: br, Wr: conn}

	// 服务端发送 Initial Handshake Packet 客户端接收后回复 Handshake Response Packet
	// https://dev.mysql.com/doc/internals/en/plain-handshake.html
	// 下面客户端开始接受initial packet https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake
	salt := cli.ReadInitialHandshake(rw)

	cli.WriteHandshakeResponse41(rw, salt)
	// 客户端写回复writeHandshakeResponse41

	cli.ReadOkPacket(rw)
	// read ok

	// 向服务端发送ping命令 https://dev.mysql.com/doc/internals/en/com-ping.html
	cli.SendCommand(rw, myconstant.COM_PING)

	fmt.Println("Welcome to the Go MySQL CLI.  Commands end with ;")
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Type your command > ")
	for scanner.Scan() {
		fmt.Print("Type your command  > ")
		line := scanner.Text()
		if line == "exit" {
			os.Exit(0)
		}
		cli.HandleQuery(rw, line)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}

	// // 发送use db命令
	// arg := "test"
	// sendCommandArgs(rw, COM_INIT_DB, arg)

	// // 向服务器发送查询命令send query

	// arg = "select * from test.dba_test"
	// sendCommandArgs(rw, COM_QUERY, arg)

	// readresult(rw)

}
