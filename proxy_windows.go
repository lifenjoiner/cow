package main

import (
	"fmt"
	"net"
	"strings"
	"syscall"
)

var _ = fmt.Println

func isErrConnReset(err error) bool {
	// fmt.Printf("calling isErrConnReset for err type: %v Error() %s\n",
	// reflect.TypeOf(err), err.Error())
	if ne, ok := err.(*net.OpError); ok {
		// fmt.Println("isErrConnReset net.OpError.Err type:", reflect.TypeOf(ne))
		errMsg := ne.Err.Error()
		if errno, enok := ne.Err.(syscall.Errno); enok {
			// I got these number by print. Only tested on XP.
			// debug.Println("isErrConnReset errno:", errno)
			return errno == 64 || errno == 10054
		} else if strings.Contains(errMsg, "forcibly closed") || strings.Contains(errMsg, " timeout") {
			// "forcibly closed"
			// "use of closed network connection" occurs in firefox session reloading, legal close
			return true
		} else if ne.Err != nil {
			// wsasend: An established connection was aborted by the software in your host machine.
			// Not firewall interruption error, FIN following request
			debug.Println("isErrConnReset Err:", ne.Err)
		}
	}
	return false
}

// The error msg:
// 1. dial tcp: lookup ***.***.com: getaddrinfow: The requested name is valid,
//    but no data of the requested type was found.
// 2. dial tcp: lookup abc.dddeeeff.com: no such host
func isDNSError(err error) bool {
	// DNS error are not of type DNSError on Windows
	errMsg := err.Error()
	return strings.Contains(errMsg, " lookup ")
}

func isErrOpWrite(err error) bool {
	ne, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	return ne.Op == "WSASend"
}

func isErrOpRead(err error) bool {
	ne, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	return ne.Op == "WSARecv"
}

func isErrTooManyOpenFd(err error) bool {
	// TODO implement this.
	return false
}
