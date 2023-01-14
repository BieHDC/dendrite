package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
)

func startLandingpage(localaddr string) {
	http.HandleFunc("/", landing(localaddr)) //yes it can handle subpages

	//remove the socket from the previous run if it exists
	if _, err := os.Stat(localaddr); err == nil {
		if err := os.RemoveAll(localaddr); err != nil {
			fmt.Println("failed to remove old socket:", err.Error())
		}
	}

	unixListener, err := net.Listen("unix", localaddr) //avoid clash by using our local i2p address
	if err != nil {
		panic(err) //yes in this case
	}
	http.Serve(unixListener, nil)
}

func handleclient(conn net.Conn, localaddr string) {
	//fixme we could just let the user define a page to dial
	//and we could allow for an automatic redirect to another page

	//open a local connection to the server
	connloc, err := net.Dial("unix", localaddr)
	if err != nil {
		fmt.Println("failed to dial local webserver:", err.Error())
		return
	}
	//proxy the connections
	go io.Copy(connloc, conn)
	io.Copy(conn, connloc)
}

//go:embed landing.html
var landinghtml string

func landing(localaddr string) http.HandlerFunc {
	landingtemplate := template.Must(template.New("landingpage").Parse(landinghtml))

	type Landingargs struct {
		I2PAddress string
	}
	buf := &bytes.Buffer{}
	err := landingtemplate.Execute(buf, Landingargs{I2PAddress: localaddr})
	if err != nil {
		panic(err.Error())
	}
	finalpage := buf.Bytes()

	return func(w http.ResponseWriter, req *http.Request) {
		io.Copy(w, bytes.NewBuffer(finalpage))
	}
}
