// Copyright 2017 GlobalR LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
// ---------------------------------------------------------
// WHOIS server
// ---------------------------------------------------------
// Author Khachatur Ashtotyan <khachatur.ashotyan@gmail.com>

package main

import (
	"net"
	"time"
	"strings"
	"text/template"
	"bytes"
	"log"
	"os"
)

const (
	// Servers listen to requests on the well-known port number 43
	port = ":43"
	// Set maximum connection time (deadline)
	maxConnTime = 10 * time.Second
	// Set maximum request length
	maxReqLength = 64
)

var (
	// Initializing help template
	helpTemplate = InitHelp()
	// Initializing success template
	successTemplate = InitSuccess()
	// Initializing success more template
	successMoreTemplate = InitSuccessMore()
	// Initializing no match template
	noMatchTemplate = InitNoMatch()
	// Buffer initializing
	tpl bytes.Buffer
	// TLD Name
	TLDNAME = os.Getenv( "TLDNAME" )
	// TLD WHOIS Server address
	TLDWHOISADDR = os.Getenv( "TLDWHOISADDR" )
	// TLD's list
	TLDS = strings.Split(os.Getenv( "TLDS" ), ",")
	// DB Host
	DBHOST = os.Getenv( "DBHOST" )
	// DB Username
	DBUNAME = os.Getenv( "DBUNAME" )
	// DB Password
	DBPSWD = os.Getenv( "DBPSWD" )
	// DB Name
	DBNAME = os.Getenv( "DBNAME" )
)


func main() {
	// Resolve TCP address
	tcpAddr, err := net.ResolveTCPAddr("tcp4", port)
	checkError(err)
	// Initialize TCP Listener
	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)

	for {
		conn, err := listener.Accept() // waits for the next call and returns a generic Conn

		if err != nil {
			continue
		}

		// Handle TCP queries
		go handleClient(conn)
	}
}

// Initialize Template by name and path
// @param {string} name name of template
// @param {string} content response content
// @return {*template.Template} template representation pointer
func InitTemplate( name string, content string ) *template.Template {
	tmpl, err := template.New(name).Parse(content) // allocates a new, undefined template with the given nam.

	checkError(err)
	tpl.Reset() // reset buffer story

	return tmpl
}

// Initialize Help template
// @return {string} help template
func InitHelp() string {
	helpTemplate := InitTemplate("Help", helpContent) // initialize template pointer

	err := helpTemplate.ExecuteTemplate(&tpl,"Help", nil)  // write template with given parameter
	checkError(err)

	return tpl.String()
}

// Initialize Success Template for handling success queries
// @return {*template.Template} template representation pointer
func InitSuccess() *template.Template {
	return InitTemplate("Success", successContent)
}

// Initialize Success More Template for handling success queries
// @return {*template.Template} template representation pointer
func InitSuccessMore() *template.Template {
	return InitTemplate("Success More", successMoreContent)
}

func InitNoMatch() *template.Template {
	return InitTemplate("No Match", noMatchContent)
}

// Handle Client WHOIS queries
// @param {net.Conn} conn generic stream-oriented network connection.
func handleClient(conn net.Conn) {
	conn.SetReadDeadline(time.Now().Add(maxConnTime)) // set maximum connection time 10 second
	request := make([]byte, maxReqLength) // set maximum request length to 128B to prevent flood based attacks
	defer conn.Close()  // close connection before exit
	for {
		readLen, err := conn.Read(request) // read client query

		if err != nil {
			logError(err)
			break
		}

		if readLen == 0 {
			break // connection already closed by client
		} else {
			req := strings.TrimSpace(string(request[:readLen])) // client query object

			if req == "help" {
				conn.Write([]byte(helpTemplate)) // client receive help
				conn.Close()
			} else {
				if checkDomain(req) { // check query correction
					handleSuccess(req, conn) // all is correct send to client WHOIS data
				} else {
					conn.Close() // we are don't owner of this TLD...
				}

			}
		}
	}
}

// Check domain name correctness
// @param {string} domain generic stream-oriented network connection.
// @return {bool} if all is OK. return true, if not receive specific error
func checkDomain(domain string) bool {
	hasOccurrence := false
	tldPart := domain[strings.Index(domain, "."):] // find part tld in string

	for _, tld := range TLDS {
		if strings.ToUpper(tldPart) == strings.ToUpper(tld) {
			hasOccurrence = true
			break
		}
	}

	return hasOccurrence
}

type SuccessData struct {
	TLDNAME			string
	TLDWHOISADDR		string
	DomainName		string
	Registrar		Registrar
	Status			string
	DomainID		string
	UpdatedDate		string
	CreationDate	string
	ExpirationDate	string
	Registrant		Registrant
}

type Registrant struct {
	Name			string
	Organization	string
	Street			string
	City			string
	State			string
	ZIP				string
	Country			string
	Phone			string
	PhoneExt		string
	Fax				string
	FaxExt			string
	Email			string
}

type Registrar struct {
	Name	string
	URL		string
	Email	string
	Phone	string
}

type SuccessMoreData struct {
	Administrative	Administrative
	Technical		Technical
	DNS				[]string
	DNSSEC			string
}

type Administrative struct {
	Name			string
	Organization 	string
	Street			string
	City			string
	State			string
	ZIP				string
	Country			string
	Email			string
	Phone			string
	PhoneExt		string
	Fax				string
	FaxExt			string
}

type Technical struct {
	Name			string
	Organization 	string
	Street			string
	City			string
	State			string
	ZIP				string
	Country			string
	Email			string
	Phone			string
	PhoneExt		string
	Fax				string
	FaxExt			string
}

// TODO::Connect to database and send request
// If all is correct send to client success request
// @param {string} req client request (domain name)
// @param {net.Conn} generic stream-oriented network connection.
func handleSuccess(req string, conn net.Conn) {
	tpl.Reset()
	err := successTemplate.ExecuteTemplate(&tpl,"Success", SuccessData{
		TLDNAME: TLDNAME,
		TLDWHOISADDR: TLDWHOISADDR,
		DomainName: req,
		DomainID: "426007",
		UpdatedDate: "2017-04-21T02:06:59-0700",
		CreationDate: "1990-05-21T21:00:00-0700",
		ExpirationDate: "2019-05-22T00:00:00-0700",
		Registrar: Registrar{
			Name: "RegNest.com (RegNest LLC)",
			URL: "https://regnest.com",
			Email: "support@regnest.com",
			Phone: "+37493305688",
		},
		Registrant: Registrant{
			Name: "John Doe",
			Organization: "World LLC.",
			Street: "123 6th St.",
			City: "Melbourne",
			State: "FL",
			Country: "US",
			Phone: "+37493305688",
			PhoneExt: "",
			Fax: "+37493305688",
			FaxExt: "",
			ZIP: "32904",
			Email: "john@doe.com",

		},
	} )
	checkError(err)
	conn.Write([]byte(tpl.String()))

	tpl.Reset()
	err = successMoreTemplate.ExecuteTemplate(&tpl,"Success More", SuccessMoreData{
		Administrative: Administrative{
			Name: "John Doe",
			Organization: "World LLC.",
			Street: "123 6th St.",
			City: "Melbourne",
			State: "FL",
			ZIP: "32904",
			Country: "US",
			Phone: "6503491051",
			PhoneExt: "",
			Fax: "6503491051",
			FaxExt:"",
			Email:"john@doe.ge",
		},
		Technical: Technical{
			Name: "John Doe",
			Organization: "World LLC.",
			Street: "123 6th St.",
			City: "Melbourne",
			State: "FL",
			ZIP: "32904",
			Country: "US",
			Phone:"6503491051",
			PhoneExt: "",
			Fax: "6503491051",
			FaxExt:"",
			Email:"john@doe.ge",
		},
		DNS: []string{"coco.ns.cloudflare.com","todd.ns.cloudflare.com"},
		DNSSEC: "unsigned",
	} )
	checkError(err)
	conn.Write([]byte(tpl.String()))
	conn.Close()
}

// Fatal Error handling
// Log the message and turn off server
// @param {error} err error interface
func checkError(err error) {
	if err != nil {
		log.Fatalf("Fatal error: %s", err.Error())
	}
}

// Warnings handling
// Log the server messages (for example, client closed connection)
// @param {error} err error interface
func logError(err error) {
	if err != nil {
		log.Printf("Warning: %s", err.Error())
	}
}

// Template Variables
const (
	// Help Response content
	helpContent = `
	
	HELP
	
`

	// Success Response Content
	successContent = `
%
%{{ .TLDNAME }} TLD whois server
% Please see 'whois -h {{ .TLDWHOISADDR }} help' for usage.
%

Domain Name: {{ .DomainName }}
Registry Domain ID: {{ .DomainID }}
Updated Date: {{ .UpdatedDate }}
Creation Date: {{ .CreationDate }}
Expiration Date: {{ .ExpirationDate }}
Registrar: {{ .Registrar.Name }}
Registrar URL: {{ .Registrar.URL }}
Registrar Abuse Contact Email: {{ .Registrar.Email }}
Registrar Abuse Contact Phone: {{ .Registrar.Phone }}
Registrant Name: {{ .Registrant.Name }}
Registrant Organization: {{ .Registrant.Organization }}
Registrant Street: {{ .Registrant.Street }}
Registrant City: {{ .Registrant.City }}
Registrant State/Province: {{ .Registrant.State }}
Registrant Postal Code: {{ .Registrant.ZIP }}
Registrant Country: {{ .Registrant.Country }}
Registrant Phone: {{ .Registrant.Phone }}
Registrant Phone Ext: {{ .Registrant.PhoneExt }}
Registrant Fax: {{ .Registrant.Fax }}
Registrant Fax Ext: {{ .Registrant.FaxExt }}
Registrant Email: {{ .Registrant.Email }}
`

	// Success More Response Content
	successMoreContent = `
Admin Name: {{ .Administrative.Name }}
Admin Organization: {{ .Administrative.Organization }}
Admin Street: {{ .Administrative.Street }}
Admin City: {{ .Administrative.City }}
Admin State/Province: {{ .Administrative.State }}
Admin Postal Code: {{ .Administrative.ZIP }}
Admin Country: {{ .Administrative.Country }}
Admin Phone: {{ .Administrative.Phone }}
Admin Phone Ext: {{ .Administrative.PhoneExt }}
Admin Fax: {{ .Administrative.Fax }}
Admin Fax Ext: {{ .Administrative.FaxExt }}
Admin Email: {{ .Administrative.Email }}
Tech Name: {{ .Technical.Name }}
Tech Organization: {{ .Technical.Organization }}
Tech Street: {{ .Technical.Street }}
Tech City: {{ .Technical.City }}
Tech State/Province: {{ .Technical.State }}
Tech Postal Code: {{ .Technical.ZIP }}
Tech Country: {{ .Technical.Country }}
Tech Phone: {{ .Technical.Phone }}
Tech Phone Ext: {{ .Technical.PhoneExt }}
Tech Fax: {{ .Technical.Fax }}
Tech Fax Ext: {{ .Technical.FaxExt }}
Tech Email: {{ .Technical.Email }}
{{range $dns := .DNS}}Name Server: {{ $dns }}
{{end}}
DNSSEC: {{ .DNSSEC }}
`

	// No Match Response Content
	noMatchContent = `
%
%{{ .TLDNAME }} TLD whois server
% Please see 'whois -h {{ .TLDWHOISURL }} help' for usage.
%

No match for "{{ .DomainName }}".
`

)
