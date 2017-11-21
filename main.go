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
	"log/syslog"
	"os"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"fmt"
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
	// DB interface
	DB 		*gorm.DB
	// interface for logging
	LOGGER 	*syslog.Writer
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
	// DB SSL Mode
	DBSSL = os.Getenv( "DBSSL" )
)


func main() {
	InitLogger()
	InitDB()

	// Close DB and logger when end the program
	defer DB.Close()
	defer LOGGER.Close()

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

// Initialize logger interface
// return logger representation pointer
func InitLogger() {
	var err error
	if LOGGER, err = syslog.New(syslog.LOG_ERR, "WHOIS Server"); err != nil {
		log.Fatal(err)
	}
}

func InitDB() {
	var err error

	if DB, err = gorm.Open("postgres", fmt.Sprintf("host=%s user=%s dbname=%s password=%s sslmode=%s",
		DBHOST, DBUNAME, DBNAME, DBPSWD, DBSSL ) ); err != nil {
		log.Fatal(err)
	}
}

// Initialize Template by name and path
// name name of template
// content response content
// template representation pointer
func InitTemplate( name string, content string ) *template.Template {
	tmpl, err := template.New(name).Parse(content) // allocates a new, undefined template with the given nam.

	checkError(err)
	tpl.Reset() // reset buffer story

	return tmpl
}

// Initialize Help template
// return help template
func InitHelp() string {
	helpTemplate := InitTemplate("Help", helpContent) // initialize template pointer

	err := helpTemplate.ExecuteTemplate(&tpl,"Help", nil)  // write template with given parameter
	checkError(err)

	return tpl.String()
}

// Initialize Success Template for handling success queries
// return template representation pointer
func InitSuccess() *template.Template {
	return InitTemplate("Success", successContent)
}

// Initialize Success More Template for handling success queries
// return template representation pointer
func InitSuccessMore() *template.Template {
	return InitTemplate("Success More", successMoreContent)
}

// Initialize No Match Template for handling success queries
// return template representation pointer
func InitNoMatch() *template.Template {
	return InitTemplate("No Match", noMatchContent)
}

// Handle Client WHOIS queries
// conn generic stream-oriented network connection.
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
// domain generic stream-oriented network connection.
// if all is OK. return true, if not receive specific error
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

// ---- GORM Models ---- //
// ------- Start ------- //

type DNS struct {
	DNS						string			`gorm:"primary_key;column:dns"`
	StatusID				uint			`gorm:"column:statusId"`
	HasDnsSec				bool			`gorm:"column:hasDnsSec"`
	RegistrarID				uint			`gorm:"column:registrarId"`
	UpdatedDate				time.Time		`gorm:"column:updatedDate"`
	CreationDate			time.Time		`gorm:"column:creationDate"`
	ExpirationDate			time.Time		`gorm:"column:expirationDate"`
	Status					string  		`gorm:"type:varchar(10);column:status"`
	DnsSecStatus			string			`gorm:"type:varchar(20);column:dnsSecStatus"`

	// Registrar info
	RegistrarName			string			`gorm:"type:varchar;column:registrarName"`
	RegistrarUrl			string			`gorm:"type:varchar;column:registrarUrl"`
	RegistrarContactEmail	string			`gorm:"type:varchar;column:registrarContactEmail"`
	RegistrarContactPhone	string			`gorm:"type:varchar;column:registrarContactPhone"`

	// Registrant info
	RegistrantName  		string  		`gorm:"type:varchar;column:registrantName"`
	RegistrantOrganization  string  		`gorm:"type:varchar;column:registrantOrganization"`
	RegistrantStreet		string  		`gorm:"type:varchar;column:registrantStreet"`
	RegistrantCity			string  		`gorm:"type:varchar;column:registrantCity"`
	RegistrantProvince		string  		`gorm:"type:varchar;column:registrantProvince"`
	RegistrantZipCode		uint	  		`gorm:"type:varchar;column:registrantZipCode"`
	RegistrantCountry		string  		`gorm:"type:varchar;column:registrantCountry"`
	RegistrantPhone			string  		`gorm:"type:varchar;column:registrantPhone"`
	RegistrantPhoneExt		string  		`gorm:"type:varchar;column:registrantPhoneExt"`
	RegistrantFax			string  		`gorm:"type:varchar;column:registrantFax"`
	RegistrantFaxExt		string  		`gorm:"type:varchar;column:registrantFaxExt"`
	RegistrantEmail			string  		`gorm:"type:varchar;column:registrantEmail"`

	// Admin info
	AdminName  				string  		`gorm:"type:varchar;column:adminName"`
	AdminOrganization  		string  		`gorm:"type:varchar;column:adminOrganization"`
	AdminStreet				string  		`gorm:"type:varchar;column:adminStreet"`
	AdminCity				string  		`gorm:"type:varchar;column:adminCity"`
	AdminProvince			string  		`gorm:"type:varchar;column:adminProvince"`
	AdminZipCode			uint	  		`gorm:"type:varchar;column:adminZipCode"`
	AdminCountry			string  		`gorm:"type:varchar;column:adminCountry"`
	AdminPhone				string  		`gorm:"type:varchar;column:adminPhone"`
	AdminPhoneExt			string  		`gorm:"type:varchar;column:adminPhoneExt"`
	AdminFax				string  		`gorm:"type:varchar;column:adminFax"`
	AdminFaxExt				string  		`gorm:"type:varchar;column:adminFaxExt"`
	AdminEmail				string  		`gorm:"type:varchar;column:adminEmail"`

	// Tech info
	TechName  				string  		`gorm:"type:varchar;column:techName"`
	TechOrganization  		string  		`gorm:"type:varchar;column:techOrganization"`
	TechStreet				string  		`gorm:"type:varchar;column:techStreet"`
	TechCity				string  		`gorm:"type:varchar;column:techCity"`
	TechProvince			string  		`gorm:"type:varchar;column:techProvince"`
	TechZipCode				uint	  		`gorm:"type:varchar;column:techZipCode"`
	TechCountry				string  		`gorm:"type:varchar;column:techCountry"`
	TechPhone				string  		`gorm:"type:varchar;column:techPhone"`
	TechPhoneExt			string  		`gorm:"type:varchar;column:techPhoneExt"`
	TechFax					string  		`gorm:"type:varchar;column:techFax"`
	TechFaxExt				string  		`gorm:"type:varchar;column:techFaxExt"`
	TechEmail				string  		`gorm:"type:varchar;column:techEmail"`

	Nameservers				[]Nameserver
}

type Nameserver struct {
	ID 				uint 	`gorm:"primary_key"`
	DNSName			string	`gorm:"type:varchar(255);column:dns"`
	Nameserver		string	`gorm:"type:varchar(255);column:nameserver"`
}

func (d DNS) TableName() string {
	return "data"
}

func (n Nameserver) TableName() string {
	return "nameserver"
}

// ---- GORM Models ---- //
// -------- End -------- //

// If all is correct send to client success request
// req client request (domain name)
// generic stream-oriented network connection.
func handleSuccess(req string, conn net.Conn) {
	var dns = DNS{}

	DB.Where("dns = ?", req).Find(&dns)

	fmt.Println(dns.DNS)

	if dns.DNS != "" {
		DB.Find(&dns.Nameservers)

		res := struct {
			DNS				DNS
			TLDNAME			string
			TLDWHOISADDR	string
		}{
			DNS:			dns,
			TLDWHOISADDR:	TLDWHOISADDR,
			TLDNAME:		TLDNAME,
		}

		tpl.Reset()
		err := successTemplate.ExecuteTemplate(&tpl,"Success", res)
		checkError(err)
		conn.Write([]byte(tpl.String()))

		tpl.Reset()
		err = successMoreTemplate.ExecuteTemplate(&tpl,"Success More", res)
		checkError(err)
		conn.Write([]byte(tpl.String()))
		conn.Close()
	} else {
		res := struct {
			DNS				string
			TLDNAME			string
			TLDWHOISADDR	string
		}{
			DNS:			req,
			TLDWHOISADDR:	TLDWHOISADDR,
			TLDNAME:		TLDNAME,
		}

		tpl.Reset()
		err := noMatchTemplate.ExecuteTemplate(&tpl,"No Match", res)
		checkError(err)
		conn.Write([]byte(tpl.String()))
		conn.Close()
	}
}

// Fatal Error handling
// Log the message and turn off server
// err error interface
func checkError(err error) {
	if err != nil {
		LOGGER.Err(err.Error())
	}
}

// Warnings handling
// Log the server messages (for example, client closed connection)
// err error interface
func logError(err error) {
	if err != nil {
		LOGGER.Debug(err.Error())
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

Domain Name: {{ .DNS.DNS }}
Updated Date: {{ .DNS.UpdatedDate }}
Creation Date: {{ .DNS.CreationDate }}
Expiration Date: {{ .DNS.ExpirationDate }}
Registrar: {{ .DNS.RegistrarName }}
Registrar URL: {{ .DNS.RegistrarUrl }}
Registrar Abuse Contact Email: {{ .DNS.RegistrarContactEmail }}
Registrar Abuse Contact Phone: {{ .DNS.RegistrarContactPhone }}
Registrant Name: {{ .DNS.RegistrantName }}
Registrant Organization: {{ .DNS.RegistrantOrganization }}
Registrant Street: {{ .DNS.RegistrantStreet }}
Registrant City: {{ .DNS.RegistrantCity }}
Registrant State/Province: {{ .DNS.RegistrantProvince }}
Registrant Postal Code: {{ .DNS.RegistrantZipCode }}
Registrant Country: {{ .DNS.RegistrantCountry }}
Registrant Phone: {{ .DNS.RegistrantPhone }}
Registrant Phone Ext: {{ .DNS.RegistrantPhoneExt }}
Registrant Fax: {{ .DNS.RegistrantFax }}
Registrant Fax Ext: {{ .DNS.RegistrantFaxExt }}
Registrant Email: {{ .DNS.RegistrantEmail }}
`

	// Success More Response Content
	successMoreContent = `
Admin Name: {{ .DNS.AdminName }}
Admin Organization: {{ .DNS.AdminOrganization }}
Admin Street: {{ .DNS.AdminStreet }}
Admin City: {{ .DNS.AdminCity }}
Admin State/Province: {{ .DNS.AdminProvince }}
Admin Postal Code: {{ .DNS.AdminZipCode }}
Admin Country: {{ .DNS.AdminCountry }}
Admin Phone: {{ .DNS.AdminPhone }}
Admin Phone Ext: {{ .DNS.AdminPhoneExt }}
Admin Fax: {{ .DNS.AdminFax }}
Admin Fax Ext: {{ .DNS.AdminFaxExt }}
Admin Email: {{ .DNS.AdminEmail }}
Tech Name: {{ .DNS.TechName }}
Tech Organization: {{ .DNS.TechOrganization }}
Tech Street: {{ .DNS.TechStreet }}
Tech City: {{ .DNS.TechCity }}
Tech State/Province: {{ .DNS.TechProvince }}
Tech Postal Code: {{ .DNS.TechZipCode }}
Tech Country: {{ .DNS.TechCountry }}
Tech Phone: {{ .DNS.TechPhone }}
Tech Phone Ext: {{ .DNS.TechPhoneExt }}
Tech Fax: {{ .DNS.TechFax }}
Tech Fax Ext: {{ .DNS.TechFaxExt }}
Tech Email: {{ .DNS.TechEmail }}
{{range $dns := .DNS.Nameservers}}Name Server: {{ $dns.Nameserver }}
{{end}}
DNSSEC: {{ .DNS.DnsSecStatus }}
`

	// No Match Response Content
	noMatchContent = `
%
%{{ .TLDNAME }} TLD whois server
% Please see 'whois -h {{ .TLDWHOISADDR }} help' for usage.
%

No match for "{{ .DNS }}".
`
)
