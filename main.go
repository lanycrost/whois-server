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
	"regexp"
	"log"
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
	// Initializing top level error template
	topErrTemplate = InitTopError()
	// Initializing second level error template
	secondErrTemplate = InitSecondError()
	// Initializing syntax error template
	syntaxErrTemplate = InitSyntaxError()
	// Initializing domain name length error template
	lenErrTemplate = InitLenError()
	// Initializing success template
	successTemplate = InitSuccess()
	// Initializing success more template
	successMoreTemplate = InitSuccessMore()
	// Buffer initializing
	tpl bytes.Buffer
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
// @param {string} path path of template
// @return {*template.Template} template representation pointer
func InitTemplate( name string, path string ) *template.Template {
	t := template.New(name) // allocates a new, undefined template with the given name.

	tmpl, err := t.ParseFiles(path) // parses the named files and associates the resulting templates with t
	checkError(err)
	tpl.Reset() // reset buffer story

	return tmpl
}

// Initialize Help template
// @return {string} help template
func InitHelp() string {
	helpTemplate := InitTemplate("Help", "./tmpl/help") // initialize template pointer

	err := helpTemplate.ExecuteTemplate(&tpl,"help", nil)  // write template with given parameter
	checkError(err)

	return tpl.String()
}

// Initialize Length Error template
// @return {string} length error template
func InitLenError() string {
	helpTemplate := InitTemplate("Error", "./tmpl/error/len_error") // initialize template pointer

	err := helpTemplate.ExecuteTemplate(&tpl,"len_error", nil) // write template with given parameter
	checkError(err)

	return tpl.String()
}

// Initialize Syntax Error template
// @return {string} syntax error template
func InitSyntaxError() string {
	helpTemplate := InitTemplate("Error", "./tmpl/error/syntax_error") // initialize template pointer

	err := helpTemplate.ExecuteTemplate(&tpl,"syntax_error", nil) // write template with given parameter
	checkError(err)

	return tpl.String()
}

// Initialize Top Level Error template
// @return {string} top level error template
func InitTopError() string {
	helpTemplate := InitTemplate("Error", "./tmpl/error/top_level_error") // initialize template pointer

	err := helpTemplate.ExecuteTemplate(&tpl,"top_level_error", nil) // write template with given parameter
	checkError(err)

	return tpl.String()
}

// Initialize Second Level Error template
// @return {string} second level error template
func InitSecondError() string {
	helpTemplate := InitTemplate("Error", "./tmpl/error/second_level_error") // initialize template pointer

	err := helpTemplate.ExecuteTemplate(&tpl,"second_level_error", nil) // write template with given parameter
	checkError(err)

	return tpl.String()
}

// Initialize Success Template for handling success queries
// @return {*template.Template} template representation pointer
func InitSuccess() *template.Template {
	return InitTemplate("Success", "./tmpl/success/success")
}

// Initialize Success More Template for handling success queries
// @return {*template.Template} template representation pointer
func InitSuccessMore() *template.Template {
	return InitTemplate("Success", "./tmpl/success/success_more")
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
				if checkDomain(req, conn) { // check query correction
					handleSuccess(req, conn) // all is correct send to client WHOIS data
				}

			}
		}
	}
}

// Check domain name correctness
// @param {string} domain generic stream-oriented network connection.
// @param {net.Conn} conn generic stream-oriented network connection.
// @return {bool} if all is OK. return true, if not receive specific error
func checkDomain(domain string, conn net.Conn) bool {
	domain = strings.ToLower(domain) // domain name to lowercase
	match, _ := regexp.MatchString(`^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$`, domain ) // check domain name correctness by regex

	if ! match {
		conn.Write([]byte(syntaxErrTemplate)) // client have syntax error
		conn.Close()
	} else {
		domainParts := strings.Split(domain, ".") // check domain name parts

		// check this domain name is belongs to us
		if ( len(domainParts) == 2 && domainParts[1] == "ge" ) ||
			( len(domainParts) == 3 && (
				( domainParts[1] == "com" ||
					domainParts[1] == "edu" ||
					domainParts[1] == "gov" ||
					domainParts[1] == "org" ||
					domainParts[1] == "mil" ||
					domainParts[1] == "net" ||
					domainParts[1] == "pvt" ) && domainParts[2] == "ge" ) ) {
			if len(domainParts[0]) < 2 {
				conn.Write([]byte(lenErrTemplate)) // for finish check domain name length correctness
				conn.Close()
			}
			return true
		} else {
			// send specific error by domain name
			if len(domainParts) == 2 {
				conn.Write([]byte(topErrTemplate)) // send top level error
				conn.Close()
			} else {
				conn.Write([]byte(secondErrTemplate)) // send second level serror
				conn.Close()
			}
		}
	}

	return true
}

type SuccessData struct {
	DomainName	string
	Registrar	string
	Status		string
	Registrant	Registrant
}

type Registrant struct {
	Name		string
	Address1	string
	Address2	string
	ZIP			string
	Country		string
}

type SuccessMoreData struct {
	Administrative	Administrative
	Technical		Technical
	DNS				[]string
	Registered		string
	Modified		string
	Expires			string
}

type Administrative struct {
	Name		string
	Address1	string
	Address2	string
	ZIP			string
	Country		string
	Email		string
	Phone		string
}

type Technical struct {
	Name		string
	Address1	string
	Address2	string
	ZIP			string
	Country		string
	Email		string
	Phone		string
}

// TODO::Connect to database and send request
// If all is correct send to client success request
// @param {string} req client request (domain name)
// @param {net.Conn} generic stream-oriented network connection.
func handleSuccess(req string, conn net.Conn) {
	tpl.Reset()
	err := successTemplate.ExecuteTemplate(&tpl,"success", SuccessData{
		DomainName: req,
		Registrar: "RegNest.com (RegNest LLC)",
		Status: "active, registrar locked",
		Registrant: Registrant{
			Name: "John Doe",
			Address1: "123 6th St.",
			Address2: "Melbourne, FL",
			ZIP: "32904",
			Country: "US",
		},
	} )
	checkError(err)
	conn.Write([]byte(tpl.String()))

	tpl.Reset()
	err = successMoreTemplate.ExecuteTemplate(&tpl,"success_more", SuccessMoreData{
		Administrative: Administrative{
			Name: "John Doe",
			Address1: "123 6th St.",
			Address2: "Melbourne, FL",
			ZIP: "32904",
			Country: "US",
			Phone:"6503491051",
			Email:"john@doe.ge",
		},
		Technical: Technical{
			Name: "John Doe",
			Address1: "123 6th St.",
			Address2: "Melbourne, FL",
			ZIP: "32904",
			Country: "US",
			Phone:"6503491051",
			Email:"john@doe.ge",
		},
		DNS: []string{"coco.ns.cloudflare.com","todd.ns.cloudflare.com"},
		Registered: "2004-12-28",
		Modified: "2017-06-14",
		Expires: "2022-12-28",
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