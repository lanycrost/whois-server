Unix whois service

This service implements the WHOIS protocol as described in [RFC 3912](https://tools.ietf.org/html/rfc3912). The protocol allows to query the Registry about registrable objects.

This module translates incoming WHOIS requests into PostgreSQL query and then translates their results back to outgoing WHOIS responses.

Each response contains the link to the web whois service site which can be used to win full information about domain owners and administrative contacts.

The unix whois service allows to query even ENUM domains, although these responses do not contain the link to the web whois because the rules of information disclosure that apply to ENUM domains are different from those of common domains.

The service is built on a [Golang](https://golang.org/).

The Database is built in [PostgreSQL](https://www.postgresql.org).

For Starting server you should be set some environment variables.

    - TLDNAME: Name of TLD (AM, COM, GE, etc.).
    - TLDWHOISADDR: TLD WHOIS Server address (whois.amnic.net, whois.markmonitor.com, etc.).
    - TLDS: Server top and second level TLD's list (.ge, .gov.ge, .com, etc.).
    - DBHOST: Host of postgres DB (localhost, etc.).
    - DBUNAME: Username of DB
    - DBPSWD: Password for access to DB
    - DBNAME: DB name where store the WHOIS data
     
```
DBNAME=AMNIC TLDWHOISADDR=whois.amnic.net TLDS=.ge,.gov.ge,.school.ge DBHOST=localhost DBUNAME=root DBPSWD=root DBNAME=whois go run main.go
```

    Golang Version: 1.9.1
    Postgres Version: 10.1 

Golang Packages:
  - [net](https://golang.org/pkg/net/)
  - [time](https://golang.org/pkg/time/)
  - [strings](https://golang.org/pkg/strings/)
  - [text/template](https://golang.org/pkg/text/template/)
  - [bytes](https://golang.org/pkg/bytes/)
  - [log](https://golang.org/pkg/log/) TODO migrate to [syslog](https://golang.org/pkg/log/syslog/)
  - [os](https://golang.org/pkg/os/)
  - [gorm](http://jinzhu.me/gorm/)

Authors:
  - [Khachatur Ashotyan](mailto:khachatur.ashotyan@gmail.com)