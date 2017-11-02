Unix whois service

This service implements the WHOIS protocol as described in [RFC 3912](https://tools.ietf.org/html/rfc3912). The protocol allows to query the Registry about registrable objects.

This module translates incoming WHOIS requests into PostgreSQL query and then translates their results back to outgoing WHOIS responses.

Each response contains the link to the web whois service site which can be used to win full information about domain owners and administrative contacts.

The unix whois service allows to query even ENUM domains, although these responses do not contain the link to the web whois because the rules of information disclosure that apply to ENUM domains are different from those of common domains.

The service is built on a [Golang](https://golang.org/).

Authors:
  - [Khachatur Ashotyan](mailto:khachatur.ashotyan@gmail.com)