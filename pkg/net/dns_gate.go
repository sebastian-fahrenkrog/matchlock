package net

import (
	"golang.org/x/net/dns/dnsmessage"
)

// nameFilter decides whether a queried name may be forwarded upstream.
type nameFilter func(name string) bool

// gateDNSQuery checks every question in a guest query against allow.
//
// It returns nil when the query may be forwarded. Otherwise it returns a
// REFUSED answer to send back instead, and the first refused name. A query
// that does not parse is refused as well: forwarding bytes the gate could not
// read would let them past it.
func gateDNSQuery(query []byte, allow nameFilter) ([]byte, string) {
	if allow == nil {
		return nil, ""
	}
	var p dnsmessage.Parser
	header, err := p.Start(query)
	if err != nil {
		return refusedAnswer(dnsmessage.Header{}, nil), "<unparsable query>"
	}
	questions, err := p.AllQuestions()
	if err != nil {
		return refusedAnswer(header, nil), "<unparsable query>"
	}
	for _, q := range questions {
		if !allow(q.Name.String()) {
			return refusedAnswer(header, questions), q.Name.String()
		}
	}
	return nil, ""
}

// refusedAnswer builds a REFUSED response echoing the query's ID and questions.
func refusedAnswer(query dnsmessage.Header, questions []dnsmessage.Question) []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               query.ID,
			Response:         true,
			OpCode:           query.OpCode,
			RecursionDesired: query.RecursionDesired,
			RCode:            dnsmessage.RCodeRefused,
		},
		Questions: questions,
	}
	out, err := msg.Pack()
	if err != nil {
		return nil
	}
	return out
}
