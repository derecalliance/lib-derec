// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/derecalliance/lib-derec/packages/go/derecpb"
)

// ContactMode selects how the public encryption material is delivered in
// the ContactMessage CreateContact produces. Mirrors
// org.derecalliance.derec.protobuf.ContactMode (see derecpb.ContactMode);
// values match the wire enum exactly.
type ContactMode int32

const (
	// ContactModeInlineKeys embeds the ML-KEM encapsulation key and ECIES
	// public key directly in the contact. Default.
	ContactModeInlineKeys ContactMode = 0
	// ContactModeHashedKeys embeds only a SHA-384 binding hash; the
	// recipient obtains the real keys via a PrePair round trip and
	// verifies them against the hash.
	ContactModeHashedKeys ContactMode = 1
	// ContactModeNoKeys carries no key material and no hash — only
	// channel_id, nonce, and transport_protocol. The contact creator
	// generates key material on the fly when the corresponding
	// PrePairRequest arrives; trust rests entirely on the out-of-band
	// delivery channel being fully trusted.
	//
	// Because nothing binds the published keys to the contact, the channel
	// is held at ChannelStatusPending until VerifyFingerprint succeeds on
	// both sides: it is not a publish target, not a recovery source, and
	// inbound messages on it are ignored. A man-in-the-middle on the
	// plaintext PrePair leg leaves the two sides with different shared keys
	// and so different fingerprints, which is what the comparison catches —
	// the role the binding hash plays for ContactModeHashedKeys.
	ContactModeNoKeys ContactMode = 2
)

// CreatedContact is the result of CreateContact: the out-of-band
// ContactMessage to share, and the channel id it carries (either the
// caller-supplied value or the one the library minted).
type CreatedContact struct {
	// ContactBytes is the prost-encoded ContactMessage to deliver
	// out-of-band (QR code, deep link, …).
	ContactBytes []byte
	// ChannelID is the channel identifier carried by the contact — the
	// recipient echoes it in the pairing request, and it resolves the
	// pairing state this call persisted internally.
	ChannelID uint64
}

// CreateContact generates an out-of-band ContactMessage that bootstraps
// pairing. Either party (Owner or Helper) may call this. The material the
// library needs later — the ephemeral pairing secret for InlineKeys /
// HashedKeys, or the contact itself for NoKeys — is persisted automatically
// via the configured stores; it is not returned here.
//
// channelID nil lets the library mint a random id; a non-nil value is used
// verbatim (NoKeys contacts typically use a small human-typable value).
// nonce nil lets the library generate a fresh cryptographically-random
// value; NoKeys requires a caller-supplied value the recipient can type in.
func (p *DeRecProtocol) CreateContact(channelID *uint64, mode ContactMode, nonce *uint64) (CreatedContact, error) {
	if p.closed {
		return CreatedContact{}, errors.New("protocol: CreateContact: protocol is closed")
	}
	var cid uint64
	if channelID != nil {
		cid = *channelID
	}
	var n uint64
	if nonce != nil {
		n = *nonce
	}
	contactBytes, err := p.instance.CreateContact(channelID != nil, cid, int32(mode), nonce != nil, n)
	if err != nil {
		return CreatedContact{}, err
	}
	var msg derecpb.ContactMessage
	if err := proto.Unmarshal(contactBytes, &msg); err != nil {
		return CreatedContact{}, fmt.Errorf("protocol: CreateContact: decode contact message: %w", err)
	}
	return CreatedContact{ContactBytes: contactBytes, ChannelID: msg.GetChannelId()}, nil
}
