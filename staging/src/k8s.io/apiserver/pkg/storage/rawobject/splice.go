/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rawobject

import (
	"errors"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	// Every Kubernetes API object carries ObjectMeta in field 1, and
	// ObjectMeta carries resourceVersion in field 6.
	metadataField        = 1
	resourceVersionField = 6
	metadataTag          = byte(metadataField<<3 | int(protowire.BytesType))
	resourceVersionTag   = byte(resourceVersionField<<3 | int(protowire.BytesType))
)

var errNotSpliceable = errors.New("object metadata is not laid out in a way that allows resourceVersion injection")

// splice records where, in a serialized object, the resourceVersion goes.
// All offsets index into the object's message bytes.
type splice struct {
	// metaTag is the offset of the tag of the metadata field, and metaBody and
	// metaEnd delimit its payload.
	metaTag, metaBody, metaEnd int
	// rvStart and rvEnd delimit the existing resourceVersion field (tag
	// included). If there is none they are equal, and point at where one
	// would be in a canonically ordered encoding.
	rvStart, rvEnd int
}

// findSplice locates the resourceVersion of a serialized object without
// decoding anything else. It refuses encodings where metadata or
// resourceVersion occur more than once: those are legal protobuf, but nothing
// that writes to storage produces them, and rewriting them is not worth it.
func findSplice(msg []byte) (splice, error) {
	var s splice
	found := false
	for off := 0; off < len(msg); {
		num, typ, n := protowire.ConsumeTag(msg[off:])
		if n < 0 {
			return s, protowire.ParseError(n)
		}
		if num != metadataField {
			skip := protowire.ConsumeFieldValue(num, typ, msg[off+n:])
			if skip < 0 {
				return s, protowire.ParseError(skip)
			}
			off += n + skip
			continue
		}
		if found || typ != protowire.BytesType {
			return s, errNotSpliceable
		}
		found = true
		body, bodyLen := protowire.ConsumeBytes(msg[off+n:])
		if bodyLen < 0 {
			return s, protowire.ParseError(bodyLen)
		}
		s.metaTag = off
		s.metaEnd = off + n + bodyLen
		s.metaBody = s.metaEnd - len(body)
		off = s.metaEnd
	}
	if !found {
		return s, errNotSpliceable
	}

	s.rvStart, s.rvEnd = -1, -1
	insertAt := -1
	for off := s.metaBody; off < s.metaEnd; {
		num, typ, n := protowire.ConsumeTag(msg[off:s.metaEnd])
		if n < 0 {
			return s, protowire.ParseError(n)
		}
		skip := protowire.ConsumeFieldValue(num, typ, msg[off+n:s.metaEnd])
		if skip < 0 {
			return s, protowire.ParseError(skip)
		}
		switch {
		case num == resourceVersionField:
			if s.rvStart >= 0 || typ != protowire.BytesType {
				return s, errNotSpliceable
			}
			s.rvStart, s.rvEnd = off, off+n+skip
		case num > resourceVersionField && insertAt < 0:
			insertAt = off
		}
		off += n + skip
	}
	if s.rvStart < 0 {
		if insertAt < 0 {
			insertAt = s.metaEnd
		}
		s.rvStart, s.rvEnd = insertAt, insertAt
	}
	return s, nil
}

// size returns the size of the message once resourceVersion rv is spliced in.
func (s splice) size(msgLen int, rv string) int {
	oldMeta := s.metaEnd - s.metaBody
	newMeta := s.newMetaLen(rv)
	return msgLen - oldMeta + newMeta - protowire.SizeVarint(uint64(oldMeta)) + protowire.SizeVarint(uint64(newMeta))
}

func (s splice) newMetaLen(rv string) int {
	return (s.metaEnd - s.metaBody) - (s.rvEnd - s.rvStart) + 1 + protowire.SizeBytes(len(rv))
}

// appendTo appends msg to dst with resourceVersion set to rv. The field is
// always written, even when empty, because that is what the generated
// marshalers do, and matching them byte for byte keeps this path testable
// against the decode-and-encode one.
func (s splice) appendTo(dst, msg []byte, rv string) []byte {
	dst = append(dst, msg[:s.metaTag]...)
	dst = append(dst, metadataTag)
	dst = protowire.AppendVarint(dst, uint64(s.newMetaLen(rv)))
	dst = append(dst, msg[s.metaBody:s.rvStart]...)
	dst = append(dst, resourceVersionTag)
	dst = protowire.AppendString(dst, rv)
	dst = append(dst, msg[s.rvEnd:s.metaEnd]...)
	dst = append(dst, msg[s.metaEnd:]...)
	return dst
}
