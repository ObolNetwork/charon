// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

// Package protonil provides a function to check if a protobuf message is nil or if it contains
// nil fields that are not marked as optional.
//
// This is useful to validate protobuf messages that are received over the wire avoiding
// the need for verbose nil checks.
package protonil

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/obolnetwork/charon/app/errors"
	"github.com/obolnetwork/charon/app/z"
)

// maxFieldNumber is the maximum field number that this package supports.
const maxFieldNumber = 64

// Check returns an error if the protobuf message is nil or if it contains nil fields
// that are not marked as optional.
//
// Note this only applies to "message" fields, not primitive scalars or "map" or "list" fields
// since their zero values are valid.
func Check(msg proto.Message) error {
	if msg == nil {
		return errors.New("nil protobuf message")
	}

	rMsg := msg.ProtoReflect()
	if !rMsg.IsValid() {
		return errors.New("nil protobuf message")
	}

	fields := rMsg.Descriptor().Fields()

	// No explicit API to iterate over all fields, so just check numbers 1 to max.
	var checked int
	for i := 1; i <= maxFieldNumber; i++ {
		// Have we checked all the fields?
		if checked == fields.Len() {
			break
		}

		field := fields.ByNumber(protoreflect.FieldNumber(i))
		if field == nil {
			// No field at this index, probably reserved.
			continue
		}
		checked++

		// Check the values of map fields.
		if field.IsMap() {
			var err error
			rMsg.Get(field).Map().Range(func(_ protoreflect.MapKey, val protoreflect.Value) bool {
				value, ok := valueToMsg(val)
				if !ok {
					// Not a message value type.
					return false
				}

				err = Check(value.Interface())

				return err == nil
			})

			if err != nil {
				return errors.Wrap(err, "map value", z.Any("map", field.Name()))
			}

			continue
		}

		// Check elements of list fields.
		if field.IsList() {
			list := rMsg.Get(field).List()
			for i := range list.Len() {
				elem, ok := valueToMsg(list.Get(i))
				if !ok {
					// Not a message element type.
					break
				}

				if err := Check(elem.Interface()); err != nil {
					return errors.Wrap(err, "list element",
						z.Any("list", field.Name()), z.Int("index", i))
				}
			}

			continue
		}

		if field.Message() == nil {
			// Not a message field.
			continue
		}

		fieldVal := rMsg.Get(field).Message().Interface()

		// Check if field is nil
		if !fieldVal.ProtoReflect().IsValid() {
			if field.HasOptionalKeyword() {
				// Optional field is nil, this is ok.
				continue
			}

			return errors.New("nil proto field", z.Any("field", field.Name()))
		}

		// Recursively check inner message fields.
		if err := Check(fieldVal); err != nil {
			return errors.Wrap(err, "inner message field", z.Any("inner", field.Name()))
		}
	}

	if checked != fields.Len() {
		return errors.New("unexpected number of field checked, this should never happen")
	}

	return nil
}

// valueToMsg converts a protoreflect.Value to a protoreflect.Message if possible.
func valueToMsg(val protoreflect.Value) (protoreflect.Message, bool) {
	iface := val.Interface()
	if iface == nil {
		return nil, false
	}

	elemMsg, ok := iface.(protoreflect.Message)

	return elemMsg, ok
}
