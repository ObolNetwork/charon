// Copyright © 2022-2024 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"encoding/json"
	"time"

	"github.com/obolnetwork/charon/app/errors"
)

type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	res, err := json.Marshal(d.String())
	if err != nil {
		return nil, errors.Wrap(err, "marshal json duration")
	}

	return res, nil
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v any
	err := json.Unmarshal(b, &v)
	if err != nil {
		return errors.Wrap(err, "unmarshal json duration")
	}
	switch value := v.(type) {
	case float64:
		d.Duration = time.Duration(value)
		return nil
	case string:
		d.Duration, err = time.ParseDuration(value)
		if err != nil {
			return errors.Wrap(err, "parse string time to duration")
		}

		return nil
	default:
		return errors.New("invalid duration")
	}
}
