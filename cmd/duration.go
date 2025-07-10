// Copyright © 2022-2025 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package cmd

import (
	"encoding/json"
	"strconv"
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
	case string:
		d.Duration, err = time.ParseDuration(value)
		if err != nil {
			return errors.Wrap(err, "parse string time to duration")
		}
	default:
		return errors.New("invalid json duration")
	}

	return nil
}

func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

func (d *Duration) UnmarshalText(b []byte) error {
	strTime := string(b)

	intTime, err := strconv.ParseInt(strTime, 10, 64)
	switch {
	case err == nil:
		d.Duration = time.Duration(intTime)
	case errors.Is(err, strconv.ErrSyntax):
		d.Duration, err = time.ParseDuration(strTime)
		if err != nil {
			return errors.Wrap(err, "parse string time to duration")
		}
	default:
		return errors.Wrap(err, "invalid text duration")
	}

	return nil
}

func RoundDuration(d Duration) Duration {
	switch {
	case d.Duration > time.Second:
		return Duration{d.Round(10 * time.Millisecond)}
	case d.Duration > time.Millisecond:
		return Duration{d.Round(time.Millisecond)}
	case d.Duration > time.Microsecond:
		return Duration{d.Round(time.Microsecond)}
	default:
		return d
	}
}
