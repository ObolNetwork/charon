# Charon Configuration

This document describes the configuration options for running a charon node and cluster locally or in production.

## Flag Precedence

Charon uses [viper](https://github.com/spf13/viper) for configuration combined with [cobra](https://github.com/spf13/cobra)
for cli commands.

In descending order, the Charon node checks the following places for configuration:
- From environment vars beginning with `CHARON_`, with hyphens substituted for underscores. e.g. `CHARON_BEACON_NODE=http://....`
- From the config file specified with the `-config-file` flag as YAML, e.g. `beacon-node: http://...`
- From CLI params, e.g. `--beacon-node http://...`

## Configuration Options

```text:clireference.txt

```
If the above block is empty, see the [clireference.txt](clireference.txt) file directly.
