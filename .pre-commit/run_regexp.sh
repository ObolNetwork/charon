#!/usr/bin/env bash

FILES=$@

function check() {
    grep -HnE "$2" $FILES && printf "\n❌ Regexp check failed: %s\n\n" "$1"
}

check 'Log messages must be capitalised' 'log\.(Error|Warn|Info|Debug)\(ctx, "[[:lower:]]' && exit 1
check 'Error messages must not be capitalised' 'errors\.(New|Wrap)\((err, )?"[[:upper:]]' && exit 1

true
