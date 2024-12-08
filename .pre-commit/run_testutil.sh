#!/usr/bin/env bash

FILES=$@

# check runs a regexp check on the given files
function check() {
    grep -HnE "$2" $FILES && printf "\n❌ Regexp check failed: %s\n\n" "$1"
}

# exclude_names excludes file names matching the given regex from the list of files
function exclude_names() {
     FILES=$(echo $FILES | tr ' ' '\n' | grep -vE "$1" | tr '\n' ' ')
}

# exclude_content excludes files with content matching the given regex from the list of files
function exclude_content() {
      FILES=$(echo $FILES | tr ' ' '\n' | xargs grep -LZE "$1" | tr '\n' ' ')
}

# Exclude all file names with 'test' in the path.
exclude_names 'test'
# Exclude all files with 'Allow testutil' content.
exclude_content 'Allow testutil'

# Check any remaining files for testutil imports.
check 'Testutil package may only be imported by tests' 'github.com/obolnetwork/charon/testutil' && exit 1

true
