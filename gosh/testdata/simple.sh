#!/usr/bin/env gosh
# Use the `gosh` interp to "wrap" the shell script

# Test functions are defined as local functions with the `gt_*` prefix
gt_hello() {
  echo "hello world"
}

echo "this is just a regular shell script"

gt_fail() {
  echo "any non-zero exit code will fail the test immediately (like set -e)"

  cat foo

  echo "we'll never get here"
}
