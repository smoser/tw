#!/bin/sh

set -u

# Test binaries that should exist on most systems
TEST_BINS="sh bash"
LOG="test.log"
VER_CHECK="./ver-check"

pass() {
  echo "  [PASS] ${*}"
}

fail() {
  echo "  [FAIL] ${*}"
}

info() {
  echo "  ${*}"
}

file_contains() {
  string=$1
  file=$2
  while IFS= read -r line; do
    if [ "${line#*"${string}"}" != "$line" ]; then
      return 0
    fi
  done < "$file"
  return 1
}

cleanup() {
  rm -f $LOG
}

test_basic_functionality() {
  fail=0
  
  info "Testing basic version check with bash"
  if $VER_CHECK --bins="bash" --version="bash" --match-type="contains" >$LOG 2>&1; then
    if file_contains "PASS" "$LOG"; then
      pass "Basic version check works"
    else
      fail "Expected PASS message not found"
      fail=1
    fi
  else
    fail "Basic version check failed"
    fail=1
  fi
  
  return $fail
}

test_multiple_binaries() {
  fail=0
  
  info "Testing multiple binaries"
  if $VER_CHECK --bins="sh bash" --version="bash" --match-type="contains" >$LOG 2>&1; then
    # Should have at least one pass for bash
    if file_contains "PASS" "$LOG"; then
      pass "Multiple binaries check works"
    else
      fail "Expected PASS message not found for multiple binaries"
      fail=1
    fi
  else
    fail "Multiple binaries check failed"
    fail=1
  fi
  
  return $fail
}

test_nonexistent_binary() {
  fail=0
  
  info "Testing nonexistent binary"
  if $VER_CHECK --bins="zyxxyz" --version="anything" >$LOG 2>&1; then
    fail "Should have failed for nonexistent binary"
    fail=1
  else
    if file_contains "FAIL" "$LOG" && file_contains "not found in PATH" "$LOG"; then
      pass "Correctly failed for nonexistent binary"
    else
      fail "Expected failure message not found"
      fail=1
    fi
  fi
  
  return $fail
}

test_version_mismatch() {
  fail=0
  
  info "Testing version mismatch"
  if $VER_CHECK --bins="sh" --version="qwerty" --match-type="contains" >$LOG 2>&1; then
    fail "Should have failed for version mismatch"
    fail=1
  else
    if file_contains "FAIL" "$LOG" && file_contains "Version check failed" "$LOG"; then
      pass "Correctly failed for version mismatch"
    else
      fail "Expected version mismatch failure message not found"
      fail=1
    fi
  fi
  
  return $fail
}

test_verbose_mode() {
  fail=0
  
  info "Testing verbose mode"
  if $VER_CHECK --bins="bash" --version="bash" --match-type="contains" --verbose="true" >$LOG 2>&1; then
    if file_contains "> $ bash" "$LOG"; then
      pass "Verbose mode shows command execution"
    else
      fail "Verbose mode output not found"
      fail=1
    fi
  else
    fail "Verbose mode test failed"
    fail=1
  fi
  
  return $fail
}

test_help_output() {
  fail=0
  
  info "Testing help output"
  if $VER_CHECK --help >$LOG 2>&1; then
    if file_contains "Usage: ver-check" "$LOG"; then
      pass "Help output works"
    else
      fail "Help output missing expected content"
      fail=1
    fi
  else
    fail "Help command failed"
    fail=1
  fi
  
  return $fail
}

test_invalid_arguments() {
  fail=0
  
  info "Testing invalid arguments"
  if $VER_CHECK --invalid-arg >$LOG 2>&1; then
    fail "Should have failed for invalid argument"
    fail=1
  else
    if file_contains "ERROR" "$LOG" && file_contains "Unknown argument" "$LOG"; then
      pass "Correctly failed for invalid argument"
    else
      fail "Expected error message not found"
      fail=1
    fi
  fi
  
  return $fail
}

main() {
  failed_tests=0

  echo "Testing ver-check script functionality"
  echo ""

  echo "Test: Basic functionality"
  test_basic_functionality
  failed_tests=$((failed_tests + $?))
  echo ""

  echo "Test: Multiple binaries"
  test_multiple_binaries
  failed_tests=$((failed_tests + $?))
  echo ""

  echo "Test: Nonexistent binary"
  test_nonexistent_binary
  failed_tests=$((failed_tests + $?))
  echo ""

  echo "Test: Version mismatch"
  test_version_mismatch
  failed_tests=$((failed_tests + $?))
  echo ""

  echo "Test: Verbose mode"
  test_verbose_mode
  failed_tests=$((failed_tests + $?))
  echo ""

  echo "Test: Help output"
  test_help_output
  failed_tests=$((failed_tests + $?))
  echo ""

  echo "Test: Invalid arguments"
  test_invalid_arguments
  failed_tests=$((failed_tests + $?))
  echo ""

  if [ "$failed_tests" -eq 0 ]; then
    echo "[PASS] All tests passed."
  else
    echo "[FAIL] ${failed_tests} test(s) failed."
    exit 1
  fi
  
  cleanup
}

main "${@}"