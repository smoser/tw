# `gosh` (GO SHell test)

Author tests in shell that integrate with `go test`.

## Quickstart

```shell
apk add gosh
```

### Create a test file (`test.sh`)

```bash
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
```

### Run the test

```bash
$ chmod +x test.sh

$ ./test.sh
=== RUN   TestShell
=== RUN   TestShell/simple.sh
    main_test.go:181: rendered wrapped script to: /var/folders/5v/6gvb9x954sbd9tmqq14cwgrh0000gn/T/gosh-2899603977/wgosh.sh
this is just a regular shell script
=== RUN   TestShell/simple.sh/gt_hello
hello world
    testfn.go:85: [gt_hello] finished successfully
=== RUN   TestShell/simple.sh/gt_fail
any non-zero exit code will fail the test immediately (like set -e)
cat: foo: No such file or directory
    testfn.go:90: [gt_fail] finished with error code 1
    main_test.go:193: failed to run test: test finished with error code 1
--- FAIL: TestShell (0.24s)
    --- FAIL: TestShell/simple.sh (0.24s)
        --- PASS: TestShell/simple.sh/gt_hello (0.01s)
        --- FAIL: TestShell/simple.sh/gt_fail (0.01s)
FAIL
```

## How it works

`gosh` consists of three components:

- **goshr**: The test runner
- **gt**: The test runner client
- **gosh**: A simple wrapper to support OS's without support for `env -S`

On execution of a shell script using the `gosh` interpreter, `goshr` "wraps" the
script with the ["shell framework"](./framework.sh.tpl), and then executes it
with `os/exec` using the framework's shbang (`#!/bin/sh`).

The "framework" is mostly shell functions with a very thin amount of go templating
to ensure all the appropriate pipes are configured.

From there, the final rendered script is written to disk and executed by `goshr`.

Communication between the shell script for stdout/stderr, and progress updates
happen over named pipes, which `goshr` and `gt` orchestrate.

There are no modifications made to the original script, which means all of its
contents are still executed. The only "trickery" done by `gosh` is parsing (via
`shfmt`) and explicitly calling all `gt_*` functions with the appropriate
`set -e` arguments.

Each `gt_*` function is run serially, in the order it is defined. Tests
`PASS` when the `gt_*` function exits with a 0 exit code, and tests `FAIL`
and exit the script with a non-zero exit code (`set -e` is automatically wired
up).

`gosh` interpreted scripts support a few args as well:

- `--json`: output in `go test -json` formatted results, useful for piping into
  other tools that convert these to structured test reports like
  [`gotestsum`](https://github.com/gotestyourself/gotestsum)
- `--trace-file`: writes otel formatted traces to the provided file, each
  defined `gosh_*` is its own span

## But why?!?

You want to run some basic tests with shell, but like the ecosystem around `go test`.
