package engine

import "runtime"

// isWindows reports whether ARClient is running on Windows.
//
// Used for the few places where the bundled core's binary name differs. It is a
// function rather than a build tag because the selftest cross-compiles and the
// release workflow builds once; a build tag would mean the wrong binary name
// gets compiled in and only fails at runtime, on a user's machine, with a
// "binary not found" that does not mention naming.
func isWindows() bool { return runtime.GOOS == "windows" }
