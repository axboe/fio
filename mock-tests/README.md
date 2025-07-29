# FIO Mock Tests

## Overview

The FIO mock test suite provides isolated unit testing for specific algorithms,
calculations, and edge cases within FIO. These tests use mock implementations
to validate correctness without requiring the full FIO infrastructure.

## Purpose and Goals

### Why Mock Tests?

1. **Isolation**: Test specific algorithms without full system dependencies
2. **Precision**: Validate numerical calculations and edge cases precisely
3. **Speed**: Run quickly without I/O operations or system calls
4. **Clarity**: Each test focuses on a single aspect with clear documentation
5. **Regression Prevention**: Catch subtle bugs in mathematical operations

### What Mock Tests Are NOT

- Not integration tests (use `make test` for that)
- Not performance benchmarks (use FIO itself)
- Not I/O path testing (requires real FIO execution)

## Structure

```
mock-tests/
├── lib/           # Common test infrastructure
│   └── tap.h      # TAP (Test Anything Protocol) output support
├── tests/         # Individual test programs
│   └── test_*.c   # Test source files
├── build/         # Build artifacts (created by make)
└── Makefile       # Build system for mock tests
```

## Running Tests

### Run all mock tests:
```bash
make mock-tests
```

### Run tests from the mock-tests directory:
```bash
cd mock-tests
make test          # Run all tests
make test-tap      # Run with TAP harness (if prove is installed)
make test-latency_precision  # Run specific test
```

### Clean build artifacts:
```bash
make clean         # From mock-tests directory
# or
make clean         # From main FIO directory (cleans everything)
```

## TAP Output Format

Tests produce TAP (Test Anything Protocol) output for easy parsing:

```
TAP version 13
1..12
ok 1 - Microsecond latency: 123456000 == 123456000
ok 2 - Millisecond latency: 1234567890000 == 1234567890000
not ok 3 - Some failing test
# All tests passed
```

This format is understood by many test harnesses and CI systems.

## Writing New Mock Tests

### 1. Create test file in `tests/`:

```c
#include "../lib/tap.h"

int main(void) {
    tap_init();
    tap_plan(3);  // Number of tests

    tap_ok(1 == 1, "Basic equality");
    tap_ok(2 + 2 == 4, "Addition works");
    tap_skip("Not implemented yet");

    return tap_done();
}
```

### 2. Add to Makefile:

Edit `mock-tests/Makefile` and add your test name to the `TESTS` variable.

### 3. Document your test:

Each test should have a comprehensive header comment explaining:
- Purpose of the test
- Background on what's being tested
- Why this test matters
- What specific cases are covered

## Available Tests

### test_latency_precision

**Purpose**: Validates numerical precision improvements in steady state latency calculations.

**Background**: When calculating total latency from mean and sample count, large values
can cause precision loss or overflow. This test validates the improvement from:
```c
// Before: potential precision loss
total = (uint64_t)(mean * samples);

// After: explicit double precision
total = (uint64_t)(mean * (double)samples);
```

**Test Cases**:
- Normal operating ranges (microseconds to seconds)
- Edge cases near uint64_t overflow
- Zero sample defensive programming
- Precision in accumulation across threads
- Fractional nanosecond preservation

## Design Principles

1. **Isolation**: Mock only what's needed, test one thing at a time
2. **Clarity**: Clear test names and diagnostic messages
3. **Coverage**: Test normal cases, edge cases, and error conditions
4. **Documentation**: Explain WHY each test exists
5. **Reproducibility**: Deterministic tests with no random elements

## Integration with CI

The TAP output format makes these tests easy to integrate with CI systems:

```bash
# In CI script
make mock-tests || exit 1
```

Or with TAP parsing for better reports:

```bash
prove -v mock-tests/build/*
```

## Future Enhancements

Potential areas for expansion:
- Mock tests for parsing algorithms
- Edge case validation for statistical calculations
- Overflow detection in various calculations
- Precision validation for other numerical operations

## Contributing

When adding new mock tests:
1. Follow the existing patterns
2. Document thoroughly
3. Use meaningful test descriptions
4. Include both positive and negative test cases
5. Test edge cases and boundary conditions
