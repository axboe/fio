# Makefile for FIO mock tests
#
# These tests validate specific algorithmic improvements and edge cases
# using isolated mock implementations.

CC ?= gcc
CFLAGS = -Wall -Wextra -O2 -g -I. -I.. -lm
TEST_DIR = tests
LIB_DIR = lib
BUILD_DIR = build

# List of test programs
TESTS = test_latency_precision

# Build paths
TEST_SRCS = $(addprefix $(TEST_DIR)/, $(addsuffix .c, $(TESTS)))
TEST_BINS = $(addprefix $(BUILD_DIR)/, $(TESTS))

# TAP test runner
TAP_RUNNER = prove

.PHONY: all clean test help

all: $(BUILD_DIR) $(TEST_BINS)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%: $(TEST_DIR)/%.c $(LIB_DIR)/tap.h
	$(CC) $(CFLAGS) -o $@ $<

test: all
	@echo "Running FIO mock tests..."
	@echo "========================="
	@failed=0; \
	for test in $(TEST_BINS); do \
		echo "Running $$test..."; \
		./$$test; \
		if [ $$? -ne 0 ]; then \
			failed=$$((failed + 1)); \
		fi; \
		echo; \
	done; \
	if [ $$failed -gt 0 ]; then \
		echo "FAILED: $$failed test(s) failed"; \
		exit 1; \
	else \
		echo "SUCCESS: All tests passed"; \
	fi

# Run tests with TAP harness if available
test-tap: all
	@if command -v $(TAP_RUNNER) >/dev/null 2>&1; then \
		$(TAP_RUNNER) -v $(TEST_BINS); \
	else \
		echo "TAP runner '$(TAP_RUNNER)' not found, running tests directly..."; \
		$(MAKE) test; \
	fi

# Run a specific test
test-%: $(BUILD_DIR)/%
	./$(BUILD_DIR)/$*

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "FIO Mock Tests"
	@echo "=============="
	@echo ""
	@echo "Available targets:"
	@echo "  make all      - Build all tests"
	@echo "  make test     - Run all tests"
	@echo "  make test-tap - Run tests with TAP harness (if available)"
	@echo "  make test-NAME - Run specific test (e.g., make test-latency_precision)"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make help     - Show this help message"
	@echo ""
	@echo "Available tests:"
	@for test in $(TESTS); do echo "  - $$test"; done
