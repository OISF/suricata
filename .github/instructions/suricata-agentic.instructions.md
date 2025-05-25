---
applyTo: '**'
---
# Suricata Agentic Development Guide

*Version 4.0 - Comprehensive Development Tasks for AI Agents*

> **For AI Assistants**: This guide provides navigation patterns and diagnostic workflows for all major Suricata develo## Comprehensive Suricata Help Reference

### Core Command-Line Options for Development
**Essential commands that AI agents should memorize:**

```bash
# Build and configuration information
./src/suricata --build-info              # Shows compile-time configuration
./src/suricata --version                 # Version and basic build info

# Feature listing (verify your implementations)
./src/suricata --list-keywords           # All detection keywords  
./src/suricata --list-app-layer-protos   # Application layer protocols
./src/suricata --list-outputs            # Output modules available
./src/suricata --list-runmodes           # Threading modes available
./src/suricata --list-cuda-cards         # GPU acceleration info
./src/suricata --list-unittests          # All registered unit tests

# Unit testing (with timeout protection)
timeout 30s ./src/suricata -u                    # Run all unit tests
timeout 30s ./src/suricata -u -U "*Pattern*"     # Run specific test pattern
timeout 30s ./src/suricata -u -U "*Keyword*"     # Run tests for specific keyword
timeout 30s ./src/suricata --list-unittests | grep Parse # Find parsing tests

# Configuration and validation
./src/suricata -T -c suricata.yaml       # Test configuration file validity
./src/suricata --engine-analysis         # Enable detailed performance analysis
./src/suricata --set-value=var=value     # Override config values

# Development and debugging
./src/suricata --pcap-file-continuous    # Process PCAP in continuous mode
./src/suricata --sim-disconnected-only   # Only process disconnected flows
```

### Unit Test Execution Patterns
**Standard patterns for running and debugging tests:**

```bash
# Full test suite (use in CI/automation)
timeout 300s ./src/suricata -u > unit-test-results.log 2>&1

# Test specific components
timeout 30s ./src/suricata -u -U "*Detect*"      # All detection tests
timeout 30s ./src/suricata -u -U "*Parse*"       # All parsing tests  
timeout 30s ./src/suricata -u -U "*Match*"       # All matching tests
timeout 30s ./src/suricata -u -U "*Http*"        # HTTP-related tests
timeout 30s ./src/suricata -u -U "*Tls*"         # TLS-related tests

# Test your new keyword
timeout 30s ./src/suricata -u -U "*YourKeyword*"

# Debug failing tests
timeout 30s ./src/suricata -u -U "*FailingTest*" --set console.loglevel=debug

# List all tests containing a pattern
./src/suricata --list-unittests | grep -i {pattern}
```

### Configuration Testing Commands
**For validating configuration and rule files:**

```bash
# Test specific rule files
./src/suricata -T -S custom.rules -c suricata.yaml

# Test with specific rule categories
./src/suricata -T -c suricata.yaml --set classification-file=classification.config

# Enable specific app-layer protocols
./src/suricata -T -c suricata.yaml --set app-layer.protocols.tls.enabled=yes

# Test with engine analysis (performance profiling)
./src/suricata -T -c suricata.yaml --engine-analysis
```

### Performance and Profiling Commands
**For analyzing your feature's performance impact:**

```bash
# Basic profiling
./src/suricata -c suricata.yaml -r test.pcap --engine-analysis

# Profiling with rule timing
./src/suricata -c suricata.yaml -r test.pcap --engine-analysis --set engine.analysis.rule-profiling=yes

# Live capture profiling  
./src/suricata -c suricata.yaml -i eth0 --engine-analysis --stats-interval=30

# Memory usage analysis
./src/suricata -c suricata.yaml -r test.pcap --set engine.analysis.memory-profiling=yes
```

### Quick Reference: Exit Codes
**Important for automation and scripting:**

```bash
# Exit code meanings:
# 0 = Success
# 1 = General failure  
# 2 = Configuration error
# 124 = Timeout (when using timeout command)

# Test exit codes in scripts:
timeout 30s ./src/suricata -u -U "*Test*"
case $? in
    0) echo "Tests passed" ;;
    1) echo "Tests failed" ;;
    124) echo "Tests timed out - infinite loop suspected" ;;
    *) echo "Unexpected error" ;;
esac
```

## Build Troubleshooting

### Quick Diagnosis
```bash
# Build diagnosis command sequence (prefer VS Code tasks)
make clean
./configure --enable-unittests --enable-debug 2>&1 | tee config.log
# Prefer VS Code: Ctrl+Shift+P → Tasks: Run Task → Build Suricata
# Alternative: make V=1 2>&1 | tee build.log

# Check for common issues
grep -i "error\|failed\|not found" config.log
grep -i "undefined\|error" build.log
```

### Common Build Issues Reference
| Error Pattern | Solution Reference |
|---------------|-------------------|
| `DETECT_KEYWORD undeclared` | Check `src/detect-engine-register.h` enum |
| `undefined reference to Register` | Check `src/detect-engine-register.c` includes |
| `No such file or directory` | Check `src/Makefile.am` entries |
| `cargo build failed` | Check `rust/Cargo.toml` and module declarations |
| `unit test timeout` | Review loops and termination conditions in test | It emphasizes references over repetition and commands over explanations.

## Core Philosophy
- 🧭 **Navigate, don't memorize** - Learn to find information rather than repeat it
- 🔗 **Reference authoritative sources** - Point to docs and existing implementations
- 🚀 **Task-oriented patterns** - Reusable workflows for common development scenarios
- 🔧 **Diagnostic-first approach** - Always verify current state before making changes

## Development Task Matrix

| Task Category | Time | Discovery Command | Verification Command |
|---------------|------|-------------------|---------------------|
| **Detection keywords** | 2-4h | `find src/ -name "detect-*.c" \| head -3` | `./src/suricata --list-keywords \| grep {name}` |
| **App-layer parsers** | 1-3 days | `ls src/app-layer/ \| grep -v template` | `./src/suricata --list-app-layer-protos` |
| **Plugin development** | 1-2 days | `find src/ -name "output-*.c" \| head -3` | `./src/suricata --list-outputs` |
| **Unit tests (C)** | 30-90min | `find src/tests/ -name "*.c" \| head -3` | `./src/suricata -u -U "*{pattern}*"` |
| **Unit tests (Rust)** | 30-60min | `find . -name "*.rs" -path "*/tests/*"` | `cargo test {pattern}` |
| **Threading optimization** | Variable | `grep -r "ThreadVars\|TmModule" src/ \| head -3` | `./src/suricata --list-runmodes` |
| **Output modules** | 1-2 days | `ls src/output-*.c \| head -3` | `./src/suricata --list-outputs` |
| **Documentation** | 30-120min | `find doc/ -name "*.rst" \| head -5` | `make -C doc html` |

## AI Agent Workflow Patterns

### Pattern 1: Explore, Plan, Code, Commit (Generic Approach)
*Recommended for: output modules, optimization tasks, documentation, complex feature development*

**Use VS Code tasks when available - prefer `Ctrl+Shift+P → Tasks: Run Task → Build Suricata` over command-line builds**

```bash
# Phase 1: Explore (5-10 min) - Use scratchpad for tracking discoveries
# Create scratchpad: echo "# Task: {description}" > task-scratchpad.md
./src/suricata --build-info                    # Build configuration
git status --porcelain                         # Working directory state
find src/ -name "*{component}*" | head -5      # Find related files
grep -r "{relevant_pattern}" src/ | head -10   # Understand patterns
# Document findings in scratchpad

# Phase 2: Plan (5-15 min) - Update scratchpad with implementation plan
head -50 {template_or_example_file}            # Study reference implementation  
# Add to scratchpad: file locations, functions to modify, integration points
# Plan: [ ] File1 changes [ ] File2 changes [ ] Build integration [ ] Testing

# Phase 3: Code (Variable) - Track progress in scratchpad
cp {template} {new_file}                       # Copy template/example
# Edit files following discovered patterns
# Update scratchpad with: [x] File1 changes, notes on issues encountered

# Phase 4: Commit (5-10 min) - Final verification using VS Code tasks
# Prefer: VS Code Task "Build Suricata" over command-line make
{task_specific_test_command}                   # Functional verification
git add . && git commit -m "feat: {description}"
# Update scratchpad: [x] Complete - link to commit hash
```

### Pattern 2: Test-Driven Development (TDD Approach) 
*Strongly recommended for: keyword detection, app-layer parsing, protocol handling*

**⚠️ TIMEOUT HANDLING: Unit tests can infinite loop - set 30-second timeout wrapper when running tests**

```bash
# Phase 1: Write Tests First (15-30 min) - Use scratchpad to track test cases
# Create scratchpad: echo "# TDD Task: {description}" > tdd-scratchpad.md
cp src/tests/detect-template.c src/tests/detect-{keyword}.c
# Edit test file: implement failing tests that define expected behavior
# Document in scratchpad: test cases, expected behavior, edge cases to cover

# Phase 2: Commit Tests (2-5 min) 
# Verify tests fail as expected (proves they test the right thing)
timeout 30s ./src/suricata -u -U "*{TestKeyword}*" || echo "Tests correctly fail"
git add src/tests/ && git commit -m "test: add failing tests for {keyword}"

# Phase 3: Code Implementation (Variable) - Track progress in scratchpad  
cp src/detect-template.c src/detect-{keyword}.c
# Implement minimal code to make tests pass
# Update scratchpad: [x] Test1 passing [x] Test2 passing [ ] Test3 failing

# Phase 4: Iterate Until All Tests Pass (Variable)
# VS Code Task: "Build Suricata" then test
timeout 30s ./src/suricata -u -U "*{TestKeyword}*"  # 30s timeout prevents infinite loops
# Repeat: code → build → test until all pass
# Update scratchpad with each iteration

# Phase 5: Final Commit (5-10 min)
./src/suricata --list-keywords | grep {keyword}    # Verify registration
git add . && git commit -m "feat: implement {keyword} with tests"
# Update scratchpad: [x] Complete - all tests passing
```

### Scratchpad Methodology
*Essential for AI agents to track progress and maintain context*

```bash
# Always create task-specific scratchpad at start
echo "# Task: {brief_description}
## Objective
{what_needs_to_be_accomplished}

## Discovery
- [ ] Find related files
- [ ] Study patterns  
- [ ] Identify integration points

## Implementation Plan
- [ ] File1: {specific_changes}
- [ ] File2: {specific_changes}
- [ ] Build integration
- [ ] Testing strategy

## Progress Tracking
- [ ] Phase 1: Discovery
- [ ] Phase 2: Implementation  
- [ ] Phase 3: Testing
- [ ] Phase 4: Integration

## Notes
{track_issues_solutions_learnings}
" > {task}-scratchpad.md

# Update scratchpad throughout development:
echo "- [x] Found template in src/detect-template.c" >> {task}-scratchpad.md
echo "- Issue: Build failed due to missing Makefile.am entry" >> {task}-scratchpad.md
echo "- Solution: Added detect-{keyword}.c to src/Makefile.am line 123" >> {task}-scratchpad.md
```

Adhere to the coding style specified in the [Coding Style guide](https://docs.suricata.io/en/latest/devguide/codebase/coding-style.html):

- Use C99 standard.
- Indentation: 4 spaces, no tabs.
- Brace style: K&R.

Suricata runs on all major platform including Linux, Windows, MacOS, FreeBSD, and others. When developing always assume the code needs to be compatible with all or at least the code needs to be guarded for the specific platforms to allow successful code compilation everywhere.
New libraries are allowed but disregarded, use them only if you find them particularly useful and they cannot be replaced with in-place libraries.

Suricata's architecture includes:
- Packet acquisition modules (`source-*.[ch]`)
- Decoders (`decode-*.[ch]`)
- Stream reassembly (`stream-*.[ch]`)
- Detection engine (`detect-*.[ch]`)
- App-layer protocol parsers (`app-layer/*`)
- Logging and output modules (`output-*.[ch]`)
- Utilities (`util-*.[ch]`)

## Task-Specific Patterns

### 1. Detection Keywords (`src/detect-*.c`)
**Discovery**: `find src/ -name "detect-*.c" | head -3 | xargs grep -l "Setup.*Match.*Free"`
**Template**: `src/detect-template.c`
**Registration**: Add to `src/detect-engine-register.{c,h}`
**Verification**: `./src/suricata --list-keywords | grep {keyword}`

### 2. App-Layer Parsers (`src/app-layer/`)
**Discovery**: `ls src/app-layer/ | grep -v template | head -3`
**Template**: `src/app-layer/template/` (if exists) or study `src/app-layer/http/`
**Registration**: Add to `src/app-layer.c` and appropriate protocol files
**Verification**: `./src/suricata --list-app-layer-protos | grep {proto}`

### 3. Output Modules (`src/output-*.c`)
**Discovery**: `find src/ -name "output-*.c" | head -3 | xargs grep -l "OutputModule"`
**Template**: Study `src/output-json-alert.c` for JSON or `src/output-pcap.c` for binary
**Registration**: Add to `src/output.c`
**Verification**: `./src/suricata --list-outputs | grep {output}`

### 4. Threading Optimization (`src/runmodes.c`, `src/tm-*.c`)
**Discovery**: `grep -r "ThreadVars\|TmModule" src/ | head -5`
**Reference**: Study `src/runmodes.c` and `src/tm-threads.c`
**Tools**: `./configure --enable-profiling`, `perf`, `valgrind --tool=helgrind`
**Verification**: `./src/suricata --list-runmodes`

### 5. Unit Tests
**C Tests** (`src/tests/`):
- **Discovery**: `find src/tests/ -name "*.c" | head -3 | xargs grep -l "UtRegisterTest"`
- **Template**: `src/tests/detect-template.c` or similar test file
- **Verification**: `./src/suricata -u -U "*{TestName}*"`

**Rust Tests** (various `*/tests/` dirs):
- **Discovery**: `find . -name "*.rs" -path "*/tests/*" | head -3`
- **Reference**: Existing test files in same module
- **Verification**: `cargo test {test_pattern}`

### 6. Documentation (`doc/`)
**Discovery**: `find doc/ -name "*.rst" | grep -E "(devguide|userguide)" | head -5`
**Reference**: Study existing `.rst` files for structure and style
**Build**: `make -C doc html` or `sphinx-build -b html doc/ doc/_build/`
**Verification**: Check generated HTML and cross-references

# 3. Registration (engine integration)
grep -n "DetectTemplateRegister" src/detect-engine-register.c
# Add: DetectXxxRegister() call

# 4. Build system
grep -n "detect-template" src/Makefile.am  
# Add: detect-{keyword}.c to appropriate section

# 5. Testing
cp src/tests/detect-template.c src/tests/detect-{keyword}.c
# Edit: test functions for your keyword

# 6. Verification
make clean && make -j$(nproc) && ./src/suricata --list-keywords | grep {keyword}
```

### Unit Testing Pattern
**Test Categories** (implement applicable ones):
```bash
# Study existing test patterns first
grep -A 10 -B 10 "UtRegisterTest.*Parse" src/tests/detect-*.c | head -20
grep -A 10 -B 10 "UtRegisterTest.*Match" src/tests/detect-*.c | head -20

# Test types to implement:
# - Parse tests: DetectXxxParseTest01() - valid syntax
# - Parse tests: DetectXxxParseTest02() - invalid syntax  
# - Match tests: DetectXxxMatchTest01() - true positives
# - Match tests: DetectXxxMatchTest02() - true negatives
# - Edge tests: DetectXxxEdgeTest01() - boundary conditions
```

**Quick Test Verification**:
```bash
# Test your specific keyword
./src/suricata -u -U "*{Keyword}*"

# Test related functionality  
./src/suricata -u -U "*Parse*" | grep {keyword}
./src/suricata -u -U "*Match*" | grep {keyword}

# Full test suite verification
make check 2>&1 | grep -E "(pass|FAILED)" | tail -10
```

## Build System Integration Guide

### C File Integration (Detection Keywords, Core Features)
**Required steps for any new C file in Suricata:**

```bash
# 1. Add to src/Makefile.am (CRITICAL - file won't compile without this)
grep -A 10 -B 5 "detect-content.c" src/Makefile.am
# Find the libsuricata_c_a_SOURCES section
# Add your file: detect-{keyword}.c \ (note the backslash for line continuation)

# 2. For detection keywords - add enum ID
grep -A 5 -B 5 "DETECT_CONTENT" src/detect-engine-register.h  
# Add after similar entries: DETECT_{KEYWORD_UPPER},

# 3. For detection keywords - add registration call
grep -A 5 -B 5 "DetectContentRegister" src/detect-engine-register.c
# Add in DetectEngineRegisterFunctions(): DetectXxxRegister();

# 4. Include statements pattern
# New files need: #include "detect-engine-register.h" 
# Study existing detect-*.c files for standard includes

# 5. Verify integration (use VS Code task preferred)
# VS Code: Ctrl+Shift+P → Tasks: Run Task → Build Suricata
# Alternative: make clean && make -j$(nproc)
./src/suricata --list-keywords | grep -i {keyword}
```

### Rust File Integration (App-layer, Parsing, Performance Features)
**Required steps for any new Rust module in Suricata:**

```bash
# 1. Add to rust/Cargo.toml (if creating new top-level module)
grep -A 5 -B 5 "\[lib\]" rust/Cargo.toml
# Study the structure - most features go in existing modules

# 2. Add to rust/src/lib.rs (for new modules)
grep -A 10 "pub mod" rust/src/lib.rs
# Add: pub mod {your_module};

# 3. Rust directory structure (follow existing patterns)
# rust/src/{protocol}/    - for app-layer parsers  
# rust/src/{feature}/     - for specific features
# rust/src/{protocol}/parser.rs - main parser logic
# rust/src/{protocol}/mod.rs - module exports

# 4. Integration with C code (when needed)
# rust/src/lib.rs - export functions with #[no_mangle] pub extern "C"
# src/{corresponding}.c - call Rust functions via extern declarations

# 5. Testing structure
# rust/src/{module}/mod.rs - unit tests in mod tests { }
# Use #[test] attribute for test functions

# 6. Verify integration  
cd rust && cargo test {module_name}
# Full integration: VS Code Build Task or make clean && make
```

### Build System Integration Checklist
**Use this checklist to ensure proper integration:**

**For C Files:**
- [ ] Added to `src/Makefile.am` in `libsuricata_c_a_SOURCES`
- [ ] If detection keyword: Added enum to `src/detect-engine-register.h`
- [ ] If detection keyword: Added registration call to `src/detect-engine-register.c`
- [ ] Proper include statements (`#include "detect-engine-register.h"` etc.)
- [ ] File compiles without warnings
- [ ] Feature appears in appropriate `--list-*` command

**For Rust Files:**
- [ ] Module declared in appropriate `mod.rs` or `lib.rs`
- [ ] If new module: Added to `rust/src/lib.rs`
- [ ] C integration functions marked with `#[no_mangle] pub extern "C"`
- [ ] Tests compile with `cargo test`
- [ ] Integrated with C build system if needed

**Build Verification Commands:**
```bash
# Comprehensive build check (use VS Code task when possible)
make clean
# VS Code: Ctrl+Shift+P → Tasks: Run Task → Build Suricata
# Alternative: make -j$(nproc)

# Rust-specific verification
cd rust && cargo check && cargo test

# Feature verification (replace {keyword} with your feature)
./src/suricata --list-keywords | grep {keyword}      # For detection keywords
./src/suricata --list-app-layer-protos | grep {proto} # For app-layer features
./src/suricata --list-outputs | grep {output}        # For output modules
```

### Analysis Phase (Use existing code as reference)
```bash
# Find similar keywords
find src/ -name "detect-*.c" | xargs grep -l "string.*setup" | head -5
find src/ -name "detect-*.c" | xargs grep -l "numeric.*setup" | head -5

# Study the official template
cat src/detect-template.c
cat src/detect-template.h
cat src/tests/detect-template.c
```

### Implementation Checklist
- [ ] **Copy template**: `cp src/detect-template.{c,h} src/detect-{keyword}.{c,h}`
- [ ] **Rename functions**: Replace `Template` with `YourKeyword` throughout
- [ ] **Register keyword**: Add to `src/detect-engine-register.{c,h}`
- [ ] **Update build**: Add files to `src/Makefile.am`
- [ ] **Write tests**: Copy and adapt `src/tests/detect-template.c`

### Key Function Signatures (Reference Pattern)
```c
// These signatures are standard across all keywords
static int DetectKeywordSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectKeywordFree(DetectEngineCtx *, void *);
static int DetectKeywordMatch(DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
```

> **Reference**: See `src/detect-content.c` for complex content matching, `src/detect-msg.c` for simple string handling

## Unit Testing with Timeout Protection

### ⚠️ Critical: Unit Test Timeout Handling
**AI agents must use timeout wrappers to prevent infinite loops in unit tests**

```bash
# ALWAYS use timeout for unit test execution
# 30-second timeout is sufficient for most tests
timeout 30s ./src/suricata -u -U "*{TestPattern}*"

# Check exit codes to distinguish timeout vs test failure
if [ $? -eq 124 ]; then
    echo "TIMEOUT: Test likely has infinite loop - check implementation"
    echo "Review loops, recursive calls, and termination conditions"
else
    echo "Test completed (may have passed or failed normally)"
fi

# For debugging infinite loops in specific tests
timeout 10s gdb --batch --ex run --ex bt --args ./src/suricata -u -U "*SpecificTest*"
```

### Unit Testing Pattern (Enhanced)

**For New Keywords/Features (TDD Approach)**:
```bash
# 1. Create test file first
cp src/tests/detect-template.c src/tests/detect-{keyword}.c

# 2. Implement failing tests that define behavior
# Edit test file with specific test cases

# 3. Verify tests fail appropriately (with timeout protection)
timeout 30s ./src/suricata -u -U "*{Keyword}*" || echo "Tests correctly fail - ready to implement"

# 4. Register tests in source file
# Add to your detect-{keyword}.c:
void DetectKeywordRegisterTests(void) {
    UtRegisterTest("KeywordTest01", KeywordTest01);
    UtRegisterTest("KeywordTest02", KeywordTest02);
    // etc.
}
```

**For Existing Code (Verification)**:
```bash
# 1. Find what to test
find src/ -name "*keyword*" -type f
grep -r "FunctionName" src/

# 2. Check existing tests  
find src/tests/ -name "*keyword*" -type f
timeout 30s ./src/suricata --list-unittests | grep Keyword

# 3. Run specific test categories (with timeout)
timeout 30s ./src/suricata -u -U "*Parse*" | grep {keyword}
timeout 30s ./src/suricata -u -U "*Match*" | grep {keyword}
```

### Test Categories (Standard Pattern)
```c
// Copy this pattern for any keyword tests
static int KeywordParseTest01(void) { 
    /* Test valid parsing - should return success */ 
    return 1; // Success
}

static int KeywordParseTest02(void) { 
    /* Test invalid parsing - should return failure */ 
    return 1; // Success (test passes when invalid input correctly rejected)
}  

static int KeywordMatchTest01(void) { 
    /* Test true positive matching */ 
    return 1; // Success
}

static int KeywordMatchTest02(void) { 
    /* Test true negative (no false positives) */ 
    return 1; // Success
}

static int KeywordEdgeTest01(void) { 
    /* Test boundary conditions, empty input, etc. */ 
    return 1; // Success
}

void DetectKeywordRegisterTests(void) {
    UtRegisterTest("KeywordParseTest01", KeywordParseTest01);
    UtRegisterTest("KeywordParseTest02", KeywordParseTest02);
    UtRegisterTest("KeywordMatchTest01", KeywordMatchTest01);
    UtRegisterTest("KeywordMatchTest02", KeywordMatchTest02);
    UtRegisterTest("KeywordEdgeTest01", KeywordEdgeTest01);
}
```

### Quick Test Verification (with Timeout Protection)
```bash
# Test your specific keyword (30s timeout prevents infinite loops)
timeout 30s ./src/suricata -u -U "*{Keyword}*"

# Test related functionality with timeout protection
timeout 30s ./src/suricata -u -U "*Parse*" | grep {keyword}
timeout 30s ./src/suricata -u -U "*Match*" | grep {keyword}

# Full test suite verification (use longer timeout for full suite)
timeout 300s make check 2>&1 | grep -E "(pass|FAILED)" | tail -10

# If timeout occurs, debug specific failing test:
echo "Debugging infinite loop in tests..."
timeout 5s strace -e trace=write ./src/suricata -u -U "*SpecificFailingTest*" 2>&1 | tail -20
```

### Memory Testing (with Timeout)
```bash
# Memory leak check with timeout protection
timeout 60s valgrind --leak-check=full --error-exitcode=1 ./src/suricata -u -U "*{TestPattern}*"

# If valgrind times out, there's likely an infinite loop:
if [ $? -eq 124 ]; then
    echo "TIMEOUT in valgrind - indicates infinite loop in test"
    echo "Check: while loops, recursive calls, linked list traversal"
fi
```

## App-Layer Pattern

### Protocol Parser Structure
```bash
# Study existing parsers for patterns
ls src/app-layer/
cat src/app-layer/template.c  # If available
cat src/app-layer/http.c      # Complex example
cat src/app-layer/dns.c       # Simpler example
```

### Standard Parser Functions
```c
// Standard pattern for all app-layer parsers
static AppLayerResult ProtocolParse(Flow *, void *, AppLayerParserState *, const uint8_t *, uint32_t, void *, const uint8_t);
static void ProtocolStateFree(void *);
static int ProtocolStateGetProgress(void *, uint8_t);
```

> **Reference**: See `src/app-layer/http.c` for full implementation pattern

## Profiling Pattern

### Performance Analysis Workflow
```bash
# 1. Build with profiling
./configure --enable-profiling --enable-profiling-locks
make clean && make

# 2. Run with profiling
./src/suricata -c suricata.yaml --engine-analysis -r test.pcap

# 3. Analyze results
cat /var/log/suricata/stats.log
```

### External Profiling Tools
```bash
# CPU profiling
perf record -g ./src/suricata -c suricata.yaml -r test.pcap
perf report

# Memory profiling  
valgrind --tool=callgrind ./src/suricata -c suricata.yaml -r test.pcap
```

## VS Code Task Integration (Preferred)

### 🎯 Use VS Code Tasks Over Command Line
**AI agents should prioritize VS Code tasks for better integration and error handling**

```bash
# PREFERRED: Use VS Code Task System
# Ctrl+Shift+P → Tasks: Run Task → Build Suricata
# This provides better error highlighting and integration

# Available VS Code Task: "Build Suricata" 
# - Runs: make -j8
# - Integrated with VS Code's problem matcher
# - Shows errors in Problems panel
# - Better for AI agents as it's part of the workspace
```

### VS Code Task Usage Patterns
```bash
# For AI agents: Always prefer VS Code tasks when available
# Use run_vs_code_task tool instead of run_in_terminal for builds

# Pattern 1: Build before testing
# 1. Run VS Code Task: "Build Suricata"  
# 2. Then: timeout 30s ./src/suricata -u -U "*YourTest*"

# Pattern 2: TDD workflow with VS Code
# 1. Write tests
# 2. Run VS Code Task: "Build Suricata" (expect failure)
# 3. Implement code
# 4. Run VS Code Task: "Build Suricata" (should succeed)
# 5. Test: timeout 30s ./src/suricata -u -U "*YourTest*"
```

### Extended VS Code Tasks Configuration
**Additional tasks that can be added to .vscode/tasks.json:**

```json
{
    "version": "2.0.0", 
    "tasks": [
        {
            "label": "Build Suricata",
            "type": "cppbuild", 
            "command": "make",
            "args": ["-j8"],
            "group": {"kind": "build", "isDefault": true},
            "detail": "Build Suricata with parallel compilation"
        },
        {
            "label": "Suricata: Clean Build",
            "type": "shell",
            "command": "make clean && make -j8",
            "group": "build",
            "presentation": {"echo": true, "reveal": "always"},
            "problemMatcher": ["$gcc"]
        },
        {
            "label": "Suricata: Run Unit Tests",
            "type": "shell", 
            "command": "timeout 60s ./src/suricata -u",
            "group": "test",
            "dependsOn": "Build Suricata",
            "presentation": {"echo": true, "reveal": "always"}
        },
        {
            "label": "Suricata: Test Specific Keyword",
            "type": "shell",
            "command": "timeout 30s ./src/suricata -u -U '*${input:keywordName}*'",
            "group": "test", 
            "dependsOn": "Build Suricata"
        }
    ],
    "inputs": [
        {
            "id": "keywordName",
            "description": "Enter keyword name for testing",
            "default": "YourKeyword",
            "type": "promptString"
        }
    ]
}
```

### Development Workflow Automation

### Pre-Commit Checklist Script (Enhanced)
```bash
#!/bin/bash
# Save as scripts/pre-commit-check.sh

echo "🔍 Running pre-commit checks..."

# Build check (prefer VS Code task if available)
echo "Building..."
make clean && make -j$(nproc) || exit 1

# Unit tests with timeout protection
echo "Running unit tests..."
timeout 120s ./src/suricata -u || exit 1

# Style check
echo "Checking code style..."
make clang-format-check || exit 1

# Memory leak check (quick) with timeout
echo "Checking for memory leaks..."
timeout 60s valgrind --leak-check=summary ./src/suricata -u -U "YourTest*" || exit 1

echo "✅ All checks passed!"
```

## Advanced Patterns

### Multi-threaded Keyword Considerations
```c
// Only implement if you need per-thread data
static int KeywordThreadInit(DetectEngineThreadCtx *, const Signature *, void *);
static int KeywordThreadFree(DetectEngineThreadCtx *, const Signature *, void *);
```

> **Reference**: See `src/detect-content.c` ThreadInit/ThreadFree for pattern

### Protocol-Specific Matching  
```c
// For HTTP, TLS, etc. specific keywords
static int KeywordAppLayerMatch(DetectEngineThreadCtx *, Flow *, uint8_t, void *, void *, const Signature *, const SigMatchCtx *);
```

> **Reference**: See `src/detect-http-uri.c` for app-layer matching pattern

## Community Integration

### Getting Help Efficiently
1. **Search first**: GitHub issues, forum archives
2. **Provide context**: Code snippet, error message, build environment
3. **Reference specific files**: "Issue in `src/detect-keyword.c` line 123"

### Contributing Guidelines Reference
- **Style**: Run `make clang-format` before committing
- **Tests**: All new code needs unit tests
- **Documentation**: Update relevant .rst files in doc/
- **Performance**: Measure impact with `--engine-analysis`

### Key Community Resources
- [Suricata Forum](https://forum.suricata.io/) - Best for questions
- [GitHub Issues](https://github.com/OISF/suricata/issues) - Bug reports
- [Developer Docs](https://docs.suricata.io/en/latest/devguide/) - Architecture
- [Suricata-Verify](https://github.com/OISF/suricata-verify) - Integration tests

## Agent-Specific Instructions (Enhanced)

### For AI Agents: Critical Patterns to Follow
```yaml
# Essential AI Agent Behavior Patterns:

Build_System_Integration:
  - ALWAYS use VS Code "Build Suricata" task when available
  - NEVER skip Makefile.am entries for new C files  
  - ALWAYS verify build integration with --list-keywords/--list-* commands
  - Use timeout wrappers for all unit test execution

Memory_Management:
  - Use SCMalloc/SCFree, NEVER malloc/free in Suricata code
  - ALWAYS implement Free functions for Setup functions  
  - Check for NULL returns from SCMalloc

Error_Handling:
  - Return -1 for setup failures, 0 for no match, 1 for match
  - ALWAYS validate input parameters in Setup functions
  - Use proper error logging with SCLogError()

Code_Style:
  - 4 spaces indentation, NO tabs
  - K&R brace style  
  - 100 character line limit
  - Function names: DetectKeywordSetup, DetectKeywordMatch, DetectKeywordFree

Testing_Strategy:
  - TDD approach for keywords/parsers (write tests first)
  - Generic approach for optimization/output modules  
  - ALWAYS use timeout 30s for unit test execution
  - Test both positive and negative cases
  - If you happen to run into failing tests or abrupt code stops it might be
    because of FatalError. In that case, edit the code so it all the callables
    can be tested using unittessts.
```

### For GitHub Copilot
```yaml
# Add to .copilot/instructions.md if using GitHub Copilot
Suricata_Development_Context:
  templates:
    - Always reference src/detect-template.* for new keywords
    - Use src/tests/detect-template.c for test patterns
    - Follow src/output-json-alert.c for output modules
  
  testing:
    - Use UtRegisterTest() pattern for all unit tests
    - ALWAYS wrap unit tests with timeout 30s
    - Implement DetectKeywordRegisterTests() function
  
  integration:
    - Check src/detect-engine-register.{c,h} for keyword registration
    - Add to src/Makefile.am for build integration
    - Use VS Code "Build Suricata" task over command-line make
  
  memory_and_style:
    - Memory: SCMalloc/SCFree, never malloc/free
    - Errors: Return -1 for setup failures, 0 for no match, 1 for match
    - Style: 4 spaces, K&R braces, 100 char lines
    - Logging: SCLogError(), SCLogWarning(), SCLogInfo()
```

### For Claude/ChatGPT Integration
```markdown
# Context Loading Strategy for AI Agents

1. **Initial Context**:
   - Load this guide for workflow patterns
   - Always create and maintain a scratchpad file
   - Use VS Code tasks when available over command-line

2. **Implementation Strategy**:
   - Choose TDD workflow for keywords/parsers
   - Choose Explore-Plan-Code workflow for complex features
   - ALWAYS use timeout protection for unit tests

3. **Reference Priority**:
   - Template files > documentation > existing similar implementations
   - VS Code tasks > command-line builds
   - Timeout-protected testing > direct test execution

4. **Error Prevention**:
   - Verify build integration before testing
   - Use scratchpad to track progress and issues
   - Check --list-* commands to verify feature registration
```

## Troubleshooting Index (Enhanced)

### Quick Diagnostic Commands
```bash
# Environment check
./src/suricata --build-info | grep -E "(Unit tests|Debug|PCRE)"

# Feature registration verification
./src/suricata --list-keywords | grep your-keyword
./src/suricata --list-app-layer-protos | grep your-proto
./src/suricata --list-outputs | grep your-output

# Test registration check
./src/suricata --list-unittests | grep YourKeyword

# Memory leak check with timeout
timeout 60s valgrind --leak-check=full ./src/suricata -u -U "YourTest*"

# Build system verification
grep -n "your-file.c" src/Makefile.am
grep -n "YourKeywordRegister" src/detect-engine-register.c
```

### Error Pattern → Solution Mapping (Enhanced)
| Error | Check | Fix | Prevention |
|-------|--------|-----|------------|
| Unknown keyword | `--list-keywords` | Registration in `detect-engine-register.c` | Always verify registration |
| Test not found | `--list-unittests` | RegisterTests function call | Follow test template pattern |
| Segfault in setup | `gdb backtrace` | NULL pointer checks | Validate all parameters |
| Memory leak | `valgrind output` | Free function implementation | Match every SCMalloc with SCFree |
| Build failure | `make V=1` | Makefile.am entries | Check integration checklist |
| Test timeout | `timeout command` | Review loops/recursion | Use timeout wrappers always |
| Cargo build failed | `cargo check` | Module declarations in lib.rs | Follow Rust integration guide |

## Success Metrics

### Quality Gates
- [ ] **Builds**: `make clean && make` succeeds
- [ ] **Tests**: `./src/suricata -u -U "YourTest*"` passes  
- [ ] **Style**: `make clang-format-check` passes
- [ ] **Memory**: `valgrind` shows no leaks
- [ ] **Integration**: Keyword appears in `--list-keywords`
- [ ] **Documentation**: Function headers complete

### Performance Benchmarks
```bash
# Before your changes
time ./src/suricata -c suricata.yaml -r large.pcap > baseline.log

# After your changes  
time ./src/suricata -c suricata.yaml -r large.pcap > modified.log

# Compare
diff baseline.log modified.log
```

---

## Conclusion: AI Agent Development Mastery

This guide provides **AI-optimized workflows** for efficient Suricata development. By following these patterns, AI agents can implement features reliably while avoiding common pitfalls.

### 🤖 AI Agent Success Formula

**Choose the Right Workflow:**
- 🧪 **TDD Workflow** → Keywords, parsers, protocol handling 
- 🔍 **Explore-Plan-Code Workflow** → Output modules, optimization, complex features
- 📝 **Always use scratchpad** → Track progress, maintain context

**Essential Safety Patterns:**
- ⏱️ **Timeout protection** → `timeout 30s` for all unit tests
- 🎯 **VS Code tasks first** → Prefer integrated tools over command-line
- 🔧 **Build integration checklist** → Verify Makefile.am, registration, includes
- 💾 **Memory management** → SCMalloc/SCFree only, never malloc/free

**Quality Assurance:**
- ✅ **Verification commands** → `--list-keywords`, `--list-unittests`
- 🔍 **Template following** → Use detect-template.c patterns consistently  
- 📋 **Integration checklist** → Complete all build system steps
- 🧪 **Comprehensive testing** → Parse, match, edge cases, memory

### 🎯 Key Principles for AI Agents

1. **🔍 Study first** - Use existing code as your primary reference
2. **📋 Follow patterns** - Templates exist to ensure consistency
3. **🧪 Test with timeouts** - Prevent infinite loops in unit tests
4. **🎯 Use VS Code tasks** - Better integration than command-line builds
5. **📝 Track with scratchpad** - Maintain context across development phases
6. **📚 Reference, don't repeat** - Point to authoritative sources
7. **🤝 Verify integration** - Always check `--list-*` commands

### 🚀 Workflow Pattern Quick Reference

```bash
# TDD Pattern (Keywords/Parsers):
1. Create scratchpad to write down tasks to do and tick them off as you go
2. Write failing tests → commit
3. Implement minimal code  
4. VS Code Task: "Build Suricata"
5. timeout 30s ./src/suricata -u -U "*Test*"
6. Iterate until passing → commit

# Explore-Plan-Code Pattern (Complex Features):
1. Create scratchpad to write down tasks to do and tick them off as you go
2. Explore existing implementations
3. Plan changes in scratchpad
4. Implement following patterns
5. VS Code Task: "Build Suricata" 
6. Verify with feature-specific commands → commit
```

### 🎭 Remember: This Guide is AI-Agent Optimized

- **For humans**: Focus on learning concepts and understanding architecture
- **For AI agents**: Follow workflows systematically, use automation, prevent common failures

**Every Suricata feature follows these same patterns. Master the patterns, and you master Suricata development as an AI agent.**

### 📚 Essential References (Bookmark These)
- [Suricata Developer Guide](https://docs.suricata.io/en/latest/devguide/) - Architecture overview
- [Coding Style Guide](https://docs.suricata.io/en/latest/devguide/codebase/coding-style.html) - Style requirements  
- [GitHub Issues](https://github.com/OISF/suricata/issues) - Bug reports and discussions
- [Suricata Forum](https://forum.suricata.io/) - Community support
- **This Guide** - Workflow patterns and AI agent optimization
