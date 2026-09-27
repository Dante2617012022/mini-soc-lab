# Change control

Every meaningful lab change should answer the following before implementation:

1. What problem is being solved?
2. What security or operational risk exists?
3. What is the minimum change required?
4. Does the change create another source of truth?
5. Does it increase attack surface unnecessarily?
6. How will it be tested?
7. How will it be reverted?
8. What evidence will be retained?
9. What residual risk remains?
10. What claim can be defended from the resulting evidence?

## Change lifecycle

```text
scope
  ↓
baseline
  ↓
risk assessment
  ↓
small branch
  ↓
static validation / CI
  ↓
VM execution
  ↓
UAT
  ↓
sanitized evidence
  ↓
merge
```

## Initial change record

### CHG-001 — Endpoint baseline bootstrap

**Objective:** establish the initial state of the Debian endpoint before hardening or security-agent deployment.

**Change type:** read-only / evidence collection.

**Risk addressed:** untraceable configuration changes and inability to compare pre/post implementation state.

**Implementation:** `scripts/endpoint/collect-baseline.sh`.

**Validation:**

- script passes Bash syntax validation and ShellCheck;
- script runs without changing configuration;
- report and SHA-256 checksum are created locally;
- raw report is not committed to the public repository.

**Rollback:** not required for system state because the collector is read-only. Generated local evidence can be deleted if needed.

**Public evidence:** only sanitized excerpts or derived findings should be published.
