# Threat Model v0.2

## System

User
→ LLM
→ Tool Request
→ Validation
→ Authorization
→ Runtime Enforcement
→ Tool
→ Filesystem

---

## Assets

- Workspace files
- Notes
- Configuration
- Source code
- Agent Tool capability
- Execution integrity

---

## Trust Assumptions

LLM output은 신뢰하지 않는다.

Tool argument는 신뢰하지 않는다.

Validator, Authorization Layer,
Runtime Enforcement는
Trusted Computing Base의 일부로 간주한다.

Filesystem content는
source에 따라 trusted / untrusted일 수 있다.

---

## Threats

| Threat | Attack Surface | Mitigation | Experiment |
|---|---|---|---|
| Path Traversal | File path | safe_resolve() | EXP-007 |
| Unauthorized Read | read_file | Permission Policy + authorize() | EXP-008 |
| Unauthorized Write | write_file | Permission Policy + authorize() | EXP-009 |
| Arbitrary Command | run_command | Command Allowlist | EXP-010 |

---

## Security Flow

Tool Request
→ Validation
→ Authorization
→ Runtime Enforcement
→ Execution

---

## T-001 Path Traversal

Threat:

Attacker-controlled path가 Sandbox 밖의
Resource에 접근할 수 있다.

Example:

read_file("../secret.txt")

Mitigation:

safe_resolve()

Expected:

Validation DENY

---

## T-002 Unauthorized Write

Threat:

Agent가 Sandbox 내부이지만
Write가 허용되지 않은 Resource를 수정할 수 있다.

Example:

write_file("notes/output.txt")

Mitigation:

Permission Policy

authorize()

Expected:

Validation PASS

Authorization DENY

---

## T-003 Arbitrary Command

Threat:

Agent가 허용되지 않은 command를
실행하려고 시도할 수 있다.

Example:

run_command("rm file.txt")

Mitigation:

Command Allowlist

Expected:

Authorization DENY

---

## Residual Risks

현재 버전에서는 다음을 아직 다루지 않는다.

- Symlink edge cases
- Shell metacharacters
- Argument-level command policy
- User approval
- Multiple Agent identities
- Dynamic permissions
- Network permissions
- Indirect Prompt Injection