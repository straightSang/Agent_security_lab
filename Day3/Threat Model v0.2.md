> [Threat Model]
> - 시스템의 자산
> - 예상되는 공격자
> - 신뢰 경계
> - 가능한 공격
> 을 정리한 문서.



### 1. System

```
Minimal Tool-Using Agent

User

↓

LLM

↓

Tool Dispatcher

↓

Validator

↓

Runtime

↓

Filesystem
```

---

### 2. Assets

보호해야 하는 것

```
Filesystem

User files

Credentials

Source code

Tool capability

Execution integrity
```

---

### 3. Actors

누가 시스템과 상호작용하는가

```
User

LLM

Runtime

Filesystem

Attacker
```

---

### 4. Entry Points

공격자가 영향을 줄 수 있는 곳

```
User Prompt

Files

Tool Output

Observation
```


### 5. Trust Boundaries

```
User → LLM

LLM → Tool

Tool → Runtime

Runtime → Filesystem
```

### 6. Threats

| Threat | 위치 |
| --- | --- |
| Prompt Injection | User → LLM |
| Indirect Prompt Injection | File → LLM |
| Tool Misuse | LLM → Tool |
| Path Traversal | Tool → Runtime |
| Privilege Abuse | Runtime → Filesystem |


### 7. Mitigation



### ?. Summary

| Source | Trusted? | Destination | Boundary | Risk |
| --- | --- | --- | --- | --- |
| User | No | LLM | User → Model | Prompt Injection |
| File | No | LLM Context | File → Model | Indirect Prompt Injection |
| LLM Output | No | Tool | Model → Runtime | Tool Misuse |
| Tool Arguments | No | Validator | Tool → Runtime | Path Traversal |
| Runtime | Yes | Filesystem | Runtime → OS | Permission Enforcement |
| Tool Output | Conditional | LLM | Environment → Model | Context Poisoning |


### 8. To be supplemented

- Threats

- Mitigation

- Experiment Mapping