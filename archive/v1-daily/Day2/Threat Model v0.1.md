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