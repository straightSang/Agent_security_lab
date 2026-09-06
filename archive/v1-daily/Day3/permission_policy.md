# Permission Policy v0.1

## Purpose

Mini Agent가 Tool을 통해 접근할 수 있는
Resource와 Action 범위를 정의한다.

Security decision은 LLM이 아니라
Runtime Authorization Layer에서 수행한다.

---

## Read Policy

read_file은 다음 directory에 접근 가능하다.

- workspace/
- notes/

그 외 directory는 DENY한다.

---

## Write Policy

write_file은 다음 directory에만 접근 가능하다.

- workspace/

다음 directory에는 write를 허용하지 않는다.

- notes/
- config/
- 기타 sandbox 내부 directory

---

## Command Policy

run_command는 다음 command만 허용한다.

- pwd
- ls
- cat

기타 command는 DENY한다.

---

## Security Principle

Validation과 Authorization은 분리한다.

Validation:

"요청이 유효한가?"

Authorization:

"Agent에게 이 Action을 수행할 권한이 있는가?"

따라서 Sandbox 내부에 있는 Resource라도
Permission Policy에 의해 DENY될 수 있다.

Example:

write_file("notes/test.txt")

Validation:
PASS

Authorization:
DENY