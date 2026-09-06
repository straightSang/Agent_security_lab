# 작성 예시 — 실제로 있었던 하루를 채워 본 것

`_TEMPLATE.md`의 각 칸에 무엇을 적는지 보여 주는 견본이다. 실제 연구 기록이 아니라
예시이므로 `docs/notes/`의 날짜 파일로 세지 않는다.

내용은 W1 D1에서 실제로 있었던 일(정책 도달 가능성 테스트가 `run_command`를
검사하지 않던 문제)을 그대로 옮겼다.

---

# W1 D1 — 정책 도달 가능성 검사의 사각지대

| 필드 | 값 |
|---|---|
| 날짜 | 2026-09-05 |
| Experiment ID | EXP-W1D1-01 |
| 커밋 | 166b00c |
| 환경 | Python 3.12.8 / model 없음 (정책 엔진 단위 검사) |

## 오늘의 목표

`POLICY`에 선언한 규칙 중 어떤 호출로도 도달할 수 없는 분기가 더 있는지 찾는다.

## 가설

**도달 가능성 테스트가 `allowed_scopes`만 순회하므로, `allowed_commands`로 선언된
`run_command`의 허용 명령 3종은 한 번도 검사되지 않았을 것이다.**

반증 조건: 테스트에 명령 순회를 추가했을 때 "검사한 항목" 수가 늘지 않으면 가설이 틀렸다.

## 구현

`tests/test_policy_reachability.py`에 두 가지를 추가했다.

- `COMMAND_EXAMPLES` — 명령마다 대표 명령문을 사람이 지정한다. 자동 생성하면
  테스트가 구현을 그대로 따라 하게 되어 검증력이 사라진다.
- `test_every_declared_command_is_reachable()` — `rule.get("allowed_commands", ())`를
  순회하며 각 명령이 PolicyEngine까지 도달하는지 확인한다.

`main()`에 등록해 직접 실행에서도 돌게 했다.

## 실험

- 조건: baseline(추가 전) / 처치(추가 후)
- 표본: `POLICY`의 `run_command.allowed_commands` 전체 (pwd, ls, cat) n=3
- 실행 명령:

```bash
python3 tests/test_policy_reachability.py
```

## 관측

해석 없이 사실만 적는다.

**baseline** — `검사한 (도구, scope) 조합: 5개`. `run_command` 관련 출력 없음.

**처치 1차 시도** — 실패했다. 인자를 `{"path": example}`로 넘겼다.

```
AssertionError: 도달 불가 정책 분기:
  - ls  — 명령어 'ls data/user-001'가 Policy에 도달하지 못함 (사유 MCP_REQUIRED_ARGUMENT_MISSING)
  - cat — 명령어 'cat data/user-001/notes.txt'가 ... (사유 MCP_REQUIRED_ARGUMENT_MISSING)
  - pwd — 명령어 'pwd'가 ... (사유 MCP_REQUIRED_ARGUMENT_MISSING)
```

**처치 2차 시도** — 인자를 `{"command": example}`로 고쳤다.

```
검사한 (도구, scope) 조합: 5개
검사한 허용명령: 3개
정책 도달 가능성 테스트: PASS
```

## 결과

| 지표 | Baseline | 처치 | 해석 |
|---|---:|---:|---|
| 검사된 정책 분기 수 | 5 | 8 | 3개 분기가 미검사 상태였다 |
| 도달 불가로 판명된 분기 | 0 | 0 | 도달은 가능했으나 확인된 적이 없었다 |

가설은 **참**이었다. 다만 방향이 예상과 달랐다. 도달 불가 분기를 찾을 줄 알았는데,
실제로는 "도달은 되지만 아무도 확인하지 않은 분기"였다. A-01과는 다른 유형의 사각지대다.

## 반례 / 실패한 run

**1차 시도의 실패가 이 실험에서 가장 값진 관측이었다.**

`MCP_REQUIRED_ARGUMENT_MISSING`은 테스트 코드의 버그였지만, 동시에 schema gate가
계약 위반을 Policy 도달 전에 차단한다는 직접 증거였다. 같은 입력을 두 계층에 각각
넣어 확인했다.

```
schema gate -> allowed=False  reason=MCP_REQUIRED_ARGUMENT_MISSING
validation  -> allowed=False  reason=COMMAND_ARGUMENT_UNUSABLE
```

두 계층이 같은 입력을 서로 다른 사유로 거부한다. 어휘가 겹치지 않게 설계했기 때문에
trace만 보고도 어느 관문에서 멈췄는지 구별할 수 있다.

## 한계

이 결과로 말할 수 없는 것을 적는다.

- "정책 분기가 전부 검사된다"까지만 말할 수 있다. **"정책이 옳다"는 말할 수 없다.**
  대표 경로와 대표 명령을 사람이 지정하므로, 지정한 사람의 착각은 그대로 통과한다.
- `allowed_commands`, `allowed_scopes` 외의 규칙 키가 나중에 추가되면 같은 사각지대가
  다시 생긴다. 지금 구조는 키 이름을 하드코딩하고 있다.

## 다음 행동

30분 이하 단위로 쪼갠다.

- [ ] `POLICY`의 규칙 키를 순회해 미검사 키가 있으면 실패시키는 메타 테스트 추가 (30분)
- [ ] `SCOPE_EXAMPLES`에 의도적으로 틀린 경로를 넣어 테스트가 실제로 잡는지 확인 (20분)
- [ ] 반례 1건을 `docs/THREAT_MODEL.md`의 미해결 항목에 반영 (15분)
