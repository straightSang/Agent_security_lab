# CODE STYLE — 주석 규약

이 저장소의 모든 Python 코드는 아래 형식을 따른다.
새 코드를 쓸 때도, 기존 코드를 고칠 때도 같은 형식을 유지한다.

**핵심 규칙: 주석은 블록 안(docstring)이 아니라 정의 바깥에 `#`으로 적는다.**

---

## 함수

```python
# 함수이름: 함수명
# 인자:
#     이름 (타입): 설명. 기본값이 있으면 그것도 적는다
#     이름 (타입): 설명
# 반환값:
#     타입: 설명
#     예외타입: 어떤 조건에서 발생하는지
# 기능 설명:
#     무엇을 하는지 한두 문장.
#
#     [왜 이렇게 했는가]
#     설계 판단의 근거. 대안을 버린 이유.
#
#     [주의]
#     이 함수를 쓸 때 놓치기 쉬운 것.
def 함수명(...):
    ...
```

### 규칙

- **docstring을 쓰지 않는다.** 모든 설명은 정의 위의 `#` 주석 블록에 둔다.
- **데코레이터가 있으면 데코레이터 위**에 블록을 둔다. 정의가 시작하는 지점이
  데코레이터이기 때문이다.

  ```python
  # 함수이름: PolicyEngine._decision
  # ...
  @staticmethod
  def _decision(...):
  ```

- **인자가 없으면** `인자: 없음`이라고 적는다. 항목 자체를 빼지 않는다.
- **반환값이 없으면** `None: 반환값 없음`으로 적고, 부작용이 있으면 함께 적는다.
  예: `None: 반환값 없음. sandbox_root 디렉터리를 생성하는 부작용이 있다`
- **예외를 던지면** 반환값 항목에 함께 적는다. 호출자가 무엇을 대비해야 하는지가
  반환 계약의 일부이기 때문이다.
- **`기능 설명:`은 "무엇을"보다 "왜"에 무게를 둔다.** 무엇을 하는지는 코드를
  읽으면 알 수 있다. 왜 그렇게 했는지는 코드에 없다.
- **대괄호 소제목은 아껴 쓴다.** 기본은 소제목 없이 문단으로 잇는 것이다.
  설명이 산문이면 소제목이 없어도 읽힌다.

  소제목을 쓰는 경우는 셋뿐이다.

  | 용도 | 예 |
  |---|---|
  | 목록·다이어그램의 라벨 (앞 문장이 소개하지 않을 때) | `[상태 전이]`, `[세 개의 프로필]` |
  | 놓치면 위험한 경고 | `[주의]` |
  | 평가보고서 항목 참조 | `[A-01]`, `[C-02]` |

  앞 문장이 "다음과 같다", "세 가지를 거부한다"처럼 블록을 소개하고 있으면
  라벨은 필요 없다.
- **주석 블록은 15줄 이내를 목표로 한다.** 넘으면 모듈 주석이나 섹션 배너로
  옮길 내용이 섞여 있는지 본다. 여러 함수에 걸친 설계 근거는 함수마다 반복하지
  말고 위쪽에 한 번만 적는다.
- 예외적으로 길어도 되는 곳은 그 파일의 핵심 함수 하나뿐이다.
  (`runtime.py`의 `execute_tool`, `experiment_support.py`의
  `record_run_evidence` 등)
- 메서드는 `함수이름: 클래스명.메서드명`으로 적는다. 같은 이름 메서드가 여러
  클래스에 있을 때 구분된다.

## 클래스

```python
# 클래스이름: 클래스명
# 필드:
#     이름 (타입): 설명
# 메서드:
#     이름(): 한 줄 설명
# 기능 설명:
#     ...
@dataclass(frozen=True)
class 클래스명:
    ...
```

`필드:`와 `메서드:`는 해당하는 것만 적는다. Enum은 `필드:`에 각 멤버를 적는다.

## 모듈

파일 맨 위에 둔다.

```python
# 모듈이름: 모듈명
# 역할: 한 줄 요약
# 호출 주체: 누가 이 모듈을 import하는가
#
# 기능 설명:
#     ...
```

`호출 주체:`는 의존 방향이 설계상 중요할 때 특히 유용하다. 예를 들어
`experiment_support`는 "tests/만 호출한다. agent와 runtime은 호출하지 않는다"가
그 자체로 보안 규칙이다.

## 인라인 주석

함수 안의 `#` 주석은 이 형식을 따르지 않는다. 한 줄로 "왜 이 줄이 필요한가"만
적는다.

```python
# 정규화 후에도 원본 sandbox 안인지 확인한다(심볼릭 링크 탈출 차단).
source.relative_to(source_root)
```

## 섹션 배너

파일이 길어 논리적 묶음이 필요하면 배너를 쓴다.

```python
# ===========================================================================
# 3부 — 재현성 증거
#
# 이 묶음이 왜 존재하는지, 어떤 문제를 푸는지를 여기서 설명한다.
# ===========================================================================
```

---

## 왜 이 형식인가

보안 연구 코드는 **6개월 뒤의 자신**과 **재현하려는 제3자**가 읽는다. 둘 다
"이 함수가 무엇을 반환하나"보다 "왜 이 판단을 했나"를 알아야 한다.

인자와 반환값을 고정된 자리에 두면 훑어보는 속도가 빨라지고, `기능 설명`에
설계 근거를 몰아두면 그 근거가 코드 변경과 함께 갱신된다. 별도 문서에 적힌
설계 근거는 반드시 낡는다.

### 정의 바깥에 두는 이유

코드를 읽을 때 함수 본문이 첫 줄부터 바로 보인다. docstring이 안에 있으면
본문을 보려면 스크롤을 해야 하고, 짧은 함수일수록 설명이 코드보다 길어져
구조가 가려진다. 설명과 구현을 시각적으로 분리한다.

---

## 적용 현황

| 파일 | 형식 블록 | 정의 |
|---|---:|---:|
| `conftest.py` | 1 | 0 |
| `src/agent.py` | 9 | 9 |
| `src/approval_control.py` | 3 | 2 |
| `src/experiment_support.py` | 13 | 12 |
| `src/lab_paths.py` | 2 | 1 |
| `src/runtime.py` | 16 | 15 |
| `src/trace_logger.py` | 17 | 17 |
| `src/trace_reader.py` | 6 | 5 |
| `src/security/__init__.py` | 1 | 0 |
| `src/security/approval.py` | 9 | 8 |
| `src/security/authorization.py` | 7 | 6 |
| `src/security/capability.py` | 4 | 3 |
| `src/security/evaluator.py` | 5 | 4 |
| `src/security/fixtures.py` | 3 | 2 |
| `src/security/permission.py` | 1 | 0 |
| `src/security/policy.py` | 6 | 6 |
| `src/security/provenance.py` | 9 | 8 |
| `src/security/tool_schema.py` | 8 | 7 |
| `src/security/trust.py` | 2 | 1 |
| `src/security/types.py` | 21 | 20 |
| `tests/test_indirect_injection.py` | 1 | 1 |
| `tests/test_mcp_tool_schema.py` | 4 | 4 |
| `tests/test_policy_boundary.py` | 1 | 1 |
| `tests/test_policy_reachability.py` | 6 | 6 |
| `tests/test_security_invariants.py` | 7 | 7 |
| **합계** | **162** | **145** |

블록 수가 정의 수보다 많은 것은 모듈 주석이 포함되기 때문이다.
`__init__.py`, `permission.py`, `conftest.py`처럼 정의가 없고 선언·설정만 있는
파일도 모듈 주석을 갖는다.

## 검증

주석을 고칠 때마다 다음을 확인한다. 셋 다 통과해야 한다.

```bash
pytest                                  # 회귀 5스위트
python -m ruff check src tests          # 린트
```

추가로, 주석 작업이 코드를 건드리지 않았음을 AST로 확인한다. docstring을 제거한
구문 트리가 작업 전후로 동일해야 한다.

```python
import ast
def strip_docs(tree):
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if (n.body and isinstance(n.body[0], ast.Expr)
                    and isinstance(n.body[0].value, ast.Constant)
                    and isinstance(n.body[0].value.value, str)):
                n.body.pop(0)
    return tree

assert ast.dump(strip_docs(ast.parse(before))) == ast.dump(strip_docs(ast.parse(after)))
```
