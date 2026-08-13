# 실증 검증 코드

`run_empirical_validation.py`는 GitHub의 `config/experiment_config.yaml`에 고정한 규모와 판정기준을 비식별 합성 데이터로 점검한다. Python 표준 라이브러리만 사용하므로 별도 패키지를 설치하지 않는다.

## 초보자 실행방법

1. 저장소 첫 화면에서 **Code → Download ZIP**을 누른다.
2. ZIP 파일의 압축을 푼다.
3. Windows에서 `run_validation.cmd`를 두 번 누른다.
4. `results` 폴더에서 JSON·CSV 결과를 확인한다.

명령창에서는 저장소 폴더에서 다음과 같이 실행할 수도 있다.

```powershell
python scripts/run_empirical_validation.py --output results
```

## 자동 검증 항목

- 규정 청크 606개
- 부모 질의 301개
- 대조 질의 2,167개
- 권한 불변 대조쌍 1,866개
- S4 사후 필터와 S5 검색 전 게이트웨이 비교
- 중간 후보 및 최종 결과의 권한 누출률
- 시점 위반률, nDCG@5, Hit@5
- 역할 사칭 질의 100개
- 동시 작업자 10명의 P95 응답시간
- 정책 스냅샷과 입력자료의 SHA-256 해시
- 선택적 HMAC-SHA256 서명

## 결과 해석 제한

현재 실행 결과는 사전등록 Release 이전에 합성자료로 수행한 공학적 작동 검증이다. 실제 기관 자료에 의한 논문의 확증적 실험 결과로 사용해서는 안 된다. 확증실험은 사전등록 Release 발행 후 별도 결과 폴더와 커밋으로 남긴다.
