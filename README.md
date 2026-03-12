# 하이브리드 AI 기반 악성코드 판별 시스템

> **API 호출 시퀀스 예측 및 PE 구조 분석을 결합한 통합 탐지 파이프라인**
> 

본 프로젝트는 정적 분석의 한계와 동적 분석의 제약을 동시에 해결하기 위해 개발되었습니다. Ghidra P-Code 분석을 통한 행위 예측 모델과 LightGBM 기반의 구조 분석 모델을 결합한 하이브리드 접근법을 채택했습니다.

---

## 프로젝트 핵심 철학

- **Beyond Presence:** 단순히 "어떤 API가 있는가?"를 넘어 **"어떤 순서로 호출되는가?"**가 악성 행위의 본질이라는 점에 착안했습니다.
- **Realistic Alternative:** 웹 서비스 환경에 부합하지 않는 무거운 샌드박스(CAPEv2) 대신, **Ghidra + DFS 알고리즘**을 통해 실시간에 가까운 속도로 행위 기반 분석을 구현했습니다.

## 시스템 아키텍처

사용자 업로드부터 최종 판별까지 총 5개의 레이어로 구성된 비동기 처리 파이프라인입니다.

1. **Layer 1 (Presentation):** Next.js 기반 실시간 대시보드
2. **Layer 2 (API Gateway):** FastAPI를 통한 파일 수신 및 유효성 검사
3. **Layer 3 (Task Queue):** Celery & Redis를 이용한 대규모 분석 작업 분산
4. **Layer 4 (Analysis & Inference):**
    - **Ghidra/dnlib:** 함수 호출 그래프(Call Graph) 추출
    - **DFS Preprocessor:** 실행 흐름 시퀀스 생성
    - **Dual AI Models:** BigBird(행위) & LightGBM(구조) 추론
5. **Layer 5 (Data Persistence):** PostgreSQL을 이용한 분석 결과 및 해시 캐싱

## 하이브리드 AI 모델링

### 1. API 시퀀스 분석 모델 (BigBird Transformer)

- **Input:** DFS로 정렬된 계층적 API 호출 시퀀스
- **Model:** 최대 4096 토큰을 처리하는 **BigBird** 채택 (일반 BERT의 512 토큰 한계 극복)
- **Strength:** 파일 다운로드 → 실행 → 지속성 유지로 이어지는 논리적 공격 패턴 식별

### 2. PE 구조 분석 모델 (LightGBM)

- **Features:** PE 헤더 정보, 섹션 엔트로피, 디지털 서명 유효성 등 32개 특징 추출
- **Performance:** **F1 Score 0.99** 달성
- **Strength:** 실행 압축 및 코드 암호화가 적용된 비정상 구조 파일 탐지에 특화

## 문제 해결 및 기술적 성장 (Troubleshooting)

- **동적 분석의 제약 극복:** CAPEv2 샌드박스 구축 시 발생한 KVM 가상화 이슈와 긴 분석 시간을 해결하기 위해, 정적 분석 도구인 Ghidra의 디컴파일 기능을 역이용하여 **동적 분석과 유사한 예측 시퀀스를 생성**하는 창의적 대안을 제시했습니다.
- **간접 호출(Indirect Call) 대응:** 악성코드의 은닉 기법인 레지스터 기반 호출을 추적하기 위해 P-Code 레벨 분석을 수행하고, 도달 불가능한 **고아 함수(Orphan Functions)** 내의 위험 API 분포를 분석 결과에 반영했습니다.

## 향후 계획 (Roadmap)

- **데이터셋 고도화:** 상용 소프트웨어 설치 파일(Installer) 대규모 수집을 통한 오탐(False Positive) 감소
- **실측 기반 분석:** API 후킹(Hooking) 기술을 도입하여 예측을 넘어선 경량 동적 분석 엔진 구축

## 시작하기

### 환경 변수 설정 (.env)

`VT_API_KEY=your_virustotal_api_key`

### 시스템 가동

codeBash

`chmod +x start_all.sh ./start_all.sh`
