# 프로젝트 개요

전체 개요 문서(목표, 차별점, 52개 점검 항목, 판정 규칙, 검증 계획, 진행 단계)는 아래 문서에서 관리합니다.

- https://claude.ai/artifact/RnnC3xnxQijMKhdR7bgFm9

핵심 결정 요약
- 대상: Ubuntu Server 22.04/24.04 웹 서버 1대, root로 직접 실행
- 판정: 심각 / 위험 / 정상 3단계, 판정마다 원본 증거·이유·다음 확인 사항
- 진행: 항목을 구현할 때마다 검증 VM에 바로 적용해 확인 (만들기와 검증을 번갈아)
- 검증 VM: 공개 VM(lin.security, Metasploitable3) + 깨끗한 Ubuntu VM
