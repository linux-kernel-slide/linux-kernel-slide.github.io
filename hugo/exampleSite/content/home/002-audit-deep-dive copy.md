+++
weight = 20
+++

### 2. 리눅스 커널 audit 내부 구조 분석!

- kaudit 의 중요한 부분을 콕 콕 찍먹해볼 시간입니다.

---

### 2.1. kaduit 언제 어떻게 초기화 될까요?

- auidt_init

---

### 2.2. 감사 정책을 어떻게 로드할까요?

- **auditctl** 이 로드한 감사 정책 내용을 audit_context 로

<img src="000-audit_components.png" alt="audit_components" width="720">

---

### 2.3. **audit.log** 로그에 찍히기까지

- audit_context
