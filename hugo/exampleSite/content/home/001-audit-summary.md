+++
weight = 10
+++

## Index

- 1. audit 어떻게 보안에 활용할까?
    - 1.1 큰 그림
    - 1.2 Hook
    - 1.3 audit 슈퍼 유저가 되기
    - 1.4 감사 정책 포맷

- 2. 리눅스 커널 audit 내부 구조 분석!
    - 2.1. 언제 어떻게 초기화 되는가?
    - 2.2. 감사 정책을 어떻게 로드할까?
    - 2.2. **audit.log** 로그에 찍히기까지

- 3. 참고

---

### 1. audit 어떻게 보안에 활용할까?

- *`/opt` 디렉토리 안에 중요한 파일이 있는데 어떤 사용자가 지우셨나요?*
- *이상한 소프트웨어가 자꾸 설치되네요. 어떤 사용자가 설치한거죠?*
- *소스 서버에 자꾸 이상한 IP 가 접근합니다. 이러다가 DRM 걸리거나 소스를 들고 나가는거 아닌지 모르겠어요.*

- **audit 을 잘 사용하기 위해서 커널/유저 동작과 소프트웨어 컴포넌트는 어떻게 구성되어 있는 지 살펴봅니다.**

---

### 1.1 큰 그림

- 커널 프로세스 kauditd 와 auditd 서비스 데몬이 netlink 기반으로 통신을 합니다.

<img src="000-audit_components.png" alt="audit_components" width="720">

---

### 1.2 Hook

- audit_context

---

### 1.3 audit 슈퍼 유저가 되기

- auditd
- auditctl

---

## 1.4 감사 정책 포맷

- youtube

<a href="http://www.youtube.com/watch?feature=player_embedded&v=WzIpMlS89HI
" target="_blank"><img src="http://img.youtube.com/vi/WzIpMlS89HI/0.jpg" 
alt="Git Lens" width="400" height="300" /></a>
