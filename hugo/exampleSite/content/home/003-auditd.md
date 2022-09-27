+++
weight = 30
+++

### 2. 유저 스페이스 auditd 콤포넌트 분석!

- auditd 의 중요한 부분을 콕 찍먹해볼 시간입니다.

---

### 2.1. auditd 언제 어떻게 초기화 할까요?

- [auditd.c - main()](https://github.com/linux-audit/audit-userspace/blob/v3.0.9/src/auditd.c) 콕 찍어볼까요?

```c

	/* Load the Configuration File */
	if (load_config(&config, TEST_AUDITD))

	/* Init netlink */
	if ((fd = audit_open())

	// Init complete, start event loop
	if (!stop)
		ev_loop (loop, 0);

```

```c
int audit_open(void)
{
	int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_AUDIT);

```

---

### 2.2. 감사 정책을 어떻게 로드할까요?

auditd 데몬을 직접 만들어볼까요? libaudit + auditd 내부에서도 사용하는 libev 로~

```c
#include <stdio.h>
#include <unistd.h>

#include <libaudit.h>

#include <ev.h>

static int fd;

void monitoring(struct ev_loop *loop, struct ev_io *io, int revents) {
    struct audit_reply reply;

    audit_get_reply(fd, &reply, GET_REPLY_NONBLOCKING, 0);

    if (reply.type != AUDIT_EOE &&
            reply.type != AUDIT_PROCTITLE &&
            reply.type != AUDIT_PATH) {
        printf("Event: Type=%s Message=%.*s\n",
                     audit_msg_type_to_name(reply.type),
                     reply.len,
                     reply.message);
    }
}

int main() {
    fd = audit_open();
    struct audit_rule_data* rule = new audit_rule_data();

    // 디렉토리에 대한 감시는 다음과 같은 API 를 사용합니다.
    //  audit_add_watch_dir(AUDIT_DIR, &rule, "bitcoin");

    audit_add_watch(&rule, "bitcoin/wallet.dat");

    // 셋업한 룰을 auditd 에 넘겨줍니다.
    audit_add_rule_data(fd, rule, AUDIT_FILTER_USER, AUDIT_ALWAYS);
    struct ev_io monitor;
    audit_set_pid(fd, getpid(), WAIT_YES);

    audit_set_enabled(fd, 1);
    struct ev_loop *loop = ev_default_loop(EVFLAG_NOENV);

    ev_io_init(&monitor, monitoring, fd, EV_READ);
    ev_io_start(loop, &monitor);

    // wallet.dat 파일에 이벤트가 오는지 확인하면서 감시합니다.
    ev_loop(loop, 0);

    audit_close(fd);
    return 0;
}
```

---

### 주요 릴리즈 변경

2020-12-17 audit 3.0 릴리즈부터는 기존 audispd 이벤트 디스패쳐 데몬을 auditd 로 통합했습니다.

This is the long awaited 3.0 major feature release. Most notable item is that audispd is gone.
- Merge auditd and audispd code
- Move all audispd config files under /etc/audit/
- Move audispd.conf settings into auditd.conf
