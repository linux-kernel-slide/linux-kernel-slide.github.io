+++
weight = 20
+++

### 2. 리눅스 커널 kauditd 내부 구조 분석!

- kaudit 의 중요한 부분을 콕 찍먹해볼 시간입니다.

---

### 2.1. kaduit 언제 어떻게 초기화 될까요?

```
-> arch_call_rest_init()
  -> rest_init()
    -> pid = kernel_thread(kernel_init, NULL, CLONE_FS);
      -> kernel_init()
        -> kernel_init_freeable()
          -> do_basic_setup()
            -> do_initcalls()
```

- do_initcalls() 내의 Linux 커널 부팅 중 초기화 호출 상대적 순서를 살펴보면, 3번째에 해당하는 것을 볼 수 있습니다.
  - early_initcall(), core_initcall()
  - **postcore_initcall()** → **postcore_initcall(audit_init);**
  - arch_initcall(), subsys_initcall(), fs_initcall(), device_initcall()

---

### 2.1. kaduit 언제 어떻게 초기화 될까요?

```bash
# dmesg | grep audit
[    0.215458] audit: initializing netlink subsys (disabled)
[    0.215500] audit: type=2000 audit(1664301355.215:1): state=initialized audit_enabled=0 res=1
[    7.430702] audit: type=1404 audit(1664301363.005:2): enforcing=1 old_enforcing=0 auid=4294967295 ses=4294967295 enabled=1 old-enabled=1 lsm=selinux res=1
[    7.786790] audit: type=1403 audit(1664301363.360:3): auid=4294967295 ses=4294967295 lsm=selinux res=1
```
```bash
$ ps -ef | grep audit
root          69       2  0 09:29 ?        00:00:00 [kauditd]
root        1038       1  0 09:29 ?        00:00:00 /sbin/auditd
```

---

### 2.1. kaduit 언제 어떻게 초기화 될까요?

- **audit_init()** 다음 항목에 주목해서 보면 어떨까요?
  - skb_queue 자료구조 audit_queue
  - kauditd_thread(), audit_log()

```c
/* Initialize audit support at boot time. */
static int __init audit_init(void)
{
	int i;

	if (audit_initialized == AUDIT_DISABLED)
		return 0;

	audit_buffer_cache = kmem_cache_create("audit_buffer",
					       sizeof(struct audit_buffer),
					       0, SLAB_PANIC, NULL);

	skb_queue_head_init(&audit_queue);
	skb_queue_head_init(&audit_retry_queue);
	skb_queue_head_init(&audit_hold_queue);

	for (i = 0; i < AUDIT_INODE_BUCKETS; i++)
		INIT_LIST_HEAD(&audit_inode_hash[i]);
	// ...
	audit_initialized = AUDIT_INITIALIZED;

	kauditd_task = kthread_run(kauditd_thread, NULL, "kauditd");
	// ...
	audit_log(NULL, GFP_KERNEL, AUDIT_KERNEL,
		"state=initialized audit_enabled=%u res=1",
		 audit_enabled);

	return 0;
}
```

 - 큐 자료구조 초기화 및 kauditd 커널 스레드의 생성을 확인할 수 있습니다.

---

### 2.2. **audit.log** 로그에 찍히기까지

- **struct common_audit_data** : audit log 에서 사용할 data 구조체

```c
/* Auxiliary data to use in generating the audit record. */
struct common_audit_data {
	union 	{
		struct path path;
		struct dentry *dentry;
		struct inode *inode;
		struct lsm_network_audit *net;
		int cap;
		int ipc_id;
		struct task_struct *tsk;
		char *kmod_name;
		struct lsm_ioctlop_audit *op;
		struct file *file;
		struct lsm_ibpkey_audit *ibpkey;
		struct lsm_ibendport_audit *ibendport;
		int reason;
		const char *anonclass;
	} u;
}
```

---

### 2.2. **audit.log** 로그에 찍히기까지

- **common_lsm_audit()** : Hook 에서 audit 하기 위해 사용할 함수

```c
/**
 * common_lsm_audit - generic LSM auditing function
 * @a:  auxiliary audit data
 * @pre_audit: lsm-specific pre-audit callback
 * @post_audit: lsm-specific post-audit callback
 *
 * setup the audit buffer for common security information
 * uses callback to print LSM specific information
 */
void common_lsm_audit(struct common_audit_data *a,
	void (*pre_audit)(struct audit_buffer *, void *),
	void (*post_audit)(struct audit_buffer *, void *))
{
	struct audit_buffer *ab;

	if (a == NULL)
		return;
	/* we use GFP_ATOMIC so we won't sleep */
	ab = audit_log_start(audit_context(), GFP_ATOMIC | __GFP_NOWARN,
			     AUDIT_AVC);

	if (ab == NULL)
		return;

	if (pre_audit)
		pre_audit(ab, a);

	dump_common_audit_data(ab, a);

	if (post_audit)
		post_audit(ab, a);

	audit_log_end(ab);
}
```

---

### 2.2. **audit.log** 로그에 찍히기까지

- **audit_log_start()** : struct audit_buffer 인스턴스를 만들어줍니다.
- **audit_log_end()** : 만든 버퍼를 큐잉합니다.

```c
/* The audit_buffer is used when formatting an audit record.  The caller
 * locks briefly to get the record off the freelist or to allocate the
 * buffer, and locks briefly to send the buffer to the netlink layer or
 * to place it on a transmit queue.  Multiple audit_buffers can be in
 * use simultaneously. */
struct audit_buffer {
	struct sk_buff       *skb;	/* formatted skb ready to send */
	struct audit_context *ctx;	/* NULL or associated context */
	gfp_t		     gfp_mask;
};
```

```c
/**
 * audit_log - Log an audit record
 * @ctx: audit context
 * @gfp_mask: type of allocation
 * @type: audit message type
 * @fmt: format string to use
 * @...: variable parameters matching the format string
 *
 * This is a convenience function that calls audit_log_start,
 * audit_log_vformat, and audit_log_end.  It may be called
 * in any context.
 */
void audit_log(struct audit_context *ctx, gfp_t gfp_mask, int type,
	       const char *fmt, ...)
{
	struct audit_buffer *ab;
	va_list args;

	ab = audit_log_start(ctx, gfp_mask, type);
	if (ab) {
		va_start(args, fmt);
		audit_log_vformat(ab, fmt, args);
		va_end(args);
		audit_log_end(ab);
	}
}
```

 - 로그를 만들기위한 버퍼를 사용하는 루틴을 확인합니다.

---

### 2.2. **audit.log** 로그에 찍히기까지

- **struct audit_context** 를 가지고 **struct audit_buffer** 인스턴스를 만들어줍니다.

```c
/**
 * audit_log_start - obtain an audit buffer
 * @ctx: audit_context (may be NULL)
 * @gfp_mask: type of allocation
 * @type: audit message type
 *
 * Returns audit_buffer pointer on success or NULL on error.
 *
 * Obtain an audit buffer.  This routine does locking to obtain the
 * audit buffer, but then no locking is required for calls to
 * audit_log_*format.  If the task (ctx) is a task that is currently in a
 * syscall, then the syscall is marked as auditable and an audit record
 * will be written at syscall exit.  If there is no associated task, then
 * task context (ctx) should be NULL.
 */
struct audit_buffer *audit_log_start(struct audit_context *ctx, gfp_t gfp_mask,
				     int type)
{
	struct audit_buffer *ab;
	struct timespec64 t;
	unsigned int serial;

	if (audit_initialized != AUDIT_INITIALIZED)
		return NULL;

	if (unlikely(!audit_filter(type, AUDIT_FILTER_EXCLUDE)))
		return NULL;

	/* NOTE: don't ever fail/sleep on these two conditions:
	 * 1. auditd generated record - since we need auditd to drain the
	 *    queue; also, when we are checking for auditd, compare PIDs using
	 *    task_tgid_vnr() since auditd_pid is set in audit_receive_msg()
	 *    using a PID anchored in the caller's namespace
	 * 2. generator holding the audit_cmd_mutex - we don't want to block
	 *    while holding the mutex, although we do penalize the sender
	 *    later in audit_receive() when it is safe to block
	 */
	if (!(auditd_test_task(current) || audit_ctl_owner_current())) {
		long stime = audit_backlog_wait_time;

		while (audit_backlog_limit &&
		       (skb_queue_len(&audit_queue) > audit_backlog_limit)) {
			/* wake kauditd to try and flush the queue */
			wake_up_interruptible(&kauditd_wait);

			/* sleep if we are allowed and we haven't exhausted our
			 * backlog wait limit */
			if (gfpflags_allow_blocking(gfp_mask) && (stime > 0)) {
				long rtime = stime;

				DECLARE_WAITQUEUE(wait, current);

				add_wait_queue_exclusive(&audit_backlog_wait,
							 &wait);
				set_current_state(TASK_UNINTERRUPTIBLE);
				stime = schedule_timeout(rtime);
				atomic_add(rtime - stime, &audit_backlog_wait_time_actual);
				remove_wait_queue(&audit_backlog_wait, &wait);
			} else {
				if (audit_rate_check() && printk_ratelimit())
					pr_warn("audit_backlog=%d > audit_backlog_limit=%d\n",
						skb_queue_len(&audit_queue),
						audit_backlog_limit);
				audit_log_lost("backlog limit exceeded");
				return NULL;
			}
		}
	}

	ab = audit_buffer_alloc(ctx, gfp_mask, type);
	if (!ab) {
		audit_log_lost("out of memory in audit_log_start");
		return NULL;
	}

	audit_get_stamp(ab->ctx, &t, &serial);
	/* cancel dummy context to enable supporting records */
	if (ctx)
		ctx->dummy = 0;
	audit_log_format(ab, "audit(%llu.%03lu:%u): ",
			 (unsigned long long)t.tv_sec, t.tv_nsec/1000000, serial);

	return ab;
}
```

 - **Hook 의 ctx -> audit_context -> audit_buffer**

---

### 2.2. **audit.log** 로그에 찍히기까지

- **struct audit_buffer** 를 가지고 넷링크 통신을 위한 sk_buff 를 만들고, audit_queue 테일에 큐잉합니다.

```c
/**
 * audit_log_end - end one audit record
 * @ab: the audit_buffer
 *
 * We can not do a netlink send inside an irq context because it blocks (last
 * arg, flags, is not set to MSG_DONTWAIT), so the audit buffer is placed on a
 * queue and a kthread is scheduled to remove them from the queue outside the
 * irq context.  May be called in any context.
 */
void audit_log_end(struct audit_buffer *ab)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;

	if (!ab)
		return;

	if (audit_rate_check()) {
		skb = ab->skb;
		ab->skb = NULL;

		/* setup the netlink header, see the comments in
		 * kauditd_send_multicast_skb() for length quirks */
		nlh = nlmsg_hdr(skb);
		nlh->nlmsg_len = skb->len - NLMSG_HDRLEN;

		/* queue the netlink packet and poke the kauditd thread */
		skb_queue_tail(&audit_queue, skb);
		wake_up_interruptible(&kauditd_wait);
	} else
		audit_log_lost("rate limit exceeded");

	audit_buffer_free(ab);
}
```

- queue the netlink packet and poke the kauditd thread

---

### 2.2. **audit.log** 로그에 찍히기까지

- kthread 에서는 irq context 밖에서 audit_queue 처리가 가능합니다!
  - audit buffer 는 audit_queue 에 들어가구요.
  - 프로세스 컨텍스트에서 처리해서 핸들링이 쉬워지죠!

```c
/**
 * kauditd_thread - Worker thread to send audit records to userspace
 * @dummy: unused
 */
static int kauditd_thread(void *dummy)
{
	int rc;
	u32 portid = 0;
	struct net *net = NULL;
	struct sock *sk = NULL;
	struct auditd_connection *ac;

#define UNICAST_RETRIES 5

	set_freezable();
	while (!kthread_should_stop()) {
		/* NOTE: see the lock comments in auditd_send_unicast_skb() */
		rcu_read_lock();
		ac = rcu_dereference(auditd_conn);
		if (!ac) {
			rcu_read_unlock();
			goto main_queue;
		}
		net = get_net(ac->net);
		sk = audit_get_sk(net);
		portid = ac->portid;
		rcu_read_unlock();

		/* attempt to flush the hold queue */
		rc = kauditd_send_queue(sk, portid,
					&audit_hold_queue, UNICAST_RETRIES,
					NULL, kauditd_rehold_skb);
		if (rc < 0) {
			sk = NULL;
			auditd_reset(ac);
			goto main_queue;
		}

		/* attempt to flush the retry queue */
		rc = kauditd_send_queue(sk, portid,
					&audit_retry_queue, UNICAST_RETRIES,
					NULL, kauditd_hold_skb);
		if (rc < 0) {
			sk = NULL;
			auditd_reset(ac);
			goto main_queue;
		}

main_queue:
		/* process the main queue - do the multicast send and attempt
		 * unicast, dump failed record sends to the retry queue; if
		 * sk == NULL due to previous failures we will just do the
		 * multicast send and move the record to the hold queue */
		rc = kauditd_send_queue(sk, portid, &audit_queue, 1,
					kauditd_send_multicast_skb,
					(sk ?
					 kauditd_retry_skb : kauditd_hold_skb));
		if (ac && rc < 0)
			auditd_reset(ac);
		sk = NULL;

		/* drop our netns reference, no auditd sends past this line */
		if (net) {
			put_net(net);
			net = NULL;
		}

		/* we have processed all the queues so wake everyone */
		wake_up(&audit_backlog_wait);

		/* NOTE: we want to wake up if there is anything on the queue,
		 *       regardless of if an auditd is connected, as we need to
		 *       do the multicast send and rotate records from the
		 *       main queue to the retry/hold queues */
		wait_event_freezable(kauditd_wait,
				     (skb_queue_len(&audit_queue) ? 1 : 0));
	}

	return 0;
}
```

- netlink 기반 logger 구현 한다면 참고할 수 있는 좋은 코드네요!

---

### 2.2. **audit.log** 로그에 찍히기까지

- **kauditd_thread()** 내부에서 보았던, 유저 스페이스로 netlink 소켓으로 패킷을 전달하는 부분입니다!

```c
/**
 * kauditd_send_queue - Helper for kauditd_thread to flush skb queues
 * @sk: the sending sock
 * @portid: the netlink destination
 * @queue: the skb queue to process
 * @retry_limit: limit on number of netlink unicast failures
 * @skb_hook: per-skb hook for additional processing
 * @err_hook: hook called if the skb fails the netlink unicast send
 *
 * Description:
 * Run through the given queue and attempt to send the audit records to auditd,
 * returns zero on success, negative values on failure.  It is up to the caller
 * to ensure that the @sk is valid for the duration of this function.
 *
 */
static int kauditd_send_queue(struct sock *sk, u32 portid,
			      struct sk_buff_head *queue,
			      unsigned int retry_limit,
			      void (*skb_hook)(struct sk_buff *skb),
			      void (*err_hook)(struct sk_buff *skb, int error))
{
	int rc = 0;
	struct sk_buff *skb = NULL;
	struct sk_buff *skb_tail;
	unsigned int failed = 0;

	/* NOTE: kauditd_thread takes care of all our locking, we just use
	 *       the netlink info passed to us (e.g. sk and portid) */

	skb_tail = skb_peek_tail(queue);
	while ((skb != skb_tail) && (skb = skb_dequeue(queue))) {
		/* call the skb_hook for each skb we touch */
		if (skb_hook)
			(*skb_hook)(skb);

		/* can we send to anyone via unicast? */
		if (!sk) {
			if (err_hook)
				(*err_hook)(skb, -ECONNREFUSED);
			continue;
		}

retry:
		/* grab an extra skb reference in case of error */
		skb_get(skb);
		rc = netlink_unicast(sk, skb, portid, 0);
		if (rc < 0) {
			/* send failed - try a few times unless fatal error */
			if (++failed >= retry_limit ||
			    rc == -ECONNREFUSED || rc == -EPERM) {
				sk = NULL;
				if (err_hook)
					(*err_hook)(skb, rc);
				if (rc == -EAGAIN)
					rc = 0;
				/* continue to drain the queue */
				continue;
			} else
				goto retry;
		} else {
			/* skb sent - drop the extra reference and continue */
			consume_skb(skb);
			failed = 0;
		}
	}

	return (rc >= 0 ? 0 : rc);
}
```

- 큐잉한 audit_queue 에서 skb 를 get 하고, 이를 netlink 로 전달합니다.

---

### 2.2. **audit.log** 로그에 찍히기까지

- **struct audit_context** 멤버를 슬쩍 볼까요! 자세한 설명은 생략!

```c
/* The per-task audit context. */
struct audit_context {
	int		    dummy;	/* must be the first element */
	enum {
		AUDIT_CTX_UNUSED,	/* audit_context is currently unused */
		AUDIT_CTX_SYSCALL,	/* in use by syscall */
		AUDIT_CTX_URING,	/* in use by io_uring */
	} context;
	enum audit_state    state, current_state;
	unsigned int	    serial;     /* serial number for record */
	int		    major;      /* syscall number */
	int		    uring_op;   /* uring operation */
	struct timespec64   ctime;      /* time of syscall entry */
	unsigned long	    argv[4];    /* syscall arguments */
	long		    return_code;/* syscall return code */
	u64		    prio;
	int		    return_valid; /* return code is valid */
	/*
	 * The names_list is the list of all audit_names collected during this
	 * syscall.  The first AUDIT_NAMES entries in the names_list will
	 * actually be from the preallocated_names array for performance
	 * reasons.  Except during allocation they should never be referenced
	 * through the preallocated_names array and should only be found/used
	 * by running the names_list.
	 */
	struct audit_names  preallocated_names[AUDIT_NAMES];
	int		    name_count; /* total records in names_list */
	struct list_head    names_list;	/* struct audit_names->list anchor */
	char		    *filterkey;	/* key for rule that triggered record */
	struct path	    pwd;
	struct audit_aux_data *aux;
	struct audit_aux_data *aux_pids;
	struct sockaddr_storage *sockaddr;
	size_t sockaddr_len;
				/* Save things to print about task_struct */
	pid_t		    pid, ppid;
	kuid_t		    uid, euid, suid, fsuid;
	kgid_t		    gid, egid, sgid, fsgid;
	unsigned long	    personality;
	int		    arch;

	pid_t		    target_pid;
	kuid_t		    target_auid;
	kuid_t		    target_uid;
	unsigned int	    target_sessionid;
	u32		    target_sid;
	char		    target_comm[TASK_COMM_LEN];

	struct audit_tree_refs *trees, *first_trees;
	struct list_head killed_trees;
	int tree_count;

	int type;
	union {
		struct {
			int nargs;
			long args[6];
		} socketcall;
		struct {
			kuid_t			uid;
			kgid_t			gid;
			umode_t			mode;
			u32			osid;
			int			has_perm;
			uid_t			perm_uid;
			gid_t			perm_gid;
			umode_t			perm_mode;
			unsigned long		qbytes;
		} ipc;
		struct {
			mqd_t			mqdes;
			struct mq_attr		mqstat;
		} mq_getsetattr;
		struct {
			mqd_t			mqdes;
			int			sigev_signo;
		} mq_notify;
		struct {
			mqd_t			mqdes;
			size_t			msg_len;
			unsigned int		msg_prio;
			struct timespec64	abs_timeout;
		} mq_sendrecv;
		struct {
			int			oflag;
			umode_t			mode;
			struct mq_attr		attr;
		} mq_open;
		struct {
			pid_t			pid;
			struct audit_cap_data	cap;
		} capset;
		struct {
			int			fd;
			int			flags;
		} mmap;
		struct open_how openat2;
		struct {
			int			argc;
		} execve;
		struct {
			char			*name;
		} module;
		struct {
			struct audit_ntp_data	ntp_data;
			struct timespec64	tk_injoffset;
		} time;
	};
	int fds[2];
	struct audit_proctitle proctitle;
};
```

- The per-task audit context.

```c
static inline void audit_set_context(struct task_struct *task, struct audit_context *ctx)
{
	task->audit_context = ctx;
}

static inline struct audit_context *audit_context(void)
{
	return current->audit_context;
}
```

-- task_struct 에 audit_context 멤버가 있습니다.

---

### 2.3. audit rule 을 어떻게 로드할까?

- 유저 스페이스 : auditd

```c
int audit_add_rule_data(int fd, struct audit_rule_data *rule,
                        int flags, int action)
{
	int rc;

	rule->flags  = flags;
	rule->action = action;
	rc = audit_send(fd, AUDIT_ADD_RULE, rule,
			sizeof(struct audit_rule_data) + rule->buflen);
```

---

### 2.3. audit rule 을 어떻게 로드할까?

- 커널 스페이스 : kaduditd

```c
/**
 * audit_receive - receive messages from a netlink control socket
 * @skb: the message buffer
 *
 * Parse the provided skb and deal with any messages that may be present,
 * malformed skbs are discarded.
 */
static void audit_receive(struct sk_buff  *skb)
{
	struct nlmsghdr *nlh;
	/*
	 * len MUST be signed for nlmsg_next to be able to dec it below 0
	 * if the nlmsg_len was not aligned
	 */
	int len;
	int err;

	nlh = nlmsg_hdr(skb);
	len = skb->len;

	audit_ctl_lock();
	while (nlmsg_ok(nlh, len)) {
		err = audit_receive_msg(skb, nlh);
```

- 룰은 위의 로직을 통해서 유저에서 커널로 올라옴을 확인합니다!