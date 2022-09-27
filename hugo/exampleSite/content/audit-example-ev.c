#include <stdio.h>
#include <unistd.h>

#include <libaudit.h>

#include <ev.h>

/**
 * @brief How to use libaudit?
 *  (1) https://stackoverflow.com/questions/56252499/how-to-use-libaudit
 *  (2) https://stackoverflow.com/questions/57534297/how-to-use-audit-in-linux-to-monitor-a-file-using-libaudit
 * 
 * @brief libev
 * 
 *  ref:
 *    man : https://linux.die.net/man/3/ev
 *    libev: http://software.schmorp.de/pkg/libev.html
 *    
 * 
 *  src:
 *    https://git.launchpad.net/ubuntu/+source/libev?h=ubuntu%2Fjammy
 */

int fd;

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