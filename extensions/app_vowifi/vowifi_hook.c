#include <freeDiameter/extension.h>
#include "vowifi_hook.h"


void vowifi_hook_message_sent(enum fd_hook_type type, struct msg * msg, struct peer_hdr * peer, void * other, struct fd_hook_permsgdata *pmd, void * regdata) {
    LOG_N("=== Message sent ===");
}

void vowifi_hook_message_received(enum fd_hook_type type, struct msg * msg, struct peer_hdr * peer, void * other, struct fd_hook_permsgdata *pmd, void * regdata) {
    LOG_N("=== Message sent ===");
}

void vowifi_hook_clear_session(struct sess_state *state, os0_t sid, void *opaque) {
    LOG_N("++++ CLEANING SESSION +++++: %s\n", sid);
}