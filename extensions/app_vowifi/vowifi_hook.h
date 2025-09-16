#ifndef __VOWIFI_HOOK_H__
#define __VOWIFI_HOOK_H__

#include <freeDiameter/extension.h> 

void vowifi_hook_message_sent(enum fd_hook_type type, struct msg * msg, struct peer_hdr * peer, void * other, struct fd_hook_permsgdata *pmd, void * regdata);
void vowifi_hook_message_received(enum fd_hook_type type, struct msg * msg, struct peer_hdr * peer, void * other, struct fd_hook_permsgdata *pmd, void * regdata);

void vowifi_hook_clear_session(struct sess_state *state, os0_t sid, void *opaque);

#endif /* __VOWIFI_HOOK_H__ */