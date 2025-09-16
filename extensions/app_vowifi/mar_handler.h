#ifndef _MAR_HANDLER_H
#define _MAR_HANDLER_H

int vowifi_handle_mar(struct msg **msg, struct avp *avp, 
                                   struct session* sess, void *opaque, 
                                   enum disp_action *act);

#endif /* _MAR_HANDLER_H */