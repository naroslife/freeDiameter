#ifndef _MAA_HANDLER_H
#define _MAA_HANDLER_H

int vowifi_handle_maa(struct msg **msg, struct avp *avp, 
                                   struct session* sess, void *opaque, 
                                   enum disp_action *act);

#endif /* _MAA_HANDLER_H */
