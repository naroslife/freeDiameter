#ifndef __SAR_HANDLER_H__
#define __SAR_HANDLER_H__

int vowifi_handle_sar(struct msg **msg, struct avp *avp, 
                                   struct session* sess, void *opaque, 
                                   enum disp_action *act);

#endif /* _SAR_HANDLER_H__*/