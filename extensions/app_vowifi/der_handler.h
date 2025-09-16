#ifndef _DER_HANDLER_H
#define _DER_HANDLER_H

#include "vowifi.h"

int createDeaFromDer(struct msg *der, struct msg **dea, char* result_message);

int vowifi_handle_der(struct msg **msg, struct avp *avp, 
                                   struct session* sess, void *opaque, 
                                   enum disp_action *act);

int fillSessionStateEapPayload(struct sess_state *state, uint8_t* derEapPayload, size_t len);

#endif /* _DER_HANDLER_H */
