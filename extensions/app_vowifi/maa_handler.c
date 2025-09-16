#include <freeDiameter/extension.h>
#include "vowifi.h"
#include "maa_handler.h"
#include "log_utils.h"
#include "utils.h"
#include <stdbool.h>

int vowifi_handle_maa(struct msg **msg, struct avp *avp, 
                                   struct session* sess, void *opaque, 
                                   enum disp_action *act) {
                                    
    *act = DISP_ACT_CONT;
    return 0;                                    
}