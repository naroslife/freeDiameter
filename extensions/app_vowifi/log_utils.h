#ifndef _LOG_UTILS_H
#define _LOG_UTILS_H

#include "der_handler.h"

int createDerSessionLog(struct msg *der, VowifiLdapRestResponse* response);

int logRejectedSession(const char* sessionId, const char* imsi, struct msg* der);

#endif /* _LOG_UTILS_H */