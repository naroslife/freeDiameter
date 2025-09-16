#ifndef _PROCESS_SAA_H
#define _PROCESS_SAA_H

#define SAT_REGISTRATION 1
#define SAT_USER_DEREGISTRATION 5

void cbSarResponseHandler(void * data, struct msg ** msg);
int sendServerAssignmentRequest(struct msg **msg, char* imsi, int sat);

#endif /* _PROCESS_SAA_H */
