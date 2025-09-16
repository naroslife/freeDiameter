#ifndef _PROCESS_MAA_H
#define _PROCESS_MAA_H

void cbMarResponseHandler(void * data, struct msg ** msg);
int sendMultimediaAuthRequest(struct msg *der, char* imsi);

#endif /* _PROCESS_MAA_H */
