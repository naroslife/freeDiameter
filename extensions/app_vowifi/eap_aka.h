#ifndef __EAP_AKA_H
#define __EAP_AKA_H

#include <freeDiameter/extension.h>

int generateEapAkaChallenge(const char* identity, const char* randHex, const char* autnHex,
                          const char* ckHex, const char* ikHex,
                          unsigned char** out, size_t* outLen);

int verifyEapAkaResponse(struct sess_state* state);
                         
int generateAtRandAtAutn(char **atRand, char **atAutn);

#endif /* __EAP_AKA_H */