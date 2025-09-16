#ifndef _UTILS_H
#define _UTILS_H

#include <freeDiameter/extension.h>

int vowifi_substring(const char* src, int startPosition, char until, char** dest);

// dest dinamikusan foglalva, src felszabaditva
int vowifi_ltrim_zeros(char* src, char** dest);

int getStringFromMsg(struct msg *msg, char** strAddr, int avpCode);
int getSessionIdFromMsg(struct msg *msg, char** sessionId);

int register_handler(int applicationId, int commandCode, int avpCode, int cmdCriteria,
                     int (*cb)( struct msg **, struct avp *, struct session *, void *, enum disp_action *),
                    struct disp_hdl ** handle, int auth, int acct);

int createMessageBase(int applicationId, int commandCode, struct msg ** msg);

int addAvpFromMessage(struct msg * srcMsg, struct msg * destMsg, struct dict_object * avp, int avpCode);
int addAvpFromMessageByAvpCode(struct msg * srcMsg, struct msg * destMsg, int avpCode);
int addAvpFromMessageByAvpCodeArray(struct msg * srcMsg, struct msg * destMsg, int avpCodes[], int count);

int addAvp(struct msg * msg, struct dict_object * avp, union avp_value * val);
int addAvpByAvpCode(struct msg * msg, int avpCode, union avp_value * val);

int addAvpInt32(struct msg * msg, struct dict_object * avp, int32_t val);
int addAvpInt32ByAvpCode(struct msg * msg, int avpCode, int32_t val);
int addAvpStr(struct msg * msg, struct dict_object * avp, uint8_t* val);
int addAvpStrByAvpCode(struct msg * msg, int avpCode, uint8_t* val);
int addAvpBytes(struct msg * msg, struct dict_object * avp, uint8_t* val, size_t len);
int addAvpBytesByAvpCode(struct msg * msg, int avpCode, uint8_t* val, size_t len);

int addExperimentalResultCode(struct msg * msg, uint32_t vendorId, uint32_t avpCode, uint32_t resultCode);
int addVendorSpecificApplicationId(struct msg * msg, uint32_t vendorId, uint32_t appId);



// AVP, COMMAND, APP, VENDOR
int getDictObjectByName(const char* name, enum dict_object_type type, struct dict_object ** obj);

int getAvpFromMessage(struct msg * srcMsg, int avpCode, struct avp ** destAvp);
int getAvpChildFromMessage(struct msg * srcMsg, int parentAvpCode, int avpCode, struct avp ** destAvp);
int getResultCodeFromMessage(struct msg * msg, uint32_t * resultCode);
int getIntValueFromMessage(struct msg * msg, int avpCode, uint32_t * intValue);
int getChildIntValueFromMessage(struct msg * msg, int parentAvpCode, int avpCode, uint32_t * intValue);

int getBytesFromAvp(struct avp * avp, uint8_t** val);
int getBytesFromAvpWithLength(struct avp * avp, uint8_t **bytes, size_t *length);
int getBytesFromMessageByAvpCode(struct msg * msg, int avpCode, uint8_t** val);
int getBytesFromMessageWithLengthByAvpCode(struct msg * msg, int avpCode, uint8_t **val, size_t *length);

int allocAndInitState(struct sess_state **state);
int createNewSession(struct msg * msg, struct session ** sess);
// ujat keszit, ha meg nincs
int getOrCreateSessionState(struct msg *msg, struct session ** session, struct sess_state **state);
int storeState(struct session * sess, struct sess_state * state);
int retrieveState(struct session * sess, struct sess_state ** state);

int debugPrintMsg(struct msg * msg);


#endif /* _UTILS_H */