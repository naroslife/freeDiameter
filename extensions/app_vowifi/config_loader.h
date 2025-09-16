#ifndef CONFIG_LOADER_H
#define CONFIG_LOADER_H

#include "vowifi.h"

#ifdef __cplusplus
extern "C" {
#endif

// External declaration of the global config
extern VOWIFI_CONFIG vowifiConfig;

int loadConfigFromFile(char* conffile);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_LOADER_H */
