/* Copyright (c) 2009 Open Information Security Foundation */

#ifndef __CONF_YAML_LOADER_H__
#define __CONF_YAML_LOADER_H__

void ConfYamlLoadFile(const char *);
void ConfYamlLoadString(const char *, size_t);
void ConfYamlRegisterTests(void);

#endif /* !__CONF_YAML_LOADER_H__ */
