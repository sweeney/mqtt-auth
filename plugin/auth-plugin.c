/*
 * mqtt-auth: C-side glue between mosquitto's plugin API v4 and our Go runtime.
 *
 * The Go side does the real work; this file does three things only:
 *   1. Tells mosquitto we implement plugin API v4 (works on 2.0.x).
 *   2. On plugin init, flattens the struct mosquitto_opt array into parallel
 *      key/value C string arrays and hands them to AuthPluginInit.
 *   3. Forwards mosquitto_auth_unpwd_check / mosquitto_auth_acl_check into
 *      the Go side and translates the return code.
 *
 * Mosquitto 2.0.x exposes both the legacy v2 plugin API (mosquitto_auth_*)
 * and a newer event-based v5 API. Per the header (MOSQ_AUTH_PLUGIN_VERSION
 * == 4 at the time of writing), v4 is the supported way to keep using
 * function-pointer style entrypoints; we return that.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

#include "_cgo_export.h"

int mosquitto_auth_plugin_version(void) {
    return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *opts, int opt_count) {
    (void)user_data;

    if (opt_count < 0) {
        return MOSQ_ERR_INVAL;
    }

    char **keys = NULL;
    char **values = NULL;
    if (opt_count > 0) {
        keys = (char **)malloc(sizeof(char *) * (size_t)opt_count);
        values = (char **)malloc(sizeof(char *) * (size_t)opt_count);
        if (keys == NULL || values == NULL) {
            free(keys);
            free(values);
            return MOSQ_ERR_NOMEM;
        }
        for (int i = 0; i < opt_count; i++) {
            keys[i] = opts[i].key;
            values[i] = opts[i].value;
        }
    }

    int rc = (int)AuthPluginInit(keys, values, (int)opt_count);

    free(keys);
    free(values);
    return rc;
}

int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count) {
    (void)user_data;
    (void)opts;
    (void)opt_count;
    AuthPluginCleanup();
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload) {
    (void)user_data;
    (void)opts;
    (void)opt_count;
    (void)reload;
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload) {
    (void)user_data;
    (void)opts;
    (void)opt_count;
    (void)reload;
    return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client, const char *username, const char *password) {
    (void)user_data;
    (void)client;
    return (int)AuthUnpwdCheck((char *)username, (char *)password);
}

int mosquitto_auth_acl_check(void *user_data, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg) {
    (void)user_data;
    (void)client;
    const char *username = mosquitto_client_username(client);
    const char *topic = (msg != NULL) ? msg->topic : NULL;
    return (int)AuthAclCheck((char *)username, (char *)topic, access);
}
