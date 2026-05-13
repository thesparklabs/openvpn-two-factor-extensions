/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2016-2026 Selva Nair <selva.nair@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/*
 * OpenVPN plugin module to do PAM and U2F two-factor authentication
 * using a split privilege model.
 *
 * Modifications made by SparkLabs Pty Ltd.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <security/pam_appl.h>

#ifdef USE_PAM_DLOPEN
#include "pamdl.h"
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <limits.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <time.h>
#include <dlfcn.h>
#include "utils.h"
#include <arpa/inet.h>
#include <openvpn-plugin.h>

#define DEBUG(verb) ((verb) >= 4)

#define INTERPRETER "python3"
#define U2F_SCRIPT_PATH "/usr/share/openvpn/pam-u2f/auth-pam-u2f.py"
#define U2F_HELPER_TIMEOUT_MS 10000
#define U2F_CLIENT_REASON_SIZE 4096
#define OPENVPN_USER_PASS_SIZE 4096
#define OPENVPN_COMMON_NAME_SIZE 128
#define OPENVPN_REMOTE_SIZE INET6_ADDRSTRLEN
#define U2F_SCRIPT_PATH_SIZE PATH_MAX
#define U2F_HELPER_ENV_COUNT 5
#define U2F_HELPER_ENV_VALUE_SIZE 4096

/* Command codes for foreground -> background communication */
#define COMMAND_VERIFY 0
#define COMMAND_EXIT   1

/* Response codes for background -> foreground communication */
#define RESPONSE_INIT_SUCCEEDED   10
#define RESPONSE_INIT_FAILED      11
#define RESPONSE_VERIFY_SUCCEEDED 12
#define RESPONSE_VERIFY_FAILED    13
#define RESPONSE_DEFER            14
#define RESPONSE_VERIFY_FAILED_WITH_REASON 15

/* Pointers to functions exported from openvpn */
static plugin_log_t plugin_log = NULL;
static plugin_secure_memzero_t plugin_secure_memzero = NULL;
static plugin_base64_decode_t plugin_base64_decode = NULL;

/* module name for plugin_log() */
static char *MODULE = "AUTH-PAM-U2F";

static const char *helper_env_names[U2F_HELPER_ENV_COUNT] = {
    "OPENVPN_FIDO_DB_PATH",
    "OPENVPN_FIDO_APP_ID",
    "OPENVPN_FIDO_VALID_FACETS",
    "OPENVPN_FIDO_TRANSACTION_TTL_SECONDS",
    "OPENVPN_FIDO_MAX_TRANSACTIONS",
};

/*
 * Plugin state, used by foreground
 */
struct auth_pam_context
{
    /* Foreground's socket to background process */
    int foreground_fd;

    /* Process ID of background process */
    pid_t background_pid;

    /* Verbosity level of OpenVPN */
    int verb;
};

/*
 * Name/Value pairs for conversation function.
 * Special Values:
 *
 *  "USERNAME" -- substitute client-supplied username
 *  "PASSWORD" -- substitute client-specified password
 *  "COMMONNAME" -- substitute client certificate common name
 *  "OTP" -- substitute static challenge response if available
 */

#define N_NAME_VALUE 16

struct name_value
{
    const char *name;
    const char *value;
};

struct name_value_list
{
    int len;
    struct name_value data[N_NAME_VALUE];
};

/*
 * Used to pass the username/password
 * to the PAM conversation function.
 */
struct user_pass
{
    int verb;

    char username[OPENVPN_USER_PASS_SIZE];
    char password[OPENVPN_USER_PASS_SIZE];
    char common_name[OPENVPN_COMMON_NAME_SIZE];
    char response[OPENVPN_USER_PASS_SIZE];
    char remote[OPENVPN_REMOTE_SIZE];
    char script_path[U2F_SCRIPT_PATH_SIZE];
    char helper_env[U2F_HELPER_ENV_COUNT][U2F_HELPER_ENV_VALUE_SIZE];

    const struct name_value_list *name_value_list;
};

/* Background process function */
static void pam_server(int fd, const char *service, int verb,
                       const struct name_value_list *name_value_list);
static int u2f_auth_verify(const struct user_pass *up, const char *password,
                           char *client_reason, size_t client_reason_len);
static void terminate_child(pid_t pid);


/*
 * Socket read/write functions.
 */

static int
recv_control(int fd)
{
    unsigned char c;
    ssize_t size;

    do
    {
        size = read(fd, &c, sizeof(c));
    }
    while (size == -1 && errno == EINTR);

    if (size == sizeof(c))
    {
        return c;
    }
    else
    {
        if (size == 0)
        {
            errno = EPIPE;
        }
        /*fprintf (stderr, "AUTH-PAM: DEBUG recv_control.read=%d\n", (int)size);*/
        return -1;
    }
}

static int
send_control(int fd, int code)
{
    unsigned char c = (unsigned char)code;
    ssize_t size;

    do
    {
        size = write(fd, &c, sizeof(c));
    }
    while (size == -1 && errno == EINTR);

    if (size == sizeof(c))
    {
        return (int)size;
    }
    else
    {
        return -1;
    }
}

static ssize_t
recv_string(int fd, char *buffer, size_t len)
{
    if (len == 0)
    {
        errno = EINVAL;
        return -1;
    }

    memset(buffer, 0, len);

    struct iovec iov = {
        .iov_base = buffer,
        .iov_len = len,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    ssize_t size;
    do
    {
        size = recvmsg(fd, &msg, 0);
    }
    while (size == -1 && errno == EINTR);

    if (size < 1)
    {
        if (size == 0)
        {
            errno = EPIPE;
        }
        return -1;
    }

    if (msg.msg_flags & MSG_TRUNC)
    {
        errno = EMSGSIZE;
        return -1;
    }

    if (buffer[size - 1] != '\0')
    {
        errno = EINVAL;
        return -1;
    }

    return size;
}

static ssize_t
send_string(int fd, const char *string)
{
    const size_t len = strlen(string) + 1;
    ssize_t size;

    do
    {
        size = write(fd, string, len);
    }
    while (size == -1 && errno == EINTR);

    if (size >= 0 && (size_t)size == len)
    {
        return size;
    }
    else
    {
        return -1;
    }
}

static int
check_string_limited(const char *string, size_t max_size, const char *label)
{
    if (!string || max_size == 0)
    {
        errno = EINVAL;
        return -1;
    }

    if (strnlen(string, max_size) >= max_size)
    {
        plugin_log(PLOG_ERR, MODULE, "%s exceeds maximum size %zu", label,
                   max_size - 1);
        errno = EMSGSIZE;
        return -1;
    }

    return 0;
}

static int
check_helper_env_limited(const char *values[])
{
    for (int i = 0; i < U2F_HELPER_ENV_COUNT; ++i)
    {
        if (check_string_limited(values[i], U2F_HELPER_ENV_VALUE_SIZE,
                                 helper_env_names[i]) == -1)
        {
            return -1;
        }
    }

    return 0;
}

static int
send_helper_env(int fd, const char *values[])
{
    for (int i = 0; i < U2F_HELPER_ENV_COUNT; ++i)
    {
        if (send_string(fd, values[i]) == -1)
        {
            return -1;
        }
    }

    return 0;
}

static int
recv_helper_env(int fd, struct user_pass *up)
{
    for (int i = 0; i < U2F_HELPER_ENV_COUNT; ++i)
    {
        if (recv_string(fd, up->helper_env[i], sizeof(up->helper_env[i])) == -1)
        {
            return -1;
        }
    }

    return 0;
}

static int
set_helper_env(const struct user_pass *up)
{
    for (int i = 0; i < U2F_HELPER_ENV_COUNT; ++i)
    {
        if (up->helper_env[i][0] != '\0'
            && setenv(helper_env_names[i], up->helper_env[i], 1) == -1)
        {
            return -1;
        }
    }

    return 0;
}

#ifdef DO_DAEMONIZE

/*
 * Daemonize if "daemon" env var is true.
 * Preserve stderr across daemonization if
 * "daemon_log_redirect" env var is true.
 */
static void
daemonize(const char *envp[])
{
    const char *daemon_string = get_env("daemon", envp);
    if (daemon_string && daemon_string[0] == '1')
    {
        const char *log_redirect = get_env("daemon_log_redirect", envp);
        int fd = -1;
        if (log_redirect && log_redirect[0] == '1')
        {
            fd = dup(2);
        }
        if (daemon(0, 0) < 0)
        {
            plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE, "daemonization failed");
        }
        else if (fd >= 3)
        {
            dup2(fd, 2);
            close(fd);
        }
    }
}

#endif /* ifdef DO_DAEMONIZE */

/*
 * Close most of parent's fds.
 * Keep stdin/stdout/stderr, plus one
 * other fd which is presumed to be
 * our pipe back to parent.
 * Admittedly, a bit of a kludge,
 * but posix doesn't give us a kind
 * of FD_CLOEXEC which will stop
 * fds from crossing a fork().
 */
static void
close_fds_except(int keep)
{
    int i;
    closelog();
    for (i = 3; i <= 100; ++i)
    {
        if (i != keep)
        {
            close(i);
        }
    }
}

/*
 * Usually we ignore signals, because our parent will
 * deal with them.
 */
static void
set_signals(void)
{
    signal(SIGTERM, SIG_DFL);

    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
}

/*
 * Return 1 if query matches match.
 */
static int
name_value_match(const char *query, const char *match)
{
    while (!isalnum(*query))
    {
        if (*query == '\0')
        {
            return 0;
        }
        ++query;
    }
    return strncasecmp(match, query, strlen(match)) == 0;
}

/*
 * Split and decode up->password in the form SCRV1:base64_pass:base64_response
 * into pass and response and save in up->password and up->response.
 * If the password is not in the expected format, input is not changed.
 */
static void
split_scrv1_password(struct user_pass *up)
{
    const int skip = strlen("SCRV1:");
    if (strncmp(up->password, "SCRV1:", skip) != 0)
    {
        return;
    }

    char *tmp = strdup(up->password);
    if (!tmp)
    {
        plugin_log(PLOG_ERR, MODULE, "out of memory parsing static challenge password");
        goto out;
    }

    char *pass = tmp + skip;
    char *resp = strchr(pass, ':');
    if (!resp) /* string not in SCRV1:xx:yy format */
    {
        goto out;
    }
    *resp++ = '\0';

    int n = plugin_base64_decode(pass, up->password, sizeof(up->password) - 1);
    if (n >= 0)
    {
        up->password[n] = '\0';
        n = plugin_base64_decode(resp, up->response, sizeof(up->response) - 1);
        if (n >= 0)
        {
            up->response[n] = '\0';
            if (DEBUG(up->verb))
            {
                plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: parsed static challenge password");
            }
            goto out;
        }
    }

    /* decode error: reinstate original value of up->password and return */
    plugin_secure_memzero(up->password, sizeof(up->password));
    plugin_secure_memzero(up->response, sizeof(up->response));
    strcpy(up->password, tmp); /* tmp is guaranteed to fit in up->password */

    plugin_log(PLOG_ERR, MODULE, "base64 decode error while parsing static challenge password");

out:
    if (tmp)
    {
        plugin_secure_memzero(tmp, strlen(tmp));
        free(tmp);
    }
}

OPENVPN_EXPORT int
openvpn_plugin_open_v3(const int v3structver, struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *ret)
{
    pid_t pid;
    int fd[2];

    struct auth_pam_context *context;
    struct name_value_list name_value_list;

    const int base_parms = 2;

    const char **argv = args->argv;
    const char **envp = args->envp;

    /* Check API compatibility -- struct version 5 or higher needed */
    if (v3structver < 5)
    {
        fprintf(stderr,
                "AUTH-PAM: This plugin is incompatible with the running version of OpenVPN\n");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /*
     * Allocate our context
     */
    context = (struct auth_pam_context *)calloc(1, sizeof(struct auth_pam_context));
    if (!context)
    {
        goto error;
    }
    context->foreground_fd = -1;

    /*
     * Intercept the --auth-user-pass-verify callback.
     */
    ret->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

    /* Save global pointers to functions exported from openvpn */
    plugin_log = args->callbacks->plugin_log;
    plugin_secure_memzero = args->callbacks->plugin_secure_memzero;
    plugin_base64_decode = args->callbacks->plugin_base64_decode;

    /*
     * Make sure we have two string arguments: the first is the .so name,
     * the second is the PAM service type.
     */
    if (string_array_len(argv) < base_parms)
    {
        plugin_log(PLOG_ERR, MODULE, "need PAM service parameter");
        goto error;
    }

    /*
     * See if we have optional name/value pairs to match against
     * PAM module queried fields in the conversation function.
     */
    name_value_list.len = 0;
    if (string_array_len(argv) > base_parms)
    {
        const int nv_len = string_array_len(argv) - base_parms;
        int i;

        if ((nv_len & 1) == 1 || (nv_len / 2) > N_NAME_VALUE)
        {
            plugin_log(PLOG_ERR, MODULE, "bad name/value list length");
            goto error;
        }

        name_value_list.len = nv_len / 2;
        for (i = 0; i < name_value_list.len; ++i)
        {
            const int base = base_parms + i * 2;
            name_value_list.data[i].name = argv[base];
            name_value_list.data[i].value = argv[base + 1];
        }
    }

    /*
     * Get verbosity level from environment
     */
    {
        const char *verb_string = get_env("verb", envp);
        if (verb_string)
        {
            context->verb = atoi(verb_string);
        }
    }

    /*
     * Make a socket for foreground and background processes
     * to communicate.
     */
    if (socketpair(PF_UNIX, SOCK_DGRAM, 0, fd) == -1)
    {
        plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE, "socketpair call failed");
        goto error;
    }

    /*
     * Fork off the privileged process.  It will remain privileged
     * even after the foreground process drops its privileges.
     */
    pid = fork();

    if (pid < 0)
    {
        plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE, "fork() failed");
        close(fd[0]);
        close(fd[1]);
        goto error;
    }

    if (pid > 0)
    {
        int status;

        /*
         * Foreground Process
         */

        context->background_pid = pid;

        /* close our copy of child's socket */
        close(fd[1]);

        /* don't let future subprocesses inherit child socket */
        if (fcntl(fd[0], F_SETFD, FD_CLOEXEC) < 0)
        {
            plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                       "Set FD_CLOEXEC flag on socket file descriptor failed");
        }

        /* wait for background child process to initialize */
        status = recv_control(fd[0]);
        if (status == RESPONSE_INIT_SUCCEEDED)
        {
            context->foreground_fd = fd[0];
            ret->handle = (openvpn_plugin_handle_t *)context;
            plugin_log(PLOG_NOTE, MODULE, "initialization succeeded (fg)");
            return OPENVPN_PLUGIN_FUNC_SUCCESS;
        }
        close(fd[0]);
        waitpid(pid, NULL, 0);
    }
    else
    {
        /*
         * Background Process
         */

        /* close all parent fds except our socket back to parent */
        close_fds_except(fd[1]);

        /* Ignore most signals (the parent will receive them) */
        set_signals();

#ifdef DO_DAEMONIZE
        /* Daemonize if --daemon option is set. */
        daemonize(envp);
#endif

        /* execute the event loop */
        pam_server(fd[1], argv[1], context->verb, &name_value_list);

        close(fd[1]);

        exit(0);
        return 0; /* NOTREACHED */
    }

error:
    free(context);
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

static void
free_return_list_entry(struct openvpn_plugin_string_list *entry)
{
    if (entry)
    {
        free(entry->name);
        free(entry->value);
        free(entry);
    }
}

static int
set_client_reason_return(struct openvpn_plugin_string_list **return_list,
                         const char *client_reason)
{
    if (!return_list || !client_reason)
    {
        return -1;
    }

    struct openvpn_plugin_string_list *entry = calloc(1, sizeof(*entry));
    if (!entry)
    {
        return -1;
    }

    entry->name = strdup("client_reason");
    entry->value = strdup(client_reason);
    if (!entry->name || !entry->value)
    {
        free_return_list_entry(entry);
        return -1;
    }

    entry->next = NULL;
    *return_list = entry;
    return 0;
}

static void
auth_channel_fail(struct auth_pam_context *context)
{
    if (!context)
    {
        return;
    }

    if (context->foreground_fd >= 0)
    {
        close(context->foreground_fd);
        context->foreground_fd = -1;
    }

    if (context->background_pid > 0)
    {
        terminate_child(context->background_pid);
        context->background_pid = -1;
    }
}

OPENVPN_EXPORT int
openvpn_plugin_func_v2(openvpn_plugin_handle_t handle, const int type, const char *argv[],
                       const char *envp[], void *per_client_context,
                       struct openvpn_plugin_string_list **return_list)
{
    struct auth_pam_context *context = (struct auth_pam_context *)handle;
    (void)argv;
    (void)per_client_context;

    if (type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY && context->foreground_fd >= 0)
    {
        /* get username/password from envp string array */
        const char *username = get_env("username", envp);
        const char *password = get_env("password", envp);
        const char *common_name = get_env("common_name", envp) ? get_env("common_name", envp) : "";
        const char *remote = get_env("untrusted_ip6", envp);
        const char *script_path = get_env("u2f_script_path", envp) ? get_env("u2f_script_path", envp)
                                                                   : U2F_SCRIPT_PATH;
        const char *helper_env_values[U2F_HELPER_ENV_COUNT];

        if (remote == NULL)
        {
            remote = get_env("untrusted_ip", envp);
        }

        if (remote == NULL)
        {
            remote = "";
        }

        for (int i = 0; i < U2F_HELPER_ENV_COUNT; ++i)
        {
            const char *value = get_env(helper_env_names[i], envp);
            helper_env_values[i] = value ? value : "";
        }

        /*
         * Upstream auth-pam can defer PAM authentication.  This plugin must
         * synchronously return a CRV1 client_reason after PAM succeeds, so keep
         * the U2F flow synchronous even if deferred_auth_pam is present.
         */
        if (get_env("auth_control_file", envp) != NULL
            && get_env("deferred_auth_pam", envp) != NULL
            && DEBUG(context->verb))
        {
            plugin_log(PLOG_NOTE, MODULE,
                       "deferred PAM auth requested but ignored for synchronous U2F challenge flow");
        }

        if (username && strlen(username) > 0 && password)
        {
            if (check_string_limited(username, OPENVPN_USER_PASS_SIZE, "username") == -1
                || check_string_limited(password, OPENVPN_USER_PASS_SIZE, "password") == -1
                || check_string_limited(common_name, OPENVPN_COMMON_NAME_SIZE,
                                        "common_name") == -1
                || check_string_limited(script_path, U2F_SCRIPT_PATH_SIZE,
                                        "u2f_script_path") == -1
                || check_string_limited(remote, OPENVPN_REMOTE_SIZE, "remote") == -1
                || check_helper_env_limited(helper_env_values) == -1)
            {
                plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE, "Auth info exceeded plugin limits");
            }
            else if (send_control(context->foreground_fd, COMMAND_VERIFY) == -1
                     || send_string(context->foreground_fd, username) == -1
                     || send_string(context->foreground_fd, password) == -1
                     || send_string(context->foreground_fd, common_name) == -1
                     || send_string(context->foreground_fd, script_path) == -1
                     || send_string(context->foreground_fd, remote) == -1
                     || send_helper_env(context->foreground_fd, helper_env_values) == -1)
            {
                plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                           "Error sending auth info to background process");
                auth_channel_fail(context);
            }
            else
            {
                const int status = recv_control(context->foreground_fd);
                if (status == RESPONSE_VERIFY_SUCCEEDED)
                {
                    return OPENVPN_PLUGIN_FUNC_SUCCESS;
                }
                if (status == RESPONSE_DEFER)
                {
                    if (DEBUG(context->verb))
                    {
                        plugin_log(PLOG_NOTE, MODULE, "deferred authentication");
                    }
                    return OPENVPN_PLUGIN_FUNC_DEFERRED;
                }
                if (status == -1)
                {
                    plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                               "Error receiving auth confirmation from background process");
                    auth_channel_fail(context);
                }
                else if (status == RESPONSE_VERIFY_FAILED_WITH_REASON)
                {
                    char client_reason[U2F_CLIENT_REASON_SIZE];
                    if (recv_string(context->foreground_fd, client_reason,
                                    sizeof(client_reason)) != -1)
                    {
                        if (set_client_reason_return(return_list, client_reason) == -1)
                        {
                            plugin_log(PLOG_ERR, MODULE,
                                       "Error allocating client_reason return value");
                        }
                    }
                    else
                    {
                        plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                                   "Error receiving client_reason from background process");
                        auth_channel_fail(context);
                    }
                }
                else if (status != RESPONSE_VERIFY_FAILED)
                {
                    plugin_log(PLOG_ERR, MODULE,
                               "Unexpected auth confirmation from background process: %d", status);
                    auth_channel_fail(context);
                }
            }
        }
    }
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct auth_pam_context *context = (struct auth_pam_context *)handle;
    bool exit_signaled = false;

    if (DEBUG(context->verb))
    {
        plugin_log(PLOG_NOTE, MODULE, "close");
    }

    if (context->foreground_fd >= 0)
    {
        /* tell background process to exit */
        if (send_control(context->foreground_fd, COMMAND_EXIT) == -1)
        {
            plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE, "Error signaling background process to exit");
        }
        else
        {
            exit_signaled = true;
        }

        close(context->foreground_fd);
        context->foreground_fd = -1;
    }

    if (context->background_pid > 0)
    {
        if (exit_signaled)
        {
            while (waitpid(context->background_pid, NULL, 0) == -1 && errno == EINTR)
            {
            }
        }
        else
        {
            terminate_child(context->background_pid);
        }
        context->background_pid = -1;
    }

    free(context);
}

OPENVPN_EXPORT void
openvpn_plugin_abort_v1(openvpn_plugin_handle_t handle)
{
    struct auth_pam_context *context = (struct auth_pam_context *)handle;

    /* tell background process to exit */
    if (context && context->foreground_fd >= 0)
    {
        send_control(context->foreground_fd, COMMAND_EXIT);
        close(context->foreground_fd);
        context->foreground_fd = -1;
    }
}

/*
 * PAM conversation function
 */
static int
my_conv(int num_msg, const struct pam_message **msg_array, struct pam_response **response_array,
        void *appdata_ptr)
{
    const struct user_pass *up = (const struct user_pass *)appdata_ptr;
    struct pam_response *aresp;
    int ret = PAM_SUCCESS;

    *response_array = NULL;

    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG)
    {
        return (PAM_CONV_ERR);
    }
    if ((aresp = calloc((size_t)num_msg, sizeof *aresp)) == NULL)
    {
        return (PAM_BUF_ERR);
    }

    /* loop through each PAM-module query */
    for (int i = 0; i < num_msg; ++i)
    {
        const struct pam_message *msg = msg_array[i];
        aresp[i].resp_retcode = 0;
        aresp[i].resp = NULL;

        if (DEBUG(up->verb))
        {
            plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: my_conv[%d] query='%s' style=%d", i,
                       msg->msg ? msg->msg : "NULL", msg->msg_style);
        }

        if (up->name_value_list && up->name_value_list->len > 0)
        {
            /* use name/value list match method */
            const struct name_value_list *list = up->name_value_list;

            /* loop through name/value pairs */
            int j; /* checked after loop */
            for (j = 0; j < list->len; ++j)
            {
                const char *match_name = list->data[j].name;
                const char *match_value = list->data[j].value;

                if (name_value_match(msg->msg, match_name))
                {
                    /* found name/value match */
                    aresp[i].resp = NULL;

                    if (DEBUG(up->verb))
                    {
                        plugin_log(
                            PLOG_NOTE, MODULE,
                            "BACKGROUND: name match found, query/match-string ['%s', '%s'] = '%s'",
                            msg->msg, match_name, match_value);
                    }

                    if (strstr(match_value, "USERNAME"))
                    {
                        aresp[i].resp = searchandreplace(match_value, "USERNAME", up->username);
                    }
                    else if (strstr(match_value, "PASSWORD"))
                    {
                        aresp[i].resp = searchandreplace(match_value, "PASSWORD", up->password);
                    }
                    else if (strstr(match_value, "COMMONNAME"))
                    {
                        aresp[i].resp =
                            searchandreplace(match_value, "COMMONNAME", up->common_name);
                    }
                    else if (strstr(match_value, "OTP"))
                    {
                        aresp[i].resp = searchandreplace(match_value, "OTP", up->response);
                    }
                    else
                    {
                        aresp[i].resp = strdup(match_value);
                    }

                    if (aresp[i].resp == NULL)
                    {
                        ret = PAM_CONV_ERR;
                    }
                    break;
                }
            }

            if (j == list->len)
            {
                ret = PAM_CONV_ERR;
            }
        }
        else
        {
            /* use PAM_PROMPT_ECHO_x hints */
            switch (msg->msg_style)
            {
                case PAM_PROMPT_ECHO_OFF:
                    aresp[i].resp = strdup(up->password);
                    if (aresp[i].resp == NULL)
                    {
                        ret = PAM_CONV_ERR;
                    }
                    break;

                case PAM_PROMPT_ECHO_ON:
                    aresp[i].resp = strdup(up->username);
                    if (aresp[i].resp == NULL)
                    {
                        ret = PAM_CONV_ERR;
                    }
                    break;

                case PAM_ERROR_MSG:
                case PAM_TEXT_INFO:
                    break;

                default:
                    ret = PAM_CONV_ERR;
                    break;
            }
        }
    }

    if (ret == PAM_SUCCESS)
    {
        *response_array = aresp;
    }
    else
    {
        free(aresp);
    }

    return ret;
}

/*
 * Return 1 if authenticated and 0 if failed.
 * Called once for every username/password
 * to be authenticated.
 */
static int
pam_auth(const char *service, const struct user_pass *up)
{
    struct pam_conv conv;
    pam_handle_t *pamh = NULL;
    int status = PAM_SUCCESS;
    int ret = 0;
    const int name_value_list_provided = (up->name_value_list && up->name_value_list->len > 0);

    /* Initialize PAM */
    conv.conv = my_conv;
    conv.appdata_ptr = (void *)up;
    status = pam_start(service, name_value_list_provided ? NULL : up->username, &conv, &pamh);
    if (status == PAM_SUCCESS)
    {
        /* Set PAM_RHOST environment variable */
        if (*(up->remote))
        {
            status = pam_set_item(pamh, PAM_RHOST, up->remote);
        }
        /* Call PAM to verify username/password */
        if (status == PAM_SUCCESS)
        {
            status = pam_authenticate(pamh, 0);
        }
        if (status == PAM_SUCCESS)
        {
            status = pam_acct_mgmt(pamh, 0);
        }
        if (status == PAM_SUCCESS)
        {
            ret = 1;
        }

        /* Output error message if failed */
        if (!ret)
        {
            plugin_log(PLOG_ERR, MODULE, "BACKGROUND: user '%s' failed to authenticate: %s",
                       up->username, pam_strerror(pamh, status));
        }

        /* Close PAM */
        pam_end(pamh, status);
    }

    return ret;
}

/*
 * Background process -- runs with privilege.
 */
static void
pam_server(int fd, const char *service, int verb, const struct name_value_list *name_value_list)
{
    struct user_pass up;
    int command;
#ifdef USE_PAM_DLOPEN
    static const char pam_so[] = "libpam.so";
#endif

    /*
     * Do initialization
     */
    if (DEBUG(verb))
    {
        plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: INIT service='%s'", service);
    }

#ifdef USE_PAM_DLOPEN
    /*
     * Load PAM shared object
     */
    if (!dlopen_pam(pam_so))
    {
        plugin_log(PLOG_ERR, MODULE, "BACKGROUND: could not load PAM lib %s: %s", pam_so,
                   dlerror());
        send_control(fd, RESPONSE_INIT_FAILED);
        goto done;
    }
#endif

    /*
     * Tell foreground that we initialized successfully
     */
    if (send_control(fd, RESPONSE_INIT_SUCCEEDED) == -1)
    {
        plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE, "BACKGROUND: write error on response socket [1]");
        goto done;
    }

    plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: initialization succeeded");

    /*
     * Event loop
     */
    while (1)
    {
        memset(&up, 0, sizeof(up));
        up.verb = verb;
        up.name_value_list = name_value_list;

        /* get a command from foreground process */
        command = recv_control(fd);

        if (DEBUG(verb))
        {
            plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: received command code: %d", command);
        }

        switch (command)
        {
            case COMMAND_VERIFY:
                if (recv_string(fd, up.username, sizeof(up.username)) == -1
                    || recv_string(fd, up.password, sizeof(up.password)) == -1
                    || recv_string(fd, up.common_name, sizeof(up.common_name)) == -1
                    || recv_string(fd, up.script_path, sizeof(up.script_path)) == -1
                    || recv_string(fd, up.remote, sizeof(up.remote)) == -1
                    || recv_helper_env(fd, &up) == -1)
                {
                    plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                               "BACKGROUND: read error on command channel: code=%d, exiting",
                               command);
                    goto done;
                }

                if (DEBUG(verb))
                {
#if 0
                    plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: USER/PASS: %s/%s",
                               up.username, up.password);
#else
                    plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: USER: %s", up.username);
                    plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: REMOTE: %s", up.remote);
                    plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: SCRIPT_PATH: %s", up.script_path);
#endif
                }

                /* If password is of the form SCRV1:base64:base64 split it up */
                split_scrv1_password(&up);

                if (!strncmp("CRV1::", up.password, strlen("CRV1::")))
                {
                    char client_reason[U2F_CLIENT_REASON_SIZE];
                    int u2f_resp = u2f_auth_verify(&up, up.password, client_reason,
                                                   sizeof(client_reason));

                    if (u2f_resp == 0)
                    {
                        if (send_control(fd, RESPONSE_VERIFY_SUCCEEDED) == -1)
                        {
                            plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                                       "BACKGROUND: write error on response socket [2]");
                            goto done;
                        }
                    }
                    else if (u2f_resp == 2)
                    {
                        if (send_control(fd, RESPONSE_VERIFY_FAILED_WITH_REASON) == -1
                            || send_string(fd, client_reason) == -1)
                        {
                            plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                                       "BACKGROUND: write error on response socket [4]");
                            goto done;
                        }
                    }
                    else if (send_control(fd, RESPONSE_VERIFY_FAILED) == -1)
                    {
                        plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                                   "BACKGROUND: write error on response socket [3]");
                        goto done;
                    }
                    break;
                }

                /* non-deferred auth: wait for pam result and send
                 * result back via control socketpair
                 */
                if (pam_auth(service, &up)) /* Succeeded */
                {
                    char client_reason[U2F_CLIENT_REASON_SIZE];
                    int u2f_resp = u2f_auth_verify(&up, NULL, client_reason,
                                                   sizeof(client_reason));

                    if (u2f_resp == 2)
                    {
                        if (send_control(fd, RESPONSE_VERIFY_FAILED_WITH_REASON) == -1
                            || send_string(fd, client_reason) == -1)
                        {
                            plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                                       "BACKGROUND: write error on response socket [4]");
                            goto done;
                        }
                    }
                    else if (send_control(fd, RESPONSE_VERIFY_FAILED) == -1)
                    {
                        plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                                   "BACKGROUND: write error on response socket [3]");
                        goto done;
                    }
                }
                else /* Failed */
                {
                    if (send_control(fd, RESPONSE_VERIFY_FAILED) == -1)
                    {
                        plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                                   "BACKGROUND: write error on response socket [3]");
                        goto done;
                    }
                }
                break;

            case COMMAND_EXIT:
                goto done;

            case -1:
                plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                           "BACKGROUND: read error on command channel");
                goto done;

            default:
                plugin_log(PLOG_ERR, MODULE, "BACKGROUND: unknown command code: code=%d, exiting",
                           command);
                goto done;
        }
        plugin_secure_memzero(up.password, sizeof(up.password));
        plugin_secure_memzero(up.response, sizeof(up.response));
    }
done:
    plugin_secure_memzero(up.password, sizeof(up.password));
    plugin_secure_memzero(up.response, sizeof(up.response));
#ifdef USE_PAM_DLOPEN
    dlclose_pam();
#endif
    if (DEBUG(verb))
    {
        plugin_log(PLOG_NOTE, MODULE, "BACKGROUND: EXIT");
    }

    return;
}

static int64_t
monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
    {
        return 0;
    }
    return ((int64_t)ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

static int
set_nonblocking(int fd)
{
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void
trim_trailing_newlines(char *str)
{
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r'))
    {
        str[--len] = '\0';
    }
}

static void
terminate_child(pid_t pid)
{
    int status;
    struct timespec sleep_time = { .tv_sec = 0, .tv_nsec = 100000000 };

    if (pid <= 0)
    {
        return;
    }

    kill(pid, SIGTERM);
    for (int i = 0; i < 10; ++i)
    {
        pid_t wait_ret = waitpid(pid, &status, WNOHANG);
        if (wait_ret == pid || (wait_ret == -1 && errno == ECHILD))
        {
            return;
        }
        nanosleep(&sleep_time, NULL);
    }

    kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
    {
    }
}

/*
 * Run the U2F helper.  Exit codes are part of the helper contract:
 *   0 = U2F verification succeeded
 *   1 = error or verification failure
 *   2 = client_reason contains a CRV1 challenge for OpenVPN
 */
static int
u2f_auth_verify(const struct user_pass *up, const char *password,
                char *client_reason, size_t client_reason_len)
{
    int pipefd[2] = { -1, -1 };
    pid_t pid;
    int status = 0;
    size_t used = 0;
    bool eof = false;
    bool child_exited = false;
    bool output_overflow = false;

    if (!up || !client_reason || client_reason_len == 0)
    {
        return 1;
    }
    client_reason[0] = '\0';

    if (pipe(pipefd) == -1)
    {
        plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE, "BACKGROUND: U2F helper pipe() failed");
        return 1;
    }

    pid = fork();
    if (pid < 0)
    {
        plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE, "BACKGROUND: U2F helper fork() failed");
        close(pipefd[0]);
        close(pipefd[1]);
        return 1;
    }

    if (pid == 0)
    {
        char *helper_argv[] = { (char *)INTERPRETER, (char *)up->script_path, NULL };

        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) == -1)
        {
            _exit(1);
        }
        close(pipefd[1]);
        close_fds_except(-1);

        if (setenv("username", up->username, 1) == -1)
        {
            _exit(1);
        }
        if (password)
        {
            if (setenv("password", password, 1) == -1)
            {
                _exit(1);
            }
        }
        else
        {
            unsetenv("password");
        }
        if (set_helper_env(up) == -1)
        {
            _exit(1);
        }

        execvp(helper_argv[0], helper_argv);
        _exit(1);
    }

    close(pipefd[1]);
    pipefd[1] = -1;

    if (set_nonblocking(pipefd[0]) == -1)
    {
        plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                   "BACKGROUND: U2F helper failed to set pipe nonblocking");
        terminate_child(pid);
        close(pipefd[0]);
        return 1;
    }

    const int64_t started = monotonic_ms();
    const int64_t deadline = started + U2F_HELPER_TIMEOUT_MS;

    while (!eof || !child_exited)
    {
        char buffer[512];
        ssize_t br;

        if (!child_exited)
        {
            pid_t wait_ret = waitpid(pid, &status, WNOHANG);
            if (wait_ret == pid)
            {
                child_exited = true;
            }
            else if (wait_ret == -1)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                           "BACKGROUND: U2F helper waitpid() failed");
                close(pipefd[0]);
                return 1;
            }
        }

        while (!eof && (br = read(pipefd[0], buffer, sizeof(buffer))) > 0)
        {
            if (used < client_reason_len - 1)
            {
                size_t available = client_reason_len - 1 - used;
                size_t to_copy = (size_t)br < available ? (size_t)br : available;
                memcpy(client_reason + used, buffer, to_copy);
                used += to_copy;
                client_reason[used] = '\0';
                if (to_copy < (size_t)br)
                {
                    output_overflow = true;
                }
            }
            else
            {
                output_overflow = true;
            }
        }

        if (!eof && br == 0)
        {
            eof = true;
        }
        else if (!eof && br == -1 && errno != EAGAIN && errno != EWOULDBLOCK
                 && errno != EINTR)
        {
            plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                       "BACKGROUND: U2F helper stdout read failed");
            terminate_child(pid);
            close(pipefd[0]);
            return 1;
        }

        if (eof && child_exited)
        {
            break;
        }

        int64_t now = monotonic_ms();
        if (now == 0 || now >= deadline)
        {
            plugin_log(PLOG_ERR, MODULE, "BACKGROUND: U2F helper timed out");
            terminate_child(pid);
            close(pipefd[0]);
            return 1;
        }

        struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN | POLLHUP };
        int poll_timeout = (int)(deadline - now);
        if (poll_timeout > 100)
        {
            poll_timeout = 100;
        }
        if (!eof)
        {
            int poll_ret = poll(&pfd, 1, poll_timeout);
            if (poll_ret == -1 && errno != EINTR)
            {
                plugin_log(PLOG_ERR | PLOG_ERRNO, MODULE,
                           "BACKGROUND: U2F helper poll() failed");
                terminate_child(pid);
                close(pipefd[0]);
                return 1;
            }
        }
        else
        {
            struct timespec sleep_time = { .tv_sec = 0, .tv_nsec = 10000000 };
            nanosleep(&sleep_time, NULL);
        }
    }

    close(pipefd[0]);

    if (output_overflow)
    {
        plugin_log(PLOG_ERR, MODULE, "BACKGROUND: U2F helper output exceeded %zu bytes",
                   client_reason_len - 1);
        return 1;
    }

    if (!WIFEXITED(status))
    {
        plugin_log(PLOG_ERR, MODULE, "BACKGROUND: U2F helper exited unexpectedly");
        return 1;
    }

    const int exit_code = WEXITSTATUS(status);
    if (exit_code == 2)
    {
        trim_trailing_newlines(client_reason);
        if (client_reason[0] == '\0')
        {
            plugin_log(PLOG_ERR, MODULE,
                       "BACKGROUND: U2F helper requested client_reason with no output");
            return 1;
        }

        if (up->verb >= 7)
        {
            plugin_log(PLOG_DEBUG, MODULE, "BACKGROUND: U2F helper client_reason: %s",
                       client_reason);
        }
        else
        {
            plugin_log(PLOG_NOTE, MODULE,
                       "BACKGROUND: U2F helper produced client_reason (%zu bytes)",
                       strlen(client_reason));
        }
    }

    return exit_code;
}
