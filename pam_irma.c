#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int result;

    pam_syslog(pamh, LOG_AUTH | LOG_INFO, "Testing123!");

    const char *username;
    result = pam_get_user(pamh, &username, NULL);

    pam_syslog(pamh, LOG_AUTH | LOG_INFO, "Username: %s", username);
}
