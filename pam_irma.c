#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

#define PAM_SM_AUTH

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    pam_syslog(pamh, LOG_AUTH | LOG_ERR, "sm_setcred");

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int result;

    pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Testing123!");

    const char *username;
    result = pam_get_user(pamh, &username, NULL);

    pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Username: %s", username);

    return PAM_SUCCESS;
}
