#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

#define PAM_SM_AUTH

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "pam_irma_details.h"

#include "silvia/silvia_parameters.h"
#include "silvia/silvia_irma_verifier.h"
#include "silvia/silvia_nfc_card.h"
#include "silvia/silvia_card_channel.h"
#include "silvia/silvia_irma_xmlreader.h"
#include "silvia/silvia_idemix_xmlreader.h"
#include "silvia/silvia_types.h"

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    printf("sm_setced-print");
    pam_syslog(pamh, LOG_AUTH | LOG_ERR, "sm_setcred");

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    printf("sm_authenticate");
    int result;

    pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Testing123!");

    const char *username;
    result = pam_get_user(pamh, &username, NULL);

    pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Username: %s", username);

    return PAM_AUTH_ERR;
}
