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



void set_parameters()
{
    ////////////////////////////////////////////////////////////////////
    // Set the system parameters in the IRMA library; this function must
    // be updated if we ever change the parameters for IRMA cards!!!
    ////////////////////////////////////////////////////////////////////

    silvia_system_parameters::i()->set_l_n(1024);
    silvia_system_parameters::i()->set_l_m(256);
    silvia_system_parameters::i()->set_l_statzk(80);
    silvia_system_parameters::i()->set_l_H(256);
    silvia_system_parameters::i()->set_l_v(1700);
    silvia_system_parameters::i()->set_l_e(597);
    silvia_system_parameters::i()->set_l_e_prime(120);
    silvia_system_parameters::i()->set_hash_type("sha256");
}


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
