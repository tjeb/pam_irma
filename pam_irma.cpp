#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

#include <string>
#include <iostream>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#define PAM_SM_AUTH

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "silvia/silvia_parameters.h"
#include "silvia/silvia_irma_verifier.h"
#include "silvia/silvia_nfc_card.h"
#include "silvia/silvia_card_channel.h"
#include "silvia/silvia_irma_xmlreader.h"
#include "silvia/silvia_idemix_xmlreader.h"
#include "silvia/silvia_types.h"


#define VERIFIER_XML_PATH "/etc/silvia/verifier.xml"
#define ISSUER_XML_PATH "/etc/silvia/issuer.xml"
#define ISSUER_IPK_PATH "/etc/silvia/ipk.xml"


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
    return PAM_SUCCESS;
}

void show_pam_info(const pam_conv *conv, const char *msgtxt)
{
    pam_message *msg = (pam_message*)malloc(sizeof(pam_message));
    msg->msg_style = PAM_TEXT_INFO;
    msg->msg = msgtxt;
    const pam_message **msgs = (const pam_message**)malloc(sizeof(pam_message*));
    msgs[0] = msg;

    pam_response *resp;

    conv->conv(1, msgs, &resp, conv->appdata_ptr);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    // Get the username
    int result;
    const char *username;
    result = pam_get_user(pamh, &username, NULL);

    const void *conv_void;
    if(pam_get_item(pamh, PAM_CONV, &conv_void) != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Unable to get PAM_CONV");
        return PAM_AUTHINFO_UNAVAIL;
    }
    const pam_conv *conv = (pam_conv*)conv_void;

    // Initiate IRMA stuff
    set_parameters();
    silvia_verifier_specification *vspec = silvia_irma_xmlreader::i()->read_verifier_spec(ISSUER_XML_PATH, VERIFIER_XML_PATH);
    if(vspec == NULL)
    {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Failed to read issuer and verifier specs");
        return PAM_AUTHINFO_UNAVAIL;
    }
    silvia_pub_key *pubkey = silvia_idemix_xmlreader::i()->read_idemix_pubkey(ISSUER_IPK_PATH);
    if(pubkey == NULL)
    {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Failed to read issuer public key");
        return PAM_AUTHINFO_UNAVAIL;
    }
    silvia_irma_verifier verifier(pubkey, vspec);


    show_pam_info(conv, "Please hold card against reader");
    silvia_nfc_card *nfc_card = NULL;
    if(!silvia_nfc_card_monitor::i()->wait_for_card(&nfc_card))
    {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Failed to read the card");
        return PAM_AUTHINFO_UNAVAIL;
    }

    // Actually get info from the card NOW
    //std::vector<bytestring> commands = verifier.get_proof_commands();
    



    return PAM_SUCCESS;
}
