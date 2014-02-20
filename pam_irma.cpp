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

bool verify_pin(pam_handle_t *pamh, const pam_conv *conv, silvia_card_channel *card)
{
    pam_message *msg = (pam_message*)malloc(sizeof(pam_message));
    msg->msg_style = PAM_PROMPT_ECHO_OFF;
    msg->msg = "Please enter your PIN code: ";
    const pam_message **msgs = (const pam_message**)malloc(sizeof(pam_message*));
    msgs[0] = msg;
    pam_response *resp;
    conv->conv(1, msgs, &resp, conv->appdata_ptr);

    show_pam_info(conv, "Verifying PIN...");

    bytestring verify_pin_apdu = "0020000008";
    for(int i = 0; i < strlen(resp->resp); i++)
    {
        verify_pin_apdu += (unsigned char)resp->resp[i];
    }

    while(verify_pin_apdu.size() < 13)
    {
        verify_pin_apdu += "00";
    }

    bytestring data;
    unsigned short sw;

    if(!card->transmit(verify_pin_apdu, data, sw))
    {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "PIN: Card communication failed");
        return false;
    }

    if(sw == 0x9000)
    {
        return true;
    }
    else if((sw >= 0x636C0) && (sw <= 0x63CF))
    {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "PIN: FAILED (%u attempts remaining)", sw - 0x63C0);
    }
    else
    {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "PIN: FAILED (card error 0x&04X)", sw);
    }

    return false;
}

bytestring bs2str(const bytestring& in)
{
    bytestring out = in;

    // Strip leading 00's
    while ((out.size() > 0) && (out[0] == 0x00))
    {
        out = out.substr(1);
    }

    // Append null-termination
    out += 0x00;

    return out;
}

bool communicate_with_card(pam_handle_t *pamh, const pam_conv *conv, silvia_card_channel* card, std::vector<bytestring>& commands, std::vector<bytestring>& results)
{
    show_pam_info(conv, "Communicating with card...");
    bool comm_ok = true;
    size_t cmd_ctr = 0;

    for(std::vector<bytestring>::iterator i = commands.begin(); i != commands.end(); i++)
    {
        bytestring result;
        if(!card->transmit(*i, result))
        {
            comm_ok = false;
            break;
        }
        cmd_ctr++;
        if(result.substr(result.size() - 2) == "6982")
        {
            //Card wants us to enter PIN
            if(!verify_pin(pamh, conv, card))
            {
                comm_ok = false;
                break;
            }

            show_pam_info(conv, "Communicating with card...");

            if(!card->transmit(*i, result))
            {
                comm_ok = false;
                break;
            }
        }
		else if ((result.substr(result.size() - 2) != "9000") && 
		         (result.substr(result.size() - 2) != "6A82") &&
		         (result.substr(result.size() - 2) != "6D00"))
        {
            pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Error communicating with card: (0x%s) ", result.substr(result.size() - 2).hex_str().c_str());
            comm_ok = false;
            break;
        }

        results.push_back(result);
    }
    return comm_ok;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int exitcode = PAM_AUTH_ERR;
    silvia_verifier_specification *vspec;
    silvia_pub_key *pubkey;
    silvia_nfc_card *card;

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
    vspec = silvia_irma_xmlreader::i()->read_verifier_spec(ISSUER_XML_PATH, VERIFIER_XML_PATH);
    if(vspec == NULL)
    {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Failed to read issuer and verifier specs");
        return PAM_AUTHINFO_UNAVAIL;
    }
    pubkey = silvia_idemix_xmlreader::i()->read_idemix_pubkey(ISSUER_IPK_PATH);
    if(pubkey == NULL)
    {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Failed to read issuer public key");
        return PAM_AUTHINFO_UNAVAIL;
    }
    silvia_irma_verifier verifier(pubkey, vspec);


    show_pam_info(conv, "Please hold card against reader");
    card = NULL;
    if(!silvia_nfc_card_monitor::i()->wait_for_card(&card))
    {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Failed to read the card");
        return PAM_AUTHINFO_UNAVAIL;
    }

    // Actually get info from the card NOW
    show_pam_info(conv, "Initializing card...");
    std::vector<bytestring> results;
    std::vector<bytestring> commands = verifier.get_select_commands();
    if(!communicate_with_card(pamh, conv, card, commands, results))
    {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Unable to select application on card");
        return PAM_AUTHINFO_UNAVAIL;
    }
    if(!verifier.submit_select_data(results))
    {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Unable to verify application selection");
        return PAM_AUTHINFO_UNAVAIL;
    }
    commands.clear();
    results.clear();
    show_pam_info(conv, "Communicating with card...");
    bool comm_ok = true;
    size_t cmd_ctr = 0;

    commands = verifier.get_proof_commands();
    if(!communicate_with_card(pamh, conv, card, commands, results))
    {
        verifier.abort();
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Unable to execute proof comments");
        return PAM_AUTHINFO_UNAVAIL;
    }
    std::vector<std::pair<std::string, bytestring> > revealed;
    show_pam_info(conv, "Verifying...");
    if(!verifier.submit_and_verify(results, revealed))
    {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Verification failed");
        return PAM_AUTHINFO_UNAVAIL;
    }
    if(revealed.size() <= 0)
    {
        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "No attributes revealed");
        return PAM_AUTHINFO_UNAVAIL;
    }
    
    std::vector<std::pair<std::string, bytestring> >::iterator i = revealed.begin();

    if((i->first == "expires") || (i->first == "metadata"))
    {
        //Check if this is expires or whatever... IGNORE FOR NOW
        //TODO!!!!
    }

    for(; i != revealed.end(); i++)
    {
        const char *key = i->first.c_str();
        const char *value = (const char*) bs2str(i->second).byte_str();

        pam_syslog(pamh, LOG_AUTH | LOG_ERR, "Attribute read: %s = %s", key, value);
    }

    return PAM_AUTHINFO_UNAVAIL;
}
