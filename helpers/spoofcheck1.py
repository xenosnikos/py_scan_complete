import sys

import emailprotectionslib.dmarc as dmarclib
import emailprotectionslib.spf as spflib
import logging


logging.basicConfig(level=logging.INFO)


def check_spf_redirect_mechanisms(spf_record):
    redirect_domain = spf_record.get_redirect_domain()

    if redirect_domain:
        output_info(f"Processing an SPF redirect domain: {redirect_domain}")
        return is_spf_record_strong(redirect_domain)
    else:
        return False


def check_spf_include_mechanisms(spf_record):
    include_domain_list = spf_record.get_include_domains()

    for include_domain in include_domain_list:
        output_info(f"Processing an SPF include domain: {include_domain}")
        strong_all_string = is_spf_record_strong(include_domain)

        if strong_all_string:
            return True

    return False


def is_spf_redirect_record_strong(spf_record):
    output_info(f"Checking SPF redirect domain: {spf_record.get_redirect_domain}")
    redirect_strong = spf_record._is_redirect_mechanism_strong()

    if redirect_strong:
        output_bad("Redirect mechanism is strong.")
    else:
        output_indifferent("Redirect mechanism is not strong.")

    return redirect_strong


def are_spf_include_mechanisms_strong(spf_record):
    output_info("Checking SPF include mechanisms")
    include_strong = spf_record._are_include_mechanisms_strong()

    if include_strong:
        output_bad("Include mechanisms include a strong record")
    else:
        output_indifferent("Include mechanisms are not strong")

    return include_strong


def check_spf_include_redirect(spf_record):
    other_records_strong = False

    if spf_record.get_redirect_domain():
        other_records_strong = is_spf_redirect_record_strong(spf_record)

    if not other_records_strong:
        other_records_strong = are_spf_include_mechanisms_strong(spf_record)

    return other_records_strong


def check_spf_all_string(spf_record):
    strong_spf_all_string = True

    if spf_record.all_string:

        if spf_record.all_string == "~all" or spf_record.all_string == "-all":
            output_indifferent(f"SPF record contains an All item: {spf_record.all_string}")
        else:
            output_good(f"SPF record All item is too weak: {spf_record.all_string}")
            strong_spf_all_string = False

    else:
        output_good("SPF record has no All string")
        strong_spf_all_string = False

    if not strong_spf_all_string:
        strong_spf_all_string = check_spf_include_redirect(spf_record)

    return strong_spf_all_string


def is_spf_record_strong(domain):
    msg = {}

    spf_record = spflib.SpfRecord.from_domain(domain)
    if spf_record and spf_record.record:
        msg["SPF record:"] = str(spf_record.record)
        msg["strong_spf_record"] = True

        strong_all_string = check_spf_all_string(spf_record)
        if not strong_all_string:

            redirect_strength = check_spf_redirect_mechanisms(spf_record)
            include_strength = check_spf_include_mechanisms(spf_record)

            msg["strong_spf_record"] = False

            if redirect_strength or include_strength:
                msg["strong_spf_record"] = True
    else:
        msg["SPF record:"] = f"{domain} has no SPF record!"
        msg["strong_spf_record"] = True

    return msg


def get_dmarc_record(domain):
    msg = {}
    dmarc = dmarclib.DmarcRecord.from_domain(domain)
    if dmarc and dmarc.record:
        msg["Found DMARC record:"] = str(dmarc.record)
        msg["dmarc"] = dmarc
    return msg


def get_dmarc_org_record(base_record):
    org_record = base_record.get_org_record()
    if org_record:
        output_info("Found DMARC Organizational record:")
        output_info(str(org_record.record))
    return org_record


def check_dmarc_extras(dmarc_record):
    msg = {}
    if dmarc_record.pct and dmarc_record.pct != str(100):
        msg['message_check_dmarc_extras'] = [f"DMARC pct is set to {dmarc_record.pct}% - might be possible"]

    if dmarc_record.rua:
        msg['message_check_dmarc_extras'].append(f"Aggregate reports will be sent: {dmarc_record.rua}")

    if dmarc_record.ruf:
        msg['message_check_dmarc_extras'].append(f"Forensics reports will be sent: {dmarc_record.ruf}")

    return msg

def check_dmarc_policy(dmarc_record):
    msg = {'policy_strength': False}

    if dmarc_record.policy:
        if dmarc_record.policy == "reject" or dmarc_record.policy == "quarantine":
            msg['policy_strength'] = True
            msg['message_check_dmarc_policy'] = [f"DMARC policy set to {dmarc_record.policy}"]
        else:
            msg['message_check_dmarc_policy'] = [f"DMARC policy set to {dmarc_record.policy}"]
    else:
        msg['message_check_dmarc_policy'] = ["DMARC record has no Policy"]

    return msg


def check_dmarc_org_policy(base_record):
    msg = {'policy_strong': False}

    try:
        org_record = base_record.get_org_record()
        if org_record and org_record.record:
            msg["Found organizational DMARC record:"] = str(org_record.record)

            if org_record.subdomain_policy:
                if org_record.subdomain_policy == "none":
                    msg['message_check_dmarc_org_policy'] = [f"Organizational subdomain policy set to {org_record.subdomain_policy}"]
                elif org_record.subdomain_policy == "quarantine" or org_record.subdomain_policy == "reject":
                    msg['message_check_dmarc_org_policy'] = [f"Organizational subdomain policy explicitly set to {org_record.subdomain_policy}"]
                    msg['policy_strong'] = True
            else:
                msg['message_check_dmarc_org_policy'] = ["No explicit organizational subdomain policy. Defaulted to organizational policy"]
                call = check_dmarc_policy(org_record)
                msg['message_check_dmarc_org_policy'].append(str(call['message_check_dmarc_policy']))
                msg['policy_strong'] = call['policy_strength']
        else:
            msg['message_check_dmarc_org_policy'] = ["No organizational DMARC record"]

    except dmarclib.OrgDomainException:
        msg['message_check_dmarc_org_policy'] = ["No organizational DMARC record"]

    except Exception as e:
        logging.exception(e)

    return msg


def is_dmarc_record_strong(domain):
    msg = {'dmarc_record_strong': False}

    dmarc1 = get_dmarc_record(domain)
    msg.update(dmarc1)
    dmarc = dmarc1['dmarc']
    if dmarc and dmarc.record:
        call = check_dmarc_policy(dmarc)
        msg['dmarc_record_strong'] = call['policy_strength']
        msg.update(call)
        msg['check_dmarc_extras'] = check_dmarc_extras(dmarc)

    elif dmarc.get_org_domain():
        msg['dmarc_info'] = "No DMARC record found. Looked at organizational record"
        call = check_dmarc_org_policy(dmarc)
        msg['message_dmarc_record_strong'] = call
        msg['dmarc_record_strong'] = call['policy_strong']

    else:
        msg['dmarc_info'] = f"{domain} has no DMARC record!"

    return msg


def main_check(domain):
    out = {}

    spf_record_strong = is_spf_record_strong(domain)
    out.update(spf_record_strong)
    dmarc_record_strong = is_dmarc_record_strong(domain)
    out.update(dmarc_record_strong)

    if spf_record_strong["strong_spf_record"] and dmarc_record_strong["dmarc_record_strong"]:
        return {
            'message': f"Spoofing not possible for {domain}"
        }
    else:
        return {
            'message': f"Spoofing possible for {domain}"
        }