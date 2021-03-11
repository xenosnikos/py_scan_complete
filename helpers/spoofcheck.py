import emailprotectionslib.dmarc as dmarclib
import emailprotectionslib.spf as spflib
import logging


logging.basicConfig(level=logging.INFO)

out = {}


def check_spf_redirect_mechanisms(spf_record):
    global out
    redirect_domain = spf_record.get_redirect_domain()

    if redirect_domain:
        out['check_spf_redirect_mechanisms'] = f"Processing an SPF redirect domain: {redirect_domain}"
        return is_spf_record_strong(redirect_domain)
    else:
        return False


def check_spf_include_mechanisms(spf_record):
    global out
    include_domain_list = spf_record.get_include_domains()

    for include_domain in include_domain_list:
        out['check_spf_include_mechanisms'] = f"Processing an SPF include domain: {include_domain}"
        strong_all_string = is_spf_record_strong(include_domain)

        if strong_all_string:
            return True

    return False


def is_spf_redirect_record_strong(spf_record):
    global out
    out['is_spf_redirect_record_strong'] = f"Checking SPF redirect domain: {spf_record.get_redirect_domain}"
    redirect_strong = spf_record._is_redirect_mechanism_strong()

    if redirect_strong:
        out['message_is_spf_redirect_record_strong'] = "Redirect mechanism is strong."
    else:
        out['message_is_spf_redirect_record_strong'] = "Redirect mechanism is not strong."

    return redirect_strong


def are_spf_include_mechanisms_strong(spf_record):
    global out
    out['are_spf_include_mechanisms_strong'] = "Checking SPF include mechanisms"
    include_strong = spf_record._are_include_mechanisms_strong()

    if include_strong:
        out['message_are_spf_include_mechanisms_strong'] = "Include mechanisms include a strong record"
    else:
        out['message_are_spf_include_mechanisms_strong'] = "Include mechanisms are not strong"

    return include_strong


def check_spf_include_redirect(spf_record):
    other_records_strong = False

    if spf_record.get_redirect_domain():
        other_records_strong = is_spf_redirect_record_strong(spf_record)

    if not other_records_strong:
        other_records_strong = are_spf_include_mechanisms_strong(spf_record)

    return other_records_strong


def check_spf_all_string(spf_record):
    global out
    strong_spf_all_string = True

    if spf_record.all_string:

        if spf_record.all_string == "~all" or spf_record.all_string == "-all":
            out['message_check_spf_all_string'] = f"SPF record contains an All item: {spf_record.all_string}"
        else:
            out['message_check_spf_all_string'] = f"SPF record All item is too weak: {spf_record.all_string}"
            strong_spf_all_string = False

    else:
        out['message_check_spf_all_string'] = "SPF record has no All string"
        strong_spf_all_string = False

    if not strong_spf_all_string:
        strong_spf_all_string = check_spf_include_redirect(spf_record)

    return strong_spf_all_string


def is_spf_record_strong(domain):
    global out
    strong_spf_record = True

    spf_record = spflib.SpfRecord.from_domain(domain)
    if spf_record and spf_record.record:
        out["Found SPF record"] = str(spf_record.record)

        strong_all_string = check_spf_all_string(spf_record)
        if not strong_all_string:

            redirect_strength = check_spf_redirect_mechanisms(spf_record)
            include_strength = check_spf_include_mechanisms(spf_record)

            strong_spf_record = False

            if redirect_strength or include_strength:
                strong_spf_record = True
    else:
        out['message_is_spf_record_strong'] = f"{domain} has no SPF record!"
        strong_spf_record = False

    return strong_spf_record


def get_dmarc_record(domain):
    global out
    dmarc = dmarclib.DmarcRecord.from_domain(domain)
    if dmarc and dmarc.record:
        out["Found DMARC record"] = str(dmarc.record)
    return dmarc


def get_dmarc_org_record(base_record):
    global out
    org_record = base_record.get_org_record()
    if org_record:
        out["Found DMARC Organizational record:"] = str(org_record.record)
    return org_record


def check_dmarc_extras(dmarc_record):
    global out
    if dmarc_record.pct and dmarc_record.pct != str(100):
        out['message_check_dmarc_extras'] = [f"DMARC pct is set to {dmarc_record.pct}% - might be possible"]

    if dmarc_record.rua:
        if 'message_check_dmarc_extras' in out:
            out['message_check_dmarc_extras'].append(f"Aggregate reports will be sent: {dmarc_record.rua}")
        else:
            out['message_check_dmarc_extras'] = [f"Aggregate reports will be sent: {dmarc_record.rua}"]

    if dmarc_record.ruf:
        if 'message_check_dmarc_extras' in out:
            out['message_check_dmarc_extras'].append(f"Forensics reports will be sent: {dmarc_record.ruf}")
        else:
            out['message_check_dmarc_extras'] = [f"Forensics reports will be sent: {dmarc_record.ruf}"]


def check_dmarc_policy(dmarc_record):
    global out
    policy_strength = False

    if dmarc_record.policy:
        if dmarc_record.policy == "reject" or dmarc_record.policy == "quarantine":
            policy_strength = True
            out['message_check_dmarc_policy'] = f"DMARC policy set to {dmarc_record.policy}"
        else:
            out['message_check_dmarc_policy'] = f"DMARC policy set to {dmarc_record.policy}"
    else:
        out['message_check_dmarc_policy'] = "DMARC record has no Policy"

    return policy_strength


def check_dmarc_org_policy(base_record):
    global out
    policy_strong = False

    try:
        org_record = base_record.get_org_record()
        if org_record and org_record.record:
            out["Found organizational DMARC record:"] = str(org_record.record)

            if org_record.subdomain_policy:
                if org_record.subdomain_policy == "none":
                    out['message_check_dmarc_org_policy'] = f"Organizational subdomain policy set to {org_record.subdomain_policy}"
                elif org_record.subdomain_policy == "quarantine" or org_record.subdomain_policy == "reject":
                    out['message_check_dmarc_org_policy'] = f"Organizational subdomain policy explicitly set to {org_record.subdomain_policy}"
                    policy_strong = True
            else:
                out['message_check_dmarc_org_policy'] = "No explicit organizational subdomain policy. Defaulting to organizational policy..."
                policy_strong = check_dmarc_policy(org_record)
        else:
            out['message_check_dmarc_org_policy'] = "No organizational DMARC record"

    except dmarclib.OrgDomainException:
        out['message_check_dmarc_org_policy'] = "No organizational DMARC record"

    except Exception as e:
        logging.exception(e)

    return policy_strong


def is_dmarc_record_strong(domain):
    global out
    dmarc_record_strong = False

    dmarc = get_dmarc_record(domain)

    if dmarc and dmarc.record:
        dmarc_record_strong = check_dmarc_policy(dmarc)

        check_dmarc_extras(dmarc)

    elif dmarc.get_org_domain():
        out['message_is_dmarc_record_strong'] = "No DMARC record found. Looking for organizational record..."
        dmarc_record_strong = check_dmarc_org_policy(dmarc)

    else:
        out['message_is_dmarc_record_strong'] = f"{domain} has no DMARC record!"

    return dmarc_record_strong


def main_check(domain):
    global out
    out = {}
    msg = {}

    spf_record_strong = is_spf_record_strong(domain)
    dmarc_record_strong = is_dmarc_record_strong(domain)

    if spf_record_strong and dmarc_record_strong:
        msg['message'] = f"Spoofing not possible for {domain}"
    else:
        msg['message'] = f"Spoofing possible for {domain}!"

    return [msg, out]
