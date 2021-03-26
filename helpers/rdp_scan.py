import nmap
import socket
from helpers import logs, utils, rdp_check_ciphers, queue_to_db


def process(scan):
    scan['status'] = 'running'
    utils.mark_db_request(scan, 'rdp')

    breach_outputs = {'value': scan['value']}

    try:
        ip = socket.gethostbyname(scan['value'])
    except:
        breach_outputs['Error'] = 'Cannot resolve IP'
        return breach_outputs

    try:
        enum_encryption = rdp_check_ciphers.rdp_scan(ip, 3389)
        if enum_encryption != 'Cannot connect':
            breach_outputs.update(enum_encryption)
        else:
            enum_encryption = rdp_check_ciphers.rdp_scan(ip, 3388)
            if enum_encryption != 'Cannot connect':
                breach_outputs.update(enum_encryption)
            else:
                breach_outputs['Error'] = 'Cannot scan for Ciphers'
    except:
        breach_outputs['Error'] = 'Cannot scan for Ciphers'

    nmap_patch = nmap.PortScanner()

    try:
        patch_check = nmap_patch.scan(hosts=ip, arguments='-p 3389,3388 -T4 -Pn -d --script rdp-ntlm-info')
    except:
        breach_outputs[scan['value']] = 'Cannot RDP Scan'
        return breach_outputs

    if 'script' in patch_check['scan'][ip]['tcp'][3389] and \
            'rdp-ntlm-info' in patch_check['scan'][ip]['tcp'][3389]['script']:
        rdp_ntlm_info_results = patch_check['scan'][ip]['tcp'][3389]['script']['rdp-ntlm-info']
    elif 'script' in patch_check['scan'][ip]['tcp'][3388] and \
            'rdp-ntlm-info' in patch_check['scan'][ip]['tcp'][3388]['script']:
        rdp_ntlm_info_results = patch_check['scan'][ip]['tcp'][3388]['script']['rdp-ntlm-info']
    else:
        rdp_ntlm_info_results = None

    logs.Logging.add('rdp scan', scan['value'], f'RDP scan complete', 'finished')

    if rdp_ntlm_info_results is not None:
        rdp_ntlm_info_modified = rdp_ntlm_info_results.strip().replace('\n', ',,').replace(': ', ':: ')

        rdp_ntlm_info_results_dict = dict((x.strip(), y.strip())
                                          for x, y in (element.split('::')
                                                       for element in rdp_ntlm_info_modified.split(',, ')))
        breach_outputs['new technology LAN manager'] = rdp_ntlm_info_results_dict
    else:
        breach_outputs['new technology LAN manager'] = None

    risk = None

    if breach_outputs['new technology LAN manager'] is not None:
        risk = 'Medium'

    if 'Native RDP' in breach_outputs['supported_encryption_protocols'] or 'SSL' in breach_outputs['supported_encryption_protocols']:
        risk = 'High'

    if 'CredSSP (NLA)' not in breach_outputs['supported_encryption_protocols'] or 'RDSTLS' not in breach_outputs['supported_encryption_protocols']:
        risk = 'High'

    breach_outputs['risk'] = risk

    scan['output'] = breach_outputs

    queue_to_db.rdp_response_db_addition(scan)

    return breach_outputs

# if native RDP or SSL is SUCCESS = RED -> Together destroys CredSSP (NLA)
# if CredSSP (NLA) or RDSTLS is not there = RED

# if RDP version present = RED -> approaching end of life or mis configured settings
