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

    port = 3389
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((ip, 3389))
        connection_flag1 = True
    except:
        connection_flag1 = False

    s.close()
    connection_flag2 = False

    if connection_flag1 is False:
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s2.connect((ip, 3388))
            port = 3388
            connection_flag2 = True
        except:
            connection_flag2 = False

        s2.close()

    if connection_flag1 is False and connection_flag2 is False:
        breach_outputs['risk'] = 'CLEAR'
        return breach_outputs

    error = {
        "supported_encryption_protocols": 'Cannot scan for supported encryption protocols (RDP possibly false positive)',
        "unsupported_encryption_protocols": 'Cannot scan for unsupported encryption protocols (RDP possibly false positive)',
        "error_messages": 'Cannot scan to retrieve error messages (RDP possibly false positive)',
        "supported_encryption_methods": 'Cannot scan for supported encryption methods (RDP possibly false positive)',
        "unsupported_encryption_methods": 'Cannot scan for unsupported encryption methods (RDP possibly false positive)',
        "server_encryption_level": 'Cannot scan for encryption level (RDP possibly false positive)'
    }

    try:
        enum_encryption = rdp_check_ciphers.rdp_scan(ip, 3389)
        if enum_encryption != 'Cannot connect':
            breach_outputs.update(enum_encryption)
        else:
            enum_encryption = rdp_check_ciphers.rdp_scan(ip, 3388)
            if enum_encryption != 'Cannot connect':
                breach_outputs.update(enum_encryption)
            else:
                breach_outputs.update(error)
    except:
        breach_outputs.update(error)

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
        breach_outputs['ntlm'] = rdp_ntlm_info_results_dict
    else:
        breach_outputs['ntlm'] = None

    risk = 'CLEAR'

    if breach_outputs['ntlm'] is None:
        logs.Logging.add('rdp scan', scan['value'], f'RDP scan ntlm failed', 'skipping ntlm results')
    else:
        if breach_outputs['ntlm'] is not None:
            risk = 'MEDIUM_RISK'

    if breach_outputs["unsupported_encryption_protocols"] == 'Cannot scan for unsupported encryption protocols (RDP ' \
                                                             'possibly false positive)':
        logs.Logging.add('rdp scan', scan['value'], f'RDP scan for enum encryption failed', 'skipping enum results')
    else:
        if 'Native RDP' in breach_outputs['supported_encryption_protocols'] or \
                'SSL' in breach_outputs['supported_encryption_protocols']:
            risk = 'CRITICAL'

        if 'CredSSP (NLA)' not in breach_outputs['supported_encryption_protocols'] or \
                'RDSTLS' not in breach_outputs['supported_encryption_protocols']:
            risk = 'HIGH_RISK'

    breach_outputs['risk'] = risk

    scan['output'] = breach_outputs

    queue_to_db.rdp_response_db_addition(scan)

    return breach_outputs

# if native RDP or SSL is SUCCESS = RED -> Together destroys CredSSP (NLA)
# if CredSSP (NLA) or RDSTLS is not there = RED

# if RDP version present = RED -> approaching end of life or mis configured settings
