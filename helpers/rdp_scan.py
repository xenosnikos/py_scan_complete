import nmap
import socket
import logging

from helpers import utils, rdp_check_ciphers, common_strings

logger = logging.getLogger(common_strings.strings['rdp'])
socket.setdefaulttimeout(3)


def process(ip):
    # marks data to running from queued in db
    utils.mark_db_request(value=ip, status=common_strings.strings['status_running'],
                          collection=common_strings.strings['rdp'])

    # initialize error dictionary to send as output for when ports are open but Enum encryption scan fails
    error = {
        common_strings.strings['error_enum']: True,
        "supported_encryption_protocols": 'Cannot scan for supported encryption protocols (RDP possibly false positive)',
        "unsupported_encryption_protocols": 'Cannot scan for unsupported encryption protocols (RDP possibly false '
                                            'positive)',
        "error_messages": 'Cannot scan to retrieve error messages (RDP possibly false positive)',
        "supported_encryption_methods": 'Cannot scan for supported encryption methods (RDP possibly false positive)',
        "unsupported_encryption_methods": 'Cannot scan for unsupported encryption methods (RDP possibly false positive)',
        "server_encryption_level": 'Cannot scan for encryption level (RDP possibly false positive)'
    }

    port_3389 = 3389
    port_3388 = 3388
    output = {}

    try:
        enum_encryption = rdp_check_ciphers.rdp_scan(ip, port_3389)
        if enum_encryption != 'Cannot connect':
            output.update(enum_encryption)
        else:
            enum_encryption = rdp_check_ciphers.rdp_scan(ip, port_3388)
            if enum_encryption != 'Cannot connect':
                output.update(enum_encryption)
            else:
                logger.info('Both ports 3389 and 3388 are not open')
                output.update({'risk': 'CLEAR'})
    except Exception as e:
        logger.error(f'Cannot scan for enum encryption {e}')
        output.update(error)

    logger.debug('Enum encryption scan complete')

    nmap_patch = nmap.PortScanner()

    try:
        patch_check = nmap_patch.scan(hosts=ip, arguments='-p 3389,3388 -T4 -Pn -d --script rdp-ntlm-info')
    except Exception as e:
        logger.error(f'Cannot scan for NTLM {e}')
        output[common_strings.strings['error_ntlm']] = True
        rdp_ntlm_info_results = common_strings.strings['error']
    else:  # If there is no exception then this block will be executed
        if 'script' in patch_check['scan'][ip]['tcp'][3389] and \
                'rdp-ntlm-info' in patch_check['scan'][ip]['tcp'][3389]['script']:
            rdp_ntlm_info_results = patch_check['scan'][ip]['tcp'][3389]['script']['rdp-ntlm-info']
        elif 'script' in patch_check['scan'][ip]['tcp'][3388] and \
                'rdp-ntlm-info' in patch_check['scan'][ip]['tcp'][3388]['script']:
            rdp_ntlm_info_results = patch_check['scan'][ip]['tcp'][3388]['script']['rdp-ntlm-info']
        else:
            rdp_ntlm_info_results = None

    logger.debug('NTLM scan complete')

    if rdp_ntlm_info_results is not None and rdp_ntlm_info_results != common_strings.strings['error']:
        rdp_ntlm_info_modified = rdp_ntlm_info_results.strip().replace('\n', ',,').replace(': ', ':: ')

        rdp_ntlm_info_results_dict = dict((x.strip(), y.strip())
                                          for x, y in (element.split('::')
                                                       for element in rdp_ntlm_info_modified.split(',, ')))
        if len(rdp_ntlm_info_results_dict) != 8:
            key_list = ["Target_Name",
                        "NetBIOS_Domain_Name",
                        "NetBIOS_Computer_Name",
                        "DNS_Domain_Name",
                        "DNS_Computer_Name",
                        "DNS_Tree_Name",
                        "Product_Version",
                        "System_Time"]

            for each_key in key_list:
                if each_key in rdp_ntlm_info_results_dict:
                    continue
                else:
                    rdp_ntlm_info_results_dict[each_key] = None

        output[common_strings.strings['output_ntlm']] = rdp_ntlm_info_results_dict
    elif rdp_ntlm_info_results is None:
        output[common_strings.strings['output_ntlm']] = ''
    else:
        output[common_strings.strings['output_ntlm']] = common_strings.strings['error']

    risk = 'CLEAR'

    if output[common_strings.strings['output_ntlm']] == common_strings.strings['error']:
        logger.error(f'NTLM scan failed, skipping NTLM results')
    else:
        if output[common_strings.strings['output_ntlm']] is not None:
            risk = 'MEDIUM_RISK'

    if common_strings.strings['error_enum'] in output:
        logger.error(f'Enum encryption scan failed, skipping Enum results')
    else:
        if 'CredSSP (NLA)' not in output['supported_encryption_protocols'] or \
                'RDSTLS' not in output['supported_encryption_protocols']:
            risk = 'HIGH_RISK'

        if 'Native RDP' in output['supported_encryption_protocols'] or \
                'SSL' in output['supported_encryption_protocols']:
            risk = 'CRITICAL'

    output['risk'] = risk

    return output

# if native RDP or SSL is SUCCESS = RED -> Together destroys CredSSP (NLA)
# if CredSSP (NLA) or RDSTLS is not there = RED

# if RDP version present = RED -> approaching end of life or mis configured settings
