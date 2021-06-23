import nmap


def nmap_scan(ip, scan_type):
    nmap_port_scan = nmap.PortScanner()

    try:
        if scan_type == 'quick':
            nmap_port_scanner = nmap_port_scan.scan(hosts=ip, arguments='-sT -Pn --top-ports 200')
        elif scan_type == 'full':
            nmap_port_scanner = nmap_port_scan.scan(hosts=ip, arguments='-p- -sT -Pn')
        else:
            nmap_port_scanner = nmap_port_scan.scan(hosts=ip, arguments='-sT -Pn --top-ports 1000')
    except:
        nmap_port_scanner = None

    if nmap_port_scanner is not None:
        scan_output = nmap_port_scanner['scan'][ip]['tcp']

        out = {}

        for (key, value) in scan_output.items():
            status_flag = True
            for (k, v) in value.items():
                if k == 'state' and v != 'open':
                    status_flag = False
                    continue
                if k == 'name' and status_flag is True:
                    out[str(key)] = {k: v, 'type': '', 'description': ''}
                    continue
    else:
        out = None

    return out
