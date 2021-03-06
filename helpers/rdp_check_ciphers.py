import socket
import sys
import logging

from helpers import common_strings

logger = logging.getLogger(common_strings.strings['rdp'])


def rdp_scan(host, port):
    # Packets
    X224_CONNECTION_REQUEST = "\x03\x00\x00\x2c\x27\xe0\x00\x00\x00\x00\x00\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73" \
                              "\x74\x73\x68\x61\x73\x68\x3d\x65\x6c\x74\x6f\x6e\x73\x0d\x0a\x01\x00\x08\x00%s\x00\x00" \
                              "\x00"

    CLIENT_MCS_CONNECT_INTIAL = "\x03\x00\x01\x9c\x02\xf0\x80\x7f\x65\x82\x01\x90\x04\x01\x01\x04\x01\x01\x01\x01\xff" \
                                "\x30\x19\x02\x01\x22\x02\x01\x02\x02\x01\x00\x02\x01\x01\x02\x01\x00\x02\x01\x01\x02" \
                                "\x02\xff\xff\x02\x01\x02\x30\x19\x02\x01\x01\x02\x01\x01\x02\x01\x01\x02\x01\x01\x02" \
                                "\x01\x00\x02\x01\x01\x02\x02\x04\x20\x02\x01\x02\x30\x1c\x02\x02\xff\xff\x02\x02\xfc" \
                                "\x17\x02\x02\xff\xff\x02\x01\x01\x02\x01\x00\x02\x01\x01\x02\x02\xff\xff\x02\x01\x02" \
                                "\x04\x82\x01\x2f\x00\x05\x00\x14\x7c\x00\x01\x81\x26\x00\x08\x00\x10\x00\x01\xc0\x00" \
                                "\x44\x75\x63\x61\x81\x18\x01\xc0\xd4\x00\x04\x00\x08\x00\x00\x05\x20\x03\x01\xca\x03" \
                                "\xaa\x09\x08\x00\x00\x28\x0a\x00\x00\x45\x00\x4d\x00\x50\x00\x2d\x00\x4c\x00\x41\x00" \
                                "\x50\x00\x2d\x00\x30\x00\x30\x00\x31\x00\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04" \
                                "\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xca\x01\x00\x00\x00\x00\x00\x10" \
                                "\x00\x07\x00\x01\x00\x37\x00\x36\x00\x34\x00\x38\x00\x37\x00\x2d\x00\x4f\x00\x45\x00" \
                                "\x4d\x00\x2d\x00\x30\x00\x30\x00\x31\x00\x31\x00\x39\x00\x30\x00\x33\x00\x2d\x00\x30" \
                                "\x00\x30\x00\x31\x00\x30\x00\x37\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x04\xc0\x0c\x00\x09\x00\x00\x00\x00\x00\x00\x00\x02" \
                                "\xc0\x0c\x00%s\x00\x00\x00\x00\x00\x00\x00\x03\xc0\x2c\x00\x03\x00\x00\x00\x72\x64" \
                                "\x70\x64\x72\x00\x00\x00\x00\x00\x80\x80\x63\x6c\x69\x70\x72\x64\x72\x00\x00\x00\xa0" \
                                "\xc0\x72\x64\x70\x73\x6e\x64\x00\x00\x00\x00\x00\xc0"

    X224_NATIVE_RDP = "\x03\x00\x00\x27\x22\xe0\x00\x00\x00\x00\x00\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73\x74\x73" \
                      "\x68\x61\x73\x68\x3d\x61\x64\x6d\x69\x6e\x69\x73\x74\x72\x0d\x0a"

    # Error messages
    error_messages = {"\x01": "SSL_REQUIRED_BY_SERVER", "\x02": "SSL_NOT_ALLOWED_BY_SERVER",
                      "\x03": "SSL_CERT_NOT_ON_SERVER", "\x04": "INCONSISTENT_FLAGS",
                      "\x05": "HYBRID_REQUIRED_BY_SERVER", "\x06": "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"}

    # Supported encryption protocols, methods and levels
    enc_protocols = {"\x00": ["Native RDP", False], "\x01": ["SSL", False], "\x03": ["CredSSP (NLA)", False],
                     "\x04": ["RDSTLS", False], "\x08": ["CredSSP with Early User Auth", False]}
    enc_methods = {"\x01": ["40-bit RC4", False], "\x02": ["128-bit RC4", False], "\x08": ["56-bit RC4", False],
                   "\x10": ["FIPS 140-1", False]}
    enc_levels = {"\x00": ["None", False], "\x01": ["Low", False], "\x02": ["Client Compatible", False],
                  "\x03": ["High", False], "\x04": ["FIPS 140-1", False]}

    LATIN_1 = 'latin-1'

    # Received errors
    errors = {}

    # Enumerate supported protocols
    for n in enc_protocols.keys():
        packet = X224_CONNECTION_REQUEST % n

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((host, port))
        except:
            return 'cannot connect'
        s.send(packet.encode(LATIN_1))
        response = s.recv(1024).decode(LATIN_1)

        if response[3] == "\x0b":
            enc_protocols["\x00"][1] = True
            break
        else:
            if response[11] == "\x02":
                enc_protocols[n][1] = True
            else:
                errors[response[15]] = True

        s.close()

    logger.debug('Supported protocols enumeration complete')

    supported_encryption_protocols = []
    unsupported_encryption_protocols = []
    error_messages_out = []
    supported_encryption_methods = []
    unsupported_encryption_methods = []
    server_encryption_level = []

    # ENCRYPTION PROTOCOLS
    # Supported & Unsupported encryption protocols

    for n in enc_protocols.keys():
        if enc_protocols[n][1]:
            supported_encryption_protocols.append(enc_protocols[n][0])
        else:
            unsupported_encryption_protocols.append(enc_protocols[n][0])

    logger.debug('Encryption protocol check complete')

    # Received error messages

    for error in errors.keys():
        error_messages_out.append(error_messages[error])

    # Enumerate native RDP encryption methods and levels
    if enc_protocols["\x00"][1]:

        for n in enc_methods.keys():
            first_packet = X224_NATIVE_RDP
            second_packet = CLIENT_MCS_CONNECT_INTIAL % n

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, port))
                s.send(first_packet.encode(LATIN_1))
                response = s.recv(1024).decode(LATIN_1)

                sys.stdout.flush()
                s.send(second_packet.encode(LATIN_1))
                response = s.recv(1024).decode(LATIN_1)
            except socket.error:
                s.close()
                continue

            for i in range(0, len(response)):
                if response[i:i + 2] == "\x02\x0c":
                    enc_methods[response[i + 4]][1] = True
                    enc_levels[response[i + 8]][1] = True
                    break

            s.close()

        logger.debug('RDP encryption enumeration complete')

        # Supported & Unsupported encryption methods

        for n in enc_methods.keys():
            if enc_methods[n][1]:
                supported_encryption_methods.append(enc_methods[n][0])
            else:
                unsupported_encryption_methods.append(enc_methods[n][0])

        logger.debug('RDP encryption method complete')

        # Server encryption level

        for n in enc_levels.keys():
            if enc_levels[n][1]:
                server_encryption_level.append(enc_levels[n][0])

        logger.debug('RDP encryption level complete')

    output = {
        "supported_encryption_protocols": supported_encryption_protocols,
        "unsupported_encryption_protocols": unsupported_encryption_protocols,
        "error_messages": error_messages_out,
        "supported_encryption_methods": supported_encryption_methods,
        "unsupported_encryption_methods": unsupported_encryption_methods,
        "server_encryption_level": server_encryption_level
    }

    return output
