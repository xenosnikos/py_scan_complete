from bson import json_util
from bson.objectid import ObjectId
import pika
import pymongo
import sslyze
import time

client = pymongo.MongoClient(open('mongo_string.txt').read())
db = client.test

connection = pika.BlockingConnection(
    pika.ConnectionParameters(host='rabbitmq', heartbeat=0))
# heartbeat is set to 0 because of an existing bug with RabbitMQ & Pika, stopping heartbeats will cause message loss if
# receiver goes down https://github.com/albertomr86/python-logging-rabbitmq/issues/17
channel = connection.channel()

channel.queue_declare(queue='sslyze_queue', durable=True)


def ssl_checks(value):
    server = sslyze.ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(value, 443)

    try:
        server_info = sslyze.ServerConnectivityTester().perform(server)
    except:
        # Could not connect to the server; abort
        print(f"Error connecting to {server}")

    print(f"Connectivity testing completed: {server}")

    scanner = sslyze.Scanner()
    server_scan_req = sslyze.ServerScanRequest(
        server_info=server_info, scan_commands={sslyze.ScanCommand.CERTIFICATE_INFO,
                                                sslyze.ScanCommand.SSL_2_0_CIPHER_SUITES,
                                                sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES,
                                                sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES,
                                                sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES,
                                                sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES,
                                                sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES,
                                                sslyze.ScanCommand.TLS_COMPRESSION,
                                                sslyze.ScanCommand.TLS_1_3_EARLY_DATA,
                                                sslyze.ScanCommand.OPENSSL_CCS_INJECTION,
                                                sslyze.ScanCommand.TLS_FALLBACK_SCSV,
                                                sslyze.ScanCommand.HEARTBLEED,
                                                sslyze.ScanCommand.ROBOT,
                                                sslyze.ScanCommand.SESSION_RENEGOTIATION,
                                                sslyze.ScanCommand.SESSION_RESUMPTION,
                                                sslyze.ScanCommand.SESSION_RESUMPTION_RATE,
                                                sslyze.ScanCommand.HTTP_HEADERS,
                                                sslyze.ScanCommand.ELLIPTIC_CURVES},
    )
    scanner.queue_scan(server_scan_req)
    obj = dict()
    time.sleep(120)
    for server_scan_result in scanner.get_results():
        print(f"\nResults for {server_scan_result.server_info.server_location.hostname}:")
        print(server_scan_result.scan_commands_results)

        # Certificate info results
        try:
            certinfo_result = server_scan_result.scan_commands_results['certificate_info']
            obj['certificate'] = {
                'certificateValidityStart': certinfo_result.certificate_deployments[0].verified_certificate_chain[
                    0].not_valid_before.strftime('%m/%d/%Y, %H:%M:%S'),
                'certificateExpiry': certinfo_result.certificate_deployments[0].verified_certificate_chain[
                    0].not_valid_after.strftime('%m/%d/%Y, %H:%M:%S'),
                'hostnameMatchesCertificate': certinfo_result.certificate_deployments[
                    0].leaf_certificate_subject_matches_hostname
            }
        except KeyError:
            print('Certificate Info not found in ', server_scan_result.scan_commands_results['certificate_info'])

        # SSL 2.0 results
        try:
            ssl2_result = server_scan_result.scan_commands_results['ssl_2_0_cipher_suites']
            obj['ssl2.0'] = {'ssl2.0CipherSuitesAccepted': len(ssl2_result.accepted_cipher_suites),
                             'ssl2.0CipherSuitesRejected': len(ssl2_result.rejected_cipher_suites),
                             'description': 'SSL 2.0 is a version of the SSL/TLS security protocols. It was released in '
                                            'February 1995, but due to security flaws was superseded by SSL 3.0 in 1996',
                             'deprecation': 2011}
        except KeyError:
            print("SSL 2.0 not found in ", server_scan_result.scan_commands_results['ssl_2_0_cipher_suites'])

        # SSL 3.0 results
        ssl3_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES]
        obj['ssl3.0'] = {'ssl3.0CipherSuitesAccepted': len(ssl3_result.accepted_cipher_suites),
                         'ssl3.0CipherSuitesRejected': len(ssl3_result.rejected_cipher_suites),
                         'description': "SSL 3.0 is an encryption standard that's used to secure Web traffic using "
                                        "the HTTPS method. It has a flaw that could allow an attacker to decrypt "
                                        "information, such as authentication cookies, according to Microsoft",
                         'deprecation': 2011}
        print("\nAccepted cipher suites for SSL 3.0:")
        for accepted_cipher_suite in ssl3_result.accepted_cipher_suites:
            print(f"* {accepted_cipher_suite.cipher_suite.name}")

        # TLS 1.0 results
        tls10_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES]
        obj['tls1.0'] = {'tls1.0CipherSuitesAccepted': len(tls10_result.accepted_cipher_suites),
                         'tls1.0CipherSuitesRejected': len(tls10_result.rejected_cipher_suites),
                         'description': "TLS 1.0 is a security protocol first defined in 1999 for establishing "
                                        "encryption channels over computer networks. Microsoft has supported this "
                                        "protocol since Windows XP/Server 2003",
                         'deprecation': "The PCI Council suggested that organizations migrate from TLS 1.0 to TLS 1.1 "
                                        "or higher before June 30, 2018"}
        print("\nAccepted cipher suites for TLS 1.0:")
        for accepted_cipher_suite in tls10_result.accepted_cipher_suites:
            print(f"* {accepted_cipher_suite.cipher_suite.name}")

        # TLS 1.1 results
        tls11_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES]
        obj['tls1.1'] = {'tls1.1CipherSuitesAccepted': len(tls11_result.accepted_cipher_suites),
                         'tls1.1CipherSuitesRejected': len(tls11_result.rejected_cipher_suites),
                         'description': "TLS 1.1 was defined in RFC 4346 in April 2006, it is an update from TLS "
                                        "version 1.0 and includes protection against CBC attacks",
                         'deprecation': "Google, Microsoft, Apple, and Mozilla have all announced that their browsers "
                                        "will no longer support TLS 1.1 as of March 2020"}
        print("\nAccepted cipher suites for TLS 1.0:")
        print("\nAccepted cipher suites for TLS 1.1:")
        for accepted_cipher_suite in tls11_result.accepted_cipher_suites:
            print(f"* {accepted_cipher_suite.cipher_suite.name}")

        # TLS 1.2 results
        tls12_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES]
        obj['tls1.2'] = {'tls1.2CipherSuitesAccepted': len(tls12_result.accepted_cipher_suites),
                         'tls1.2CipherSuitesRejected': len(tls12_result.rejected_cipher_suites),
                         'description': "TLS 1.2 is more secure than the previous cryptographic protocols such as SSL "
                                        "2.0, SSL 3.0, TLS 1.0, and TLS 1.1. Essentially, TLS 1.2 keeps data being "
                                        "transferred across the network more secure",
                         'deprecation': "TLS 1.2 has been mandatory as of March 2020 and has been a standard ever "
                                        "since, deprecation date for TLS 1.2 is unknown"}
        print("\nAccepted cipher suites for TLS 1.2:")
        for accepted_cipher_suite in tls12_result.accepted_cipher_suites:
            print(f"* {accepted_cipher_suite.cipher_suite.name}")

        # TLS 1.3 results
        tls13_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES]
        obj['tls1.3'] = {'tls1.3CipherSuitesAccepted': len(tls13_result.accepted_cipher_suites),
                         'tls1.3CipherSuitesRejected': len(tls13_result.rejected_cipher_suites),
                         'description': "TLS 1.3 is a new encryption protocol update that is both faster (reducing "
                                        "HTTPS overhead) and more secure than TLS 1.2",
                         'deprecation': "Unknown"}
        print("\nAccepted cipher suites for TLS 1.3:")
        for accepted_cipher_suite in tls13_result.accepted_cipher_suites:
            print(f"* {accepted_cipher_suite.cipher_suite.name}")

        # TLS Compression
        tls_compression_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_COMPRESSION]
        obj['tlsCompression'] = {'supportsCompression': tls_compression_result.supports_compression,
                                 'description': 'The Compression Ratio Info-leak Made Easy (CRIME) vulnerability '
                                                'affects TLS compression on older browsers '
                                 }
        print("\nAccepted TLS Compression:")
        print(f"* {tls_compression_result.supports_compression}")

        # TLS 1.3 Early Data results
        tls13ed_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_3_EARLY_DATA]
        obj['tls1.3EarlyData'] = {'supportsEarlyData': tls13ed_result.supports_early_data,
                                  'description': 'Early data allows a client to send data to a server in the first '
                                                 'round trip of a connection, without waiting for the TLS handshake '
                                                 'to complete if the client has spoken to the same server recently '
                                  }
        print("\nAccepted TLS 1.3 Early Data:")
        print(f"* {tls13ed_result.supports_early_data}")

        # Open SSL CSS Injection results
        openssl_css_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.OPENSSL_CCS_INJECTION]
        obj['openSslCssInjection'] = {'supportsCSSInjection': openssl_css_result.is_vulnerable_to_ccs_injection,
                                      'description': 'The CCS Injection Vulnerability (CVE-2014-0224) is a serious '
                                                     'vulnerability in the popular OpenSSL cryptographic software '
                                                     'library. OpenSSL is an implementation of the SSL/TLS encryption '
                                                     'protocol used to protect the privacy of Internet communication '
                                      }
        print("\nAccepted Open SSL CSS Injection:")
        print(f"* {openssl_css_result.is_vulnerable_to_ccs_injection}")

        # TLS fallback SCSV results
        tls_fallback_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_FALLBACK_SCSV]
        obj['tlsFallbackScsvResult'] = {'supportsTlsFallback': tls_fallback_result.supports_fallback_scsv,
                                        'description': 'TLS Signaling Cipher Suite Value (SCSV) can be used to guard '
                                                       'against protocol downgrade attacks. The extension can be '
                                                       'useful for clients like web browsers, which fall back to a '
                                                       'lesser protocol version if attempts to use a higher protocol '
                                                       'version fail '
                                        }
        print("\nAccepted TLS fallback:")
        print(f"* {tls_fallback_result.supports_fallback_scsv}")

        # Heartbleed Vulnerability
        heartbleed_vulnerability_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.HEARTBLEED]
        obj['heartbleedVulnerabilityResult'] = {
            'supportsHeartbleed': heartbleed_vulnerability_result.is_vulnerable_to_heartbleed,
            'description': 'The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic '
                           'software library. This weakness allows stealing the information protected, under normal '
                           'conditions, by the SSL/TLS encryption used to secure the Internet '
        }
        print("\nIs Vulnerable to HeartBleed:")
        print(f"* {heartbleed_vulnerability_result.is_vulnerable_to_heartbleed}")

        # ROBOT Vulnerability
        robot_vulnerability_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.ROBOT]
        results = {
            1: "1 - The server is vulnerable but the attack would take too long",
            2: "2 - The server is vulnerable and real attacks are feasible",
            3: "3 - The server supports RSA cipher suites but does not act as an oracle",
            4: "4 - The server does not supports RSA cipher suites",
            5: "5 - Could not determine whether the server is vulnerable or not"
        }
        obj['robotVulnerabilityResult'] = {
            'message': heartbleed_vulnerability_result.is_vulnerable_to_heartbleed,
            'description': 'ROBOT allows an attacker to obtain the RSA key necessary to decrypt TLS traffic under '
                           'certain conditions.  An attacker could exploit this vulnerability by sending crafted TLS '
                           'messages to the device, which would act as an oracle and allow the attacker to carry out '
                           'a chosen-ciphertext attack '
        }
        print("\nIs Vulnerable to ROBOT:")
        print(f"* {results[robot_vulnerability_result.robot_result.value]}")

        # Session Renegotiation
        session_renegotiation_result = server_scan_result.scan_commands_results[
            sslyze.ScanCommand.SESSION_RENEGOTIATION]
        obj['sessionRenegotiationResult'] = {
            'supportsSecureRenegotiation': session_renegotiation_result.supports_secure_renegotiation,
            'description': 'Starting a new handshake negotiation inside of an existing secure session is called '
                           'renegotiation. The application layer might not be aware that a secure session is '
                           'renegotiated at the request of a peer '
        }

        # Session Resumption
        session_resumption_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.SESSION_RESUMPTION]
        obj['sessionResumptionResult'] = {
            'supportsSessionIDResumption': session_resumption_result.is_session_id_resumption_supported,
            'attemptedSessionIDResumptions': session_resumption_result.attempted_session_id_resumptions_count,
            'successfulSessionIDResumptions': session_resumption_result.successful_session_id_resumptions_count,
            'supportsTlsTicketResumption': session_resumption_result.is_tls_ticket_resumption_supported,
            'description': 'TLS Session Resumption provides a mechanism to resume or share the same negotiated secret '
                           'key data between multiple connections. Session resumption is an important optimization '
                           'deployment. The abbreviated handshake eliminates a full roundtrip of latency and '
                           'significantly reduces computational costs for both sides '
        }
        print("\nAttempted Session ID resumptions:")
        print(f"* {session_resumption_result.attempted_session_id_resumptions_count}")
        print("\nSuccessful Session ID resumptions:")
        print(f"* {session_resumption_result.successful_session_id_resumptions_count}")
        print("\nTLS ticket resumption supported:")
        print(f"* {session_resumption_result.is_tls_ticket_resumption_supported}")
        print("\nSession ID resumption supported:")
        print(f"* {session_resumption_result.is_session_id_resumption_supported}")

        # Session Resumption Rate
        session_resumption_rate_result = server_scan_result.scan_commands_results[
            sslyze.ScanCommand.SESSION_RESUMPTION_RATE]
        obj['sessionResumptionRateResult'] = {
            'attemptedSessionIDResumptions': session_resumption_rate_result.attempted_session_id_resumptions_count,
            'successfulSessionIDResumptions': session_resumption_rate_result.successful_session_id_resumptions_count,
            'description': 'TLS Session Resumption rate provides an understanding of rate at which sessions can be '
                           'resumed '
        }
        print("\nAttempted Session ID resumptions:")
        print(f"* {session_resumption_rate_result.attempted_session_id_resumptions_count}")
        print("\nSuccessful Session ID resumptions:")
        print(f"* {session_resumption_rate_result.successful_session_id_resumptions_count}")

        # HTTP Security Headers
        http_security_rate_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.HTTP_HEADERS]
        obj['httpSecurityHeaders'] = {
            'strictTransportSecurityHeader': http_security_rate_result.strict_transport_security_header,
            'publicKeyPinsHeader': http_security_rate_result.public_key_pins_header,
            'publicKeyPinsReportOnlyHeader': http_security_rate_result.public_key_pins_report_only_header,
            'expectCTHeader': http_security_rate_result.expect_ct_header,
            'description': 'HTTP security headers are a fundamental part of website security. Upon implementation, '
                           'they protect against the types of attacks that a site is most likely to come across. '
                           'These headers protect against XSS, code injection, clickjacking, etc '
        }
        print("\nStrict transport security header:")
        print(f"* {http_security_rate_result.strict_transport_security_header}")
        print("\nPublic key pins header:")
        print(f"* {http_security_rate_result.public_key_pins_header}")
        print("\nPublic key pins report only header:")
        print(f"* {http_security_rate_result.public_key_pins_report_only_header}")
        print("\nExpect CT header:")
        print(f"* {http_security_rate_result.expect_ct_header}")

        # Supported Elliptic Curves
        supported_elliptic_curves_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.ELLIPTIC_CURVES]
        obj['supportedEllipticCurves'] = {
            'supportsECDHKeyExchange': supported_elliptic_curves_result.supports_ecdh_key_exchange,
            'supportedCurves': len(supported_elliptic_curves_result.supported_curves),
            'rejectedCurves': len(supported_elliptic_curves_result.rejected_curves),
            'description': 'Elliptic-curve cryptography is an approach to public-key cryptography based on the '
                           'algebraic structure of elliptic curves over finite fields. ECC allows smaller keys '
                           'compared to non-EC cryptography to provide equivalent security '
        }
        print("\nSupports ECDH key exchange:")
        print(f"* {supported_elliptic_curves_result.supports_ecdh_key_exchange}")
        print("\nSupported Curves:")
        print(f"* {len(supported_elliptic_curves_result.supported_curves)}")
        print("\nRejected Curves:")
        print(f"* {len(supported_elliptic_curves_result.rejected_curves)}")

        return obj


def callback(ch, method, properties, body):
    print(" [x] Received %r" % body.decode())
    json_loaded = json_util.loads(body)
    ip = json_loaded['ip']
    value = json_loaded['value']
    item_id = json_loaded['scan_id']

    print(ip, value, item_id)

    obj = ssl_checks(ip)

    db.scans.find_one_and_update({"_id": ObjectId(item_id)}, {"$set": {'SSL/TLSTestResults': obj}})
    print(" [x] Done")
    ch.basic_ack(delivery_tag=method.delivery_tag)


channel.basic_qos(prefetch_count=1)
channel.basic_consume(queue='sslyze_queue', on_message_callback=callback)
channel.start_consuming()
