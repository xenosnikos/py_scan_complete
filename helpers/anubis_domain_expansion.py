"""The target command."""
import os
import re
import socket
from queue import Queue
from urllib.parse import urlsplit
import sys
import threading
from io import StringIO

from anubis.scanners.anubis_db import search_anubisdb, send_to_anubisdb
from anubis.scanners.crt import search_crtsh
from anubis.scanners.dnsdumpster import search_dnsdumpster
from anubis.scanners.dnssec import dnssecc_subdomain_enum
from anubis.scanners.hackertarget import subdomain_hackertarget
from anubis.scanners.netcraft import search_netcraft
from anubis.scanners.nmap import scan_host
from anubis.scanners.shodan import search_shodan
from anubis.scanners.ssl import search_subject_alt_name
from anubis.scanners.zonetransfer import dns_zonetransfer
from anubis.utils.ColorPrint import ColorPrint
from anubis.commands.base import Base
from helpers import logs, utils, rdp_check_ciphers, queue_to_db


from anubis.utils.search_worker import SearchWorker

recursive_sub_domains = set()


def recursive_search(self):
    print("Starting recursive search - warning, might take a long time")
    domains = self.clean_domains(self.domains)
    domains_unique = set(domains)
    num_workers = 10

    if self.options["--queue-workers"]:
        num_workers = int(self.options["--queue-workers"])

    stopper = threading.Event()
    url_queue = Queue()
    for domain in domains_unique:
        url_queue.put(domain)

    # we need to keep track of the workers but not start them yet
    workers = [SearchWorker(url_queue, self.domains, stopper, self) for _ in
               range(num_workers)]

    # create our signal handler and connect it
    # handler = SignalHandler(stopper, workers)
    # signal.signal(signal.SIGINT, handler)

    if not self.options["--verbose"]:
        # catch stdout and replace it with our own
        self.stdout, sys.stdout = sys.stdout, StringIO()

    # start the threads!
    for worker in workers:
        worker.start()

    # wait for the queue to empty
    url_queue.join()

    sys.stdout = self.stdout


class Target(Base):
    """Main enumeration module"""
    domains = list()
    ip = str()
    dedupe = set()

    stdout = sys.stdout

    def handle_exception(self, e, message=""):
        if self.options["--verbose"]:
            print(e)
        if message:
            ColorPrint.red(message)

    def init(self):
        if self.options["FILE"]:
            full_path = os.path.join(os.getcwd(), self.options["FILE"])
            with open(full_path) as file:
                self.options["TARGET"] = list(filter(None, file.read().split('\n')))
        else:
            self.options["TARGET"] = list(
                filter(None, self.options["TARGET"].split(",")))
        # Clean up targets
        for i in range(len(self.options["TARGET"])):
            url = self.options["TARGET"][i]
            # Inject protocol if not there
            if not re.match(r'http(s?):', url):
                url = 'http://' + url

            parsed = urlsplit(url)
            host = parsed.netloc

            self.options["TARGET"][i] = host

            try:
                domain_str = socket.gethostbyname(host)
                ColorPrint.green(f"Searching for subdomains for {domain_str} ({host})")
            except Exception as e:
                self.handle_exception(e,
                                      "Error connecting to target! Make sure you spelled it correctly and it is a "
                                      "resolvable address")
                raise e

    def run(self):
        # Retrieve IP of target and run initial configurations
        self.init()
        # If multiple targets, create scans for each
        for i in range(len(self.options["TARGET"])):
            # Default scans that run every time
            target = self.options["TARGET"][i]
            ColorPrint.green(f"Working on target: {target}")
            threads = [threading.Thread(target=dns_zonetransfer, args=(self, target)),
                       threading.Thread(target=subdomain_hackertarget,
                                        args=(self, target)),
                       threading.Thread(target=search_subject_alt_name,
                                        args=(self, target)),
                       threading.Thread(target=search_netcraft, args=(self, target)),
                       threading.Thread(target=search_crtsh, args=(self, target)),
                       threading.Thread(target=search_dnsdumpster,
                                        args=(self, target)),
                       threading.Thread(target=search_anubisdb, args=(self, target))]

            # Additional options - shodan.io scan
            if self.options["--additional-info"]:
                threads.append(threading.Thread(target=search_shodan, args=(self,)))

            # Additional options - nmap scan of dnssec script and a host/port scan
            if self.options["--with-nmap"]:
                threads.append(
                    threading.Thread(target=dnssecc_subdomain_enum, args=(self, target)))
                threads.append(threading.Thread(target=scan_host, args=(self,)))

            # Start all threads and wait for them to finish
            for x in threads:
                x.start()

            for x in threads:
                x.join()

            # Run a recursive search on each subdomain - rarely useful, but nice to have
            # just in case
            if self.options["--recursive"]:
                recursive_search(self)

            # remove duplicates and clean up
            self.domains = self.clean_domains(self.domains)
            self.dedupe = set(self.domains)

            print("Found", len(self.dedupe), "subdomains")
            print("----------------")

            sub_domains = []

            for domain in self.dedupe:
                cleaned_domain = domain.strip()
                ColorPrint.green(cleaned_domain)
                sub_domains.append(domain)

            if self.options["--send-to-anubis-db"]:
                send_to_anubisdb(self, [target])
            # reset per domain
            self.domains = list()
            return sub_domains

    @staticmethod
    def clean_domains(domains):
        cleaned = []
        for subdomain in domains:
            subdomain = subdomain.lower()
            if subdomain.find("//") != -1:
                subdomain = subdomain[subdomain.find("//") + 2:]
            # Some pkey return instances like example.com. - remove the final .
            if subdomain.endswith('.'):
                subdomain = subdomain[:-1]
            # sometimes we'll get something like /www.example.com
            if subdomain[0] in ["\\", ".", "/", "#", "$", "%"]:
                subdomain = subdomain[1:]
            # If it's an email address, only take the domain part
            if "@" in subdomain:
                subdomain = subdomain.split("@")
                # If it's an actual email like mail@example.com, take example.com
                if len(subdomain) > 1:
                    subdomain = subdomain[1]
                else:
                    # If for some reason it's example.com@, take example.com
                    subdomain = subdomain[0]

            cleaned.append(subdomain.strip())
        return cleaned


def anubis_scan(scan, recursive):
    options = {'--additional-info': False,
               '--file': False,
               '--help': False,
               '--ip': False,
               '--output': 0,
               '--overwrite-nmap-scan': None,
               '--queue-workers': 10,
               '--recursive': False,
               '--send-to-anubis-db': True,
               '--silent': False,
               '--ssl': True,
               '--target': True,
               '--verbose': False,
               '--version': False,
               '--with-nmap': False,
               '-b': False,
               'FILE': None,
               'FILENAME': None,
               'TARGET': scan['value']}

    command = Target(options)
    sub_domains = command.run()
    if recursive:
        for each in sub_domains:
            if each.endswith(scan['value']):
                recursive_sub_domains.add(each)
    else:
        return sub_domains


def threader():
    while True:
        worker = q.get()
        anubis_scan(worker, True)
        q.task_done()
        if q.empty():
            break


def main_scan(scan):
    scan['status'] = 'running'
    utils.mark_db_request(scan, 'domain_expansion')

    level1_data = set(anubis_scan(scan, False))

    cleaned_up_data = [x for x in level1_data if x.endswith(scan['value']) and not x.startswith('*')]

    return cleaned_up_data


q = Queue()
