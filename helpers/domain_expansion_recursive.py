from queue import Queue
import threading

from helpers import anubis_domain_expansion
from helpers import sublist3r2

sub_domains_latest = set()
sub_domains_total = set()


def scan(data):
    global sub_domains
    output_sublistr = sublist3r2.main(domain=data['value'], engines=None, ports=None, threads=0,
                                      verbose=False, enable_bruteforce=False, savefile=None, silent=False)

    output_anubis = anubis_domain_expansion.main_scan(data)

    level_out = set(output_sublistr + output_anubis)


def threader():
    while True:
        worker = q.get()
        scan(worker)
        q.task_done()
        if q.empty():
            break


def recursive_scan(data):
    global sub_domains_total
    global sub_domains_latest
    output_sublistr = sublist3r2.main(domain=data['value'], engines=None, ports=None, threads=0,
                                      verbose=False, enable_bruteforce=False, savefile=None, silent=False)

    output_anubis = anubis_domain_expansion.main_scan(data)

    level_out = set(output_sublistr + output_anubis)

    if len(level_out) != 0:

        sub_domains_total |= level_out

        for worker in level_out:
            data['value'] = worker
            q.put(data)

        print(f"Worker puts done, {q.qsize()}")

        for x in range(len(level_out)):
            t = threading.Thread(target=threader, daemon=False)
            t.start()

        print(f"Threads created")

        q.join()

    else:
        sub_domains_latest = set()
        sub_domains_total = set()
        return sub_domains


q = Queue()
