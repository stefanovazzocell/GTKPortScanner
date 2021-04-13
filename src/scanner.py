from multiprocessing import Process, Queue, cpu_count
from time import sleep
from .portdata import PortData

import random

##
# Constants
##

LIMITS = {
    "cpu_mult": 2,
    "cpu_min": 2,
    "cpu_max": 32,
    "worker_delay": 0.01,
    "tcp": True,
    "tcp_msg": True,
    "tcp_sock_timeout": 4,
    "tcp_ip_timeout": 4,
    "tcp_sock_msg_timeout": 5,
    "tcp_retries": 2,
    "tcp_retry_delay": 0.05,
    "udp": True,
    "udp_sock_timeout": 2,
    "udp_ip_timeout": 2,
    "udp_retries": 3,
    "udp_retry_delay": 0.1,
}
LIMITS_FASTSCAN = {
    "cpu_mult": 64,
    "cpu_min": 128,
    "cpu_max": 420,
    "worker_delay": 0.001,
    "tcp": True,
    "tcp_msg": True,
    "tcp_sock_timeout": 0.5,
    "tcp_ip_timeout": 1,
    "tcp_ip_timeout": 1,
    "tcp_sock_msg_timeout": 0.6,
    "tcp_retries": 2,
    "tcp_retry_delay": 0.001,
    "udp": True,
    "udp_sock_timeout": 1,
    "udp_ip_timeout": 1,
    "udp_retries": 2,
    "udp_retry_delay": 0.001,
}

##
# Main
##


def scan_init(target_ip, port_start, port_end, fast_scan, active_probing):
    limits = dict(LIMITS)
    if fast_scan:
        limits = dict(LIMITS_FASTSCAN)
    if active_probing == False:
        limits["udp"] = False
        limits["tcp_msg"] = False
    done_queue = Queue()
    todo_queue = Queue()
    ports = []
    for port in range(port_start, port_end + 1):
        ports.append(port)
    random.shuffle(ports)
    for port in ports:
        todo_queue.put(port)
    workers_count = min(max(min(cpu_count() * limits["cpu_mult"], limits["cpu_max"]), limits["cpu_min"]), len(ports))
    print(f'Spawning {workers_count} workers')
    workers = []
    for i in range(workers_count):
        proc = Process(target=worker, args=(target_ip, todo_queue, done_queue, limits))
        proc.start()
        workers.append(proc)
    return done_queue, workers_count, todo_queue, workers


def worker(target_ip, todo_queue, done_queue, limits):
    while True:
        next_port = 0
        try:
            next_port = todo_queue.get(block=True, timeout=0.005)
        except:
            return
        if limits["worker_delay"] > 0:
            sleep(limits["worker_delay"])
        data = PortData(target_ip, next_port)
        data.scan(limits)
        done_queue.put((next_port, data))
