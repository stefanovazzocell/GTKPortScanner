import socket
from multiprocessing import Process, Queue, cpu_count
from time import sleep
from contextlib import closing
import random


def scan_init(target_ip, port_start, port_end, fast_scan):
    done_queue = Queue()
    todo_queue = Queue()
    ports = []
    for port in range(port_start, port_end + 1):
        ports.append(port)
    random.shuffle(ports)
    for port in ports:
        todo_queue.put(port)
    max_threads = 4
    cpus = cpu_count()
    if fast_scan:
        max_threads = 512
        cpus = 12 * cpus
    workers_count = max(min(cpus, max_threads), 2)
    print(f'Spawning {workers_count} workers')
    workers = []
    for i in range(workers_count):
        proc = Process(target=worker, args=(target_ip, todo_queue, done_queue, fast_scan, ))
        proc.start()
        workers.append(proc)
    return done_queue, workers_count, todo_queue, workers


def worker(target_ip, todo_queue, done_queue, fast_scan, ):
    sock_timeout = 5
    scan_timeout = 0.5
    retry_timeout = 0.1
    if fast_scan:
        sock_timeout  = 0.5
        scan_timeout  = 0.01
        retry_timeout = 0.01
    while True:
        next_port = 0
        try:
            next_port = todo_queue.get(block=True, timeout=0.005)
        except:
            return
        sleep(scan_timeout)
        is_open = check_port(target_ip, next_port, sock_timeout, retry_timeout)
        msg = ""
        if is_open:
            msg = get_message(target_ip, next_port, sock_timeout)
        done_queue.put((next_port, (is_open, msg)))

def check_port(target_ip, next_port, sock_timeout, retry_timeout):
    is_open = False
    for i in range(3):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(sock_timeout)
        if sock.connect_ex((target_ip, next_port)) == 0:
            is_open = True
            sock.close()
            print(f'{next_port} open')
            break
        sleep(retry_timeout)
        sock.close()
    return is_open

def get_message(target_ip, next_port, sock_timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(sock_timeout)
    try:
        sock.connect((target_ip, next_port))
        message = sock.recv(1024)
        sock.close()
        return prep_message(message.decode())
    except:
        pass
    return ""

def prep_message(msg):
    if msg == "":
        return msg
    msg = msg.replace("\r", "\\r")
    msg = msg.replace("\n", "\\n")
    return msg
