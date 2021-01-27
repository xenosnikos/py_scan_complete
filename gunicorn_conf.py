import multiprocessing

bind = "0.0.0.0:5000"
backlog = 2048

workers = multiprocessing.cpu_count() * 2 + 1
worker_connections = 1000
