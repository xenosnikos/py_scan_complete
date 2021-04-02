import multiprocessing

bind = "0.0.0.0:5000"
timeout = 900000000
raw_env = [
    "DEBUG=False",
    "FLASK_ENV=production",
    "FLASK_APP=main.py",
    "API_KEY=94HCy8U2a5sIO98l_hwvnbSOg9n8IKqtYyAa3amhjd8",
    "API_KEY_THREAT_INTELLIGENCE=at_0JzZZmTFtP1Lhz0RPkYE5KCEP7csM",
    "MONGO_CONN=mongodb+srv://stage:2rHOWa6oIFu0ckLG@cluster0.o5uwc.mongodb.net/test?retryWrites=true&w=majority",
    "REDIS_CONN_STRING=rediss://default:kzodr4urcjdpew09@pyscan-redis-stage-do-user-8532994-0.b.db.ondigitalocean.com"
    ":25061",
    "API_KEY_VIEW_DNS=b8a855fbba7483b74948d6089b9744f8701319bb",
    "API_KEY_WHOIS_XML=at_kn7G0qh3FLqaSpjYNDuYX6eZ1kf9h",
    "MAX_THREADS=1500"
]
