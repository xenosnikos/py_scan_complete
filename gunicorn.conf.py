import multiprocessing


bind="0.0.0.0:5000"
timeout=900
raw_env=[
"DEBUG=False",
"FLASK_ENV=production",
"FLASK_APP=main.py",
"API_KEY=94HCy8U2a5sIO98l_hwvnbSOg9n8IKqtYyAa3amhjd8",
"API_KEY_THREAT_INTELLIGENCE=at_0JzZZmTFtP1Lhz0RPkYE5KCEP7csM",
"MONGO_CONN=mongodb://Mongo:TVgmvu26M4gKQv9uAtc42KNPEBzqC@olympus.securityvue.com:27017/?authSource=admin&readPreference=primary",
"REDIS_HOST=10.1.1.13",
"REDIS_PORT=6379",
"API_KEY_VIEW_DNS=b8a855fbba7483b74948d6089b9744f8701319bb",
"API_KEY_WHOIS_XML=at_kn7G0qh3FLqaSpjYNDuYX6eZ1kf9h",
"MAX_THREADS=1500"
]
