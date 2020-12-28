FROM tiangolo/meinheld-gunicorn:python3.8
COPY ./requirements.txt /var/www/requirements.txt
RUN pip install -r /var/www/requirements.txt