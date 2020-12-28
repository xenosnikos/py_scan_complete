FROM tiangolo/meinheld-gunicorn-flask:python3.8
COPY ./requirements.txt /app/requirements.txt
WORKDIR /app
ADD auth.py /app/auth.py
ADD history.py /app/history.py
ADD main.py /app/main.py
ADD port_scan.py /app/port_scan.py
ADD port_scan_rec.py /app/port_scan_rec.py
ADD port_scan_result.py /app/port_scan_result.py
ADD refresh.py /app/refresh.py
ADD verify.py /app/verify.py
ADD mongo_string.txt /app/mongo_string.txt
ADD secret_key.txt /app/secret_key.txt
RUN pip install -r requirements.txt
ENTRYPOINT [ "python" ]
CMD [ "main.py" ]