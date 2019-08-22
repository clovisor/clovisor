FROM python:3

RUN pip install jaeger-client

RUN pip install pymongo

RUN pip install requests

RUN pip install redis

COPY . .

CMD ["python", "./correlation.py"]
