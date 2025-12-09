FROM python:latest

WORKDIR /scripts


RUN pip install --no-cache-dir \
    requests \
    urllib3 \
    certifi \
    python-hosts \
    graphviz \
    python-dotenv