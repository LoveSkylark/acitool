FROM python:latest

ARG VERIFY_SSL=false
ENV VERIFY_SSL=${VERIFY_SSL}

WORKDIR /scripts

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

