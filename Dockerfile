FROM python:latest

WORKDIR /scripts

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt