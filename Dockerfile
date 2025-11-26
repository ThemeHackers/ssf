FROM python:3.11-slim

WORKDIR /app


COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt


COPY . /app


RUN mkdir -p poc


ENTRYPOINT ["python3", "ssf.py"]
