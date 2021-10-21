FROM python:3.9

WORKDIR /worker
COPY . Umbrella
RUN pip install --no-cache-dir -r Umbrella/requirements.txt
ENTRYPOINT Umbrella/Umbrella.py
