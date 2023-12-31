FROM python:3.9
WORKDIR /app
COPY . /app/

RUN apt-get update && apt-get install -y libpcap0.8
RUN pip install -r requirements.txt

EXPOSE 9779
CMD ["python3", "broker/main.py"]