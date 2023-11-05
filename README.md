# Client-Broker Architecture based Automotive Protocol

## Description

Our proposed solution is an in-vehicle communication protocol with a broker-client architecture designed for effective data transfer. 
It offers centralized message routing, device authentication, support for custom data types, error handling, and topic management. 
This customized protocol is advantageous for telematics, fleet management, data logging, and monitoring in vehicles. 
It provides a flexible, secure and cost-effective alternative to standardized protocols like MQTT, tailored to the unique needs of in-vehicle communication.


## Getting Started

### Dependencies

List any dependencies that are required for this project. This could include libraries, frameworks, and any other software your project depends on.

- Python 3.x
- pip
- virtualenv

### Installing

Provide step by step series of examples that tell you how to get a development environment running.

```bash
pip install -r requirements.txt
```

### Executing program
#### Using Docker
- Build the docker images
```bash
docker build -t broker:latest .
docker build -t client:latest -f Dockerfile.client .
```
- Run the docker containers
```bash
docker run broker
docker run client
```

#### Using Python
- Run the broker
```bash
sudo venv/bin/python3 broker/main.py
```
- Run the client
```bash
sudo venv/bin/python3 client/main.py
```

#### Some fix
- In case packects are not being sent, need to adjust the ip address in the the `__name__ == __main__` section of the `main.py` file in both the broker and client directories.
- Follow the data type mapping and method mapping mentioned in the protocol folder.

