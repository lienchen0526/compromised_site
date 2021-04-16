# MITMProxy Compromised Website Simulation

## Tested Environment
Successfully run on:
    - Ubuntu 18.04
    - Kali Linux
We will keep developing windows version. But currently we only support Ubuntu.

## Introduction
This example show how to use MITMProxy to simulate compromised website. A compromised website may be insertd some unexpected html nodes (script, iframe...) with remote source to adversary controlled C&C site. To simulate the attack, we use man in the middle attack on client side to achieve similar effect on browser visibility. The proxy will intercept response and modify the html content in a http flow. The modification can be a html node insertion.

## Usage
First of all, you need to have docker daemon, and docker-compose. And make sure the machine can connect to internet.

### Simple Run
Using `docker-compose up` can easily run the proxy server. If you want to modify the port mapped to host, you can modify the content in `docker-compose.yml` from
```.yml
port:
    - "8080:8080"
    - "8081:8081"
```
to
```.yml
port:
    - "<what_ever>:8080"
    - "<port_you_want>:8081"
```

### First Time Run
The first time you run the proxy server, certificate will be generated in `cert` directory. You must add certificate to your browser (Simulated victim). And you have to enable proxy on the browser or computer, setting the proxy server to the host running the container.

### Action when Recieve the 

### Known Issue
1. Different attack modules can not use the same set of (url, method). It may cause unexpected behavior. 
2. The only supported landing method is "injection", which means inject a custom node into landing page.