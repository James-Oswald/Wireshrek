# Wireshrek
Wireshrek is a simple wireshark like application written in python using scapy and tkinter.

## Goal
Wireshrek is not designed to capture and record all network traffic like wireshark. Rather, its meant to provide a visual represnation of network trafic that can be kept open on a second monitor 

## Dependencies
Wireshrek was built in Python using [scapy](https://scapy.net/) and [tkinter](https://docs.python.org/3/library/tkinter.html). It was developed on Windows 10 and thus scapy requires [npcap](https://nmap.org/npcap/) to function. The application has not been tested on Linux or Mac but as long as scapy has the ability to capture packets, it should work.