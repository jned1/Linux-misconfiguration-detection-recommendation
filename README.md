# Linux Security Monitoring and Hardening System

## Project Overview

This project implements a Linux-based security monitoring and system hardening framework designed to detect suspicious activities, analyze authentication logs, and automate defensive responses.

The system focuses on real-world Linux environments by collecting and analyzing system logs such as SSH authentication attempts and firewall events. Attack simulations are performed in a controlled virtual environment to generate experimental data.

The primary goal is to enhance system visibility, improve detection accuracy, and reduce response time to potential security threats.

## Objectives

- Monitor Linux authentication logs in real time  
- Detect brute-force login attempts  
- Analyze suspicious IP behavior  
- Implement automated defensive mechanisms  
- Evaluate system effectiveness using experimental data  

## System Architecture

The project consists of the following components:

- Linux Operating System (Ubuntu or Kali Linux)
- Log collection from:
  - /var/log/auth.log
  - /var/log/syslog
  - Firewall logs
- Detection logic (rule-based monitoring)
- Automated response mechanism (e.g., IP blocking using firewall rules)
- Attack simulation environment

## Methodology

1. Configure a Linux virtual machine environment.
2. Enable SSH services and logging mechanisms.
3. Simulate attacks such as brute-force login attempts in a controlled environment.
4. Collect and analyze generated system logs.
5. Apply detection rules to identify suspicious behavior.
6. Trigger automated defensive actions (e.g., blocking malicious IP addresses).
7. Evaluate system performance and detection accuracy.

## Software Requirements

- Linux OS (Ubuntu or Kali Linux)
- Python 3.x
- OpenSSH Server
- Fail2Ban (optional)
- UFW or iptables firewall
- VirtualBox or VMware

## Hardware Requirements

- Minimum 8 GB RAM (recommended)
- Multi-core processor
- At least 50 GB free disk space
- Host machine capable of running virtual machines

## Dataset

This project uses experimentally generated datasets obtained from:

- SSH authentication logs
- System logs
- Firewall logs

Attack data is generated through controlled simulations within a virtual environment to ensure realistic and reproducible results.

## Key Features

- Real-time log monitoring
- Brute-force attack detection
- Automated IP blocking
- Lightweight and modular implementation
- Experimental validation using simulated attacks

## Expected Outcomes

- Improved detection of unauthorized access attempts
- Reduced response time to security threats
- Enhanced understanding of Linux log analysis
- Practical demonstration of system hardening techniques

## Project Category

- Experimental Research
- Automation
- Software Development

## Future Improvements

- Integration of machine learning-based detection
- Web-based dashboard for visualization
- Email or SMS alert system
- Distributed log monitoring support

## Author

jaffar jned
mahmoud bakir
