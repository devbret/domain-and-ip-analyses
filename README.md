# Domain And IP Address Analyses

Comprehensive network intelligence and reconnaissance tool for gathering detailed technical metadata about domain names and IP addresses.

## Application Overview

When analyzing a domain, this application collects critical information such as WHOIS registration data, DNS records, SSL certificate details and email security configurations. For web-based targets, it conducts basic performance checks and captures a preview of the website's content to provide an overview of a domain's digital footprint.

For IP-based analysis, the tool performs deeper infrastructure reconnaissance by conducting multi-threaded port scans, retrieving geolocation data and performing reverse DNS lookups. It also interacts with network protocols to capture service banners, verify RDAP information and measure ping latency.

All gathered data is organized and exported as a JSON file, making it an effective tool for security auditing or automated reconnaissance gathering.

## Basic Setup Instructions

Below are instructions for how to install and use this app on a Linux machine.

### Programs Needed

- [Git](https://git-scm.com/downloads)

- [Python](https://www.python.org/downloads/)

### Steps

1. Install the above programs

2. Open a terminal

3. Clone this repository: `git clone git@github.com:devbret/domain-and-ip-analyses.git`

4. Navigate to the repo's directory: `cd domain-and-ip-analyses`

5. Create a virtual environment: `python3 -m venv venv`

6. Activate the virtual environment: `source venv/bin/activate`

7. Install the needed dependencies: `pip install -r requirements.txt`

8. Run the script: `python3 app.py --domain example.com --ip 8.8.8.8`

9. Deactivate the virtual environment: `deactivate`

## Other Considerations

This project repo is intended to demonstrate an ability to do the following:

- Perform domain analysis by gathering WHOIS data, DNS records, SSL certificates and other information

- Conduct reconnaissance on IP addresses through port scanning, geolocation mapping and banner grabbing

- Automate the collection of network metadata into structured JSON reports for analysis

- Serve as a powerful reconnaissance tool for mapping the digital footprint of both domains and IP addresses

If you have any questions or would like to collaborate, please reach out either on GitHub or via [my website](https://bretbernhoft.com/).
