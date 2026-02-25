# Website Domain And IP Address Analyses

A CLI-based domain and IP intelligence tool which performs structured reconnaissance and outputs timestamped JSON reports.

## Overview

Given a domain and/or IP address, this application gathers WHOIS data, DNS records, DNSSEC status, SSL certificate details, email security records, website content previews, performance metrics, reverse DNS, IP geolocation, open port scans, RDAP ownership data, banner grabbing and ICMP latency results. The tool supports command-line configuration for scanning parameters, properly serializes datetime objects for clean JSON output and automatically archives results to a timestamped file.

## Set Up Instructions

Below are instructions for how to install and use this app.

### Programs Needed

- [Git](https://git-scm.com/downloads)

- [Python](https://www.python.org/downloads/)

### Steps

1. Install the above programs

2. Open a terminal

3. Clone this repository using `git` by running the following command `git clone git@github.com:devbret/domain-and-ip-analyses.git`

4. Navigate to the repo's directory by running `cd domain-and-ip-analyses`

5. Install the needed dependencies for operating the script by running `pip install -r requirements.txt`

6. Run the script with the command `python3 app.py --domain example.com --ip 8.8.8.8`

7. The results will be returned to you via your CLI and as JSON in a local `reports` directory
