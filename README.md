# SOC-Alert-Analysis
A Python-based blue team security tool designed to analyze Linux authentication logs (auth.log) and detect suspicious login activity using real-world SOC detection techniques.
# SOC Auth Log Analyzer

## Overview

SOC Auth Log Analyzer is a Python-based desktop application for security
monitoring and threat detection.

It analyzes Linux auth.log files and detects: - Brute force attacks -
Username enumeration - Invalid user attempts - Suspicious successful
logins - Impossible travel events (when GeoIP is enabled)

## Features

-   GUI dashboard built with Tkinter
-   Risk scoring for attacker IPs
-   CSV reporting
-   Blacklist generation
-   Alert generation
-   Security charts using matplotlib

## Required Libraries

Install dependencies:

``` bash
pip install matplotlib pillow geoip2
```

## How to Run

Run the script:

``` bash
python your_script.py
```

Then: 1. Select your auth.log file 2. Select output folder 3. Optionally
select GeoLite2 database 4. Click Run Analysis

## Output Files

The tool generates: - blacklist.txt - report.csv - alerts.txt - PNG
charts

## Detection Logic

Risk scoring: - Brute Force = +40 - Rapid failures = +30 - Username
enumeration = +30 - Impossible travel = +40

## Future Enhancements

-   Threat intelligence enrichment
-   MITRE ATT&CK mapping
-   Real-time log monitoring
