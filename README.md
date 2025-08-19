# Threat Intelligence Feed Aggregator

A lightweight application to scan IP addresses, domains, or file hashes using the VirusTotal API. Displays threat intelligence results in a table and allows CSV export.

---

## Overview

This tool allows users to input multiple indicators (IP, domain, or file hash) and fetches threat analysis data from VirusTotal. It is ideal for quick threat lookups and simple intelligence aggregation.

---

## Architecture Overview

- **Frontend**: Streamlit UI
    - 
    -
    -
    -
    -

- **Backend**: Python + VirusTotal API

- **Configuration**

---

## Data Flow
```mermaid

```

## Dependencies
    - `streamlit`
    - `pandas`
    - `requests`
    - Custom `config.py` for API key  
Install with: 
`pip install streamlit pandas requests`

## Features
    - Bulk input support (one query per line)
    - Scan IPs, domains, or file hashes
    - Display results in an interactive table
    - Download results as a CSV file
    - Handles API errors gracefully

## Security Notes
    - Never hardcode API key in the main script.
    - Add `config.py` to your `.gitignore`:  
        `config.py`
## Future Improvements
    - API response caching
    - Scan progress indicator
    - Add scan details
    - Handle API rate limiting gracefully

## Getting Started

### 1. Clone the repo
````bash`  
`git clone https://github.com/mK-zero/threat-intel-aggregator.git`  
`cd threat-intel-aggregator`
### 2. Create virtual environment & install dependencies
`python -m venv venv`  
`source venv/bin/activate`   # Windows: `venv\Scripts\activate`  
`pip install -r requirements.txt`  
### 3. Add API key
Create `config.py`:  
`VIRUSTOTAL_API_KEY = "your_api_key_here"`
### 4. Run the dashboard
`streamlit run aggregator.py`

## License  
MIT License - use freely for educational or personal projects
---