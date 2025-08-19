import streamlit as st
import requests
import pandas as pd
import openpyxl
from config import VIRUSTOTAL_API_KEY

def get_virustotal_ip_info(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return {
            "ip": ip,
            "harmless": data["data"]["attributes"]["last_analysis_stats"]["harmless"],
            "malicious": data["data"]["attributes"]["last_analysis_stats"]["malicious"],
            "suspicious": data["data"]["attributes"]["last_analysis_stats"]["suspicious"],
            "undetected": data["data"]["attributes"]["last_analysis_stats"]["undetected"]
        }
    else:
        return {"ip": ip, "error": response.status_code}

def vt_lookup(query, type="ip"):
    url = f"https://www.virustotal.com/api/v3/{type}_addresses/{query}" if type == "ip" else f"https://www.virustotal.com/api/v3/domains/{query}" if type == "domain" else f"https://www.virustotal.com/api/v3/files/{query}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "query": query,
            "type": type,
            "harmless": data.get("harmless", 0),
            "malicious": data.get("malicious", 0),
            "suspicious": data.get("suspicious", 0),
            "undetected": data.get("undetected", 0)
        }
    else:
        return {"query": query, "type": type, "error": f"Error {response.status_code}"}

def main():
    ip_list = ["8.8.8.8", "1.1.1.1", "185.220.101.1"] # Sample IPs
    results = []

    for ip in ip_list:
        print(f"Checking: {ip}")
        result = get_virustotal_ip_info(ip)
        results.append(result)
    
    df = pd.DataFrame(results)
    df.to_excel("output/threat_report.xlsx", index=False)
    print("Threat report saved to output/threat_report.xlsx")

    st.title("Threat Intelligence Feed Aggregator")
    query_type = st.selectbox("Type of Query", ["IP", "Domain", "File Hash"])
    input_list = st.text_area("Enter items (one per line)").splitlines()

    if st.button("Scan"):
        results = []
        type_key = query_type.lower().replace(" ", "_")
        for item in input_list:
            if item.strip():
                result = vt_lookup(item.strip(), type=type_key)
                results.append(result)
        
        df = pd.DataFrame(results)
        st.dataframe(df)
        st.download_button("Download CSV", data=df.to_csv(index=False), file_name="threat_report.csv")

if __name__ == "__main__":
    main()
