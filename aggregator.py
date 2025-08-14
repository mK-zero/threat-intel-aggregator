import requests
import pandas as pd
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

if __name__ == "__main__":
    main()
