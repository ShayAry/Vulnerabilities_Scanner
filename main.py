import requests
from colorama import Fore, Style
import json

requests.packages.urllib3. \
    disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# ===================== NVD SCAN ===========================
oss_name = ''''''  # Can be one or multiple oss / one or more tuples of (vendor, product)
cpe_name = ''''''  # E.g: "cpe:2.3:o:microsoft:windows_10:1607"
nvd_token = ''''''  # API key to increase the rate limit.(optional)


# ==========================================================

def request():
    if oss_name:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={oss_name}"
        if nvd_token:
            headers = {'apiKey': f"{nvd_token}"}
            r = requests.get(url, headers=headers)
            parsed_json = json.loads(r.content)
            totalResults = parsed_json["totalResults"]
            print(f"Total vulnerabilities found: {totalResults}.")
            for cve in parsed_json["vulnerabilities"]:
                print(cve['cve']["id"])
        else:
            r = requests.get(url)
            parsed_json = json.loads(r.content)
            totalResults = parsed_json["totalResults"]
            print(f"Total vulnerabilities found: {totalResults}.")
            for cve in parsed_json["vulnerabilities"]:
                print(cve['cve']["id"])

    if cpe_name:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}"
        r = requests.get(url)
        parsed_json = json.loads(r.content)
        totalResults = parsed_json["totalResults"]
        print(f"Total vulnerabilities found: {totalResults}.")
        for cve in parsed_json["vulnerabilities"]:
            print(cve['cve']["id"])

    else:
        return "Required params missing"

if __name__ == "__main__":
    request()

