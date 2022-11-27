import requests
from colorama import Fore, Style
import json

requests.packages.urllib3. \
    disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# ===================== NVD SCAN ===========================
oss_name = ''''''   # Can be one or multiple oss / one or more tuples of (vendor, product)
cpe_name = ''''''   # E.g: "cpe:2.3:o:microsoft:windows_10:1607"
nvd_token = ''''''  # API key to increase the rate limit.(optional)
# ==========================================================


def format_text(title, item):
    cr = '\r\n'
    section_break = cr + "*" * 20 + cr
    item = str(item)
    text = Style.BRIGHT + Fore.RED + title + Fore.RESET + section_break + item + section_break
    return text

def request(url):
    global r
    if oss_name:
        if nvd_token:
            headers = {'apiKey': f"{nvd_token}"}
            url_for_nvd_exact_match = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={oss_name}"
            r = requests.get(url_for_nvd_exact_match, headers=headers)
        return r

     if cpe_name:
        url_for_nvd_cpe = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}"
        r = requests.get(url_for_nvd_cpe)

     else:
         return "Required params missing"
if __name__ == "__main__":
    request()
    parsed_json = (json.loads(r.content))
    totalResults = parsed_json["totalResults"]
    cve = parsed_json["vulnerabilities"]

print(f"Total vulnerabilities found: {totalResults}.")
for cve in parsed_json["vulnerabilities"]:
    print(cve['cve']["id"])



