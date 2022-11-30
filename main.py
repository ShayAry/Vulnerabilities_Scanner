import nvdlib

# ================================================
cve = ''''''
prodcut = ''''''
cpe = ''''''  # E.g: "cpe:2.3:a:microsoft:exchange_server:5.0:-:*:*:*:*:*:*"
key = "" # KEY for NVD Api. (optional)
wild_search = False
# ================================================
if cve != "" and not None:
    r = nvdlib.searchCVE(cveId=cve, key=key, delay=1)[0]
    print(str(r.v31severity) + ' - ' + str(r.v31score))
    print("CVSS Score: " + r.v31vector)
    print(r.descriptions[0].value)
    print("Reported on: " + r.published)
    print(r.url)

if prodcut != "" and not None:
    if wild_search:
        q = nvdlib.searchCVE(keywordSearch=prodcut)
    else:
        q = nvdlib.searchCVE(keywordSearch=prodcut, keywordExactMatch=True)
    for cve in q:
        print(cve.id, str(cve.score[0]), cve.url)

if cpe != "" and not None:
    cves_list = nvdlib.searchCVE(cpeName=cpe)
    for cve in cves_list:
        print(cve.id + str(cve.score[0]), cve.url)
