import sys
import tldextract
import dns.resolver
import dns.query
import dns.zone
import re
import os
import errno
import json

print("[*] Starting script")

if len(sys.argv) < 2:
	print("[X] Usage: python", sys.argv[0], "<url/domain>")
	sys.exit(0)

for url in sys.argv[1:]:
	ext = tldextract.extract(url)
	domain = ext.domain + "." + ext.suffix
	print("[*] Getting nameservers for", domain)
	nameservers = []
	try:
		ns_query = dns.resolver.query(domain, "NS")
		for index, ns in enumerate(ns_query):
			nameserver = str(ns)[:-1]
			if nameserver is None or nameserver == "":
				continue
			nameservers.append(nameserver)
		print("[+] Successfully retrieved", len(nameservers), "nameservers")
		for nameserver in nameservers:
			try:
				axfr = dns.query.xfr(nameserver, domain, lifetime=10)
				zone = dns.zone.from_xfr(axfr)
				if zone is None:
					continue
				print("[+] Nameserver", nameserver, "is vulnerable (" + str(len(zone.nodes.items())) + " records)")
				result = {}
				i = 0
				for name, node in zone.nodes.items():
					res = {}
					name = str(name)
					if name != "@":
						name += "." + domain
					else:
						name = domain
					res["name"] = name
					rdatasets = node.rdatasets
					for rdataset in rdatasets:
						res['type'] = re.search(r"\sIN\s(.*?)\s", str(rdataset)).group(1)
						res['ttl'] = re.search(r"(.*?)\sIN\s", str(rdataset)).group(1)
						res['value'] = re.search(r"IN (.*) (.*)", str(rdataset)).group(2)
						result.update({i:res})
						i += 1
				filename = "result/" + domain + "/" + nameserver + ".json"
				if not os.path.exists(os.path.dirname(filename)):
					try:
						os.makedirs(os.path.dirname(filename))
					except OSError as exc:
						if exc.errno != errno.EEXIST:
							raise
				with open(filename, "w") as f:
					f.write(json.dumps(result))
				print("[*] Outfile saved to", filename)
			except:
				print("[-] Unable to retrieve DNS record from", nameserver)
				continue
	except:
		print("[-] Problem retrieving nameserver for domain", domain)
		continue
print("[*] Script exiting")
sys.exit(0)

