import re
import spacy
import requests

# Load Spacy model
nlp = spacy.load("en_core_web_sm")

# List of known threat actors
known_threat_actors = ["APT33", "APT28", "Lazarus", "Charming Kitten", "Fancy Bear", "Cozy Bear"]

# Example MITRE ATT&CK TTPs for identification
mitre_ttp_map = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0008": "Lateral Movement",
    "T1566.001": "Spear Phishing Attachment",
    "T1059.001": "PowerShell"
}

# Function to extract threat intelligence
def extract_threat_intelligence(report_text):
    # IoCs: Extract IPs, domains, emails, and file hashes
    ip_addresses = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', report_text)
    domains = re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}\b', report_text)
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', report_text)

    # Extract named entities using Spacy
    doc = nlp(report_text)

    # Extract threat actors (check for ORG and relevant words like 'APT')
    threat_actors = []
    for known_actor in known_threat_actors:
        if known_actor in report_text:
            threat_actors.append(known_actor)

    # Extract other organizations (non-APT) mentioned in the report
    for ent in doc.ents:
        if ent.label_ == "ORG" and ent.text not in threat_actors:
            threat_actors.append(ent.text)

    # Extract targeted entities (e.g., countries, organizations)
    targeted_entities = [ent.text for ent in doc.ents if ent.label_ == "GPE"]

    # Extract malware name
    malware_name = re.search(r"malware\s+(\w+)", report_text)
    malware_details = []
    if malware_name:
        malware_details.append({"Name": malware_name.group(1)})

    # Placeholder for malware hashes (simple regex, should be enhanced if hashes are present)
    file_hashes = re.findall(r'\b[A-Fa-f0-9]{64}\b', report_text)
    for hash_value in file_hashes:
        malware_details.append({"sha256": hash_value})

    # Placeholder for tactics and techniques (can be linked with MITRE ATT&CK)
    tactics = [{"TA0001": "Initial Access"}, {"TA0002": "Execution"}, {"TA0008": "Lateral Movement"}]
    techniques = [{"T1566.001": "Spear Phishing Attachment"}, {"T1059.001": "PowerShell"}]

    # Return a structured dictionary
    return {
        "IoCs": {
            "IP addresses": ip_addresses,
            "Domains": domains,
            "Emails": emails
        },
        "TTPs": {
            "Tactics": tactics,
            "Techniques": techniques
        },
        "Threat Actor(s)": threat_actors,
        "Malware": malware_details,
        "Targeted Entities": targeted_entities
    }

# Function to enrich malware details using VirusTotal API (optional)
def enrich_malware_details(malware_name):
    api_key = "your_virustotal_api_key"
    url = f"https://www.virustotal.com/api/v3/files/{malware_name}"

    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json_data = response.json()
        return {
            "sha256": json_data['data']['attributes']['sha256'],
            "tags": json_data['data']['attributes']['tags']
        }
    return {}

if __name__ == "__main__":
    # Sample threat report
    report_text = '''
    The APT33 group, suspected to be from Iran, has launched a new campaign targeting
    the energy sector organizations. The attack utilizes Shamoon malware, known for its destructive capabilities. 
    The threat actor exploited a vulnerability in the network perimeter to gain initial access.
    The malware was delivered via spear-phishing emails containing a malicious attachment.
    The malware's behavior was observed communicating with IP address 192.168.1.1 and domain example.com.
    The attack also involved lateral movement using PowerShell scripts.
    '''
    
    # Extract threat intelligence from the report
    result = extract_threat_intelligence(report_text)
    
    # Print the result
    print(result)
