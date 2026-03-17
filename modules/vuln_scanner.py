import socket, sqlite3, json, threading, logging, os, requests
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Optional
 
logger = logging.getLogger(__name__)
NVD_API_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY    = os.getenv("NVD_API_KEY", "")
CVE_DB_PATH    = "data/cve_cache.db"
SCAN_TIMEOUT   = 1.0
BANNER_TIMEOUT = 2.0
MAX_THREADS    = 50
 
COMMON_PORTS = {
    21:("FTP",b""),22:("SSH",b""),23:("Telnet",b""),
    25:("SMTP",b"EHLO sentinel\r\n"),53:("DNS",b""),
    80:("HTTP",b"HEAD / HTTP/1.0\r\n\r\n"),110:("POP3",b""),
    135:("MSRPC",b""),139:("NetBIOS",b""),143:("IMAP",b""),
    443:("HTTPS",b""),445:("SMB",b""),1433:("MSSQL",b""),
    1521:("Oracle",b""),3306:("MySQL",b""),3389:("RDP",b""),
    5432:("PostgreSQL",b""),5900:("VNC",b""),
    6379:("Redis",b"PING\r\n"),8080:("HTTP-Alt",b"HEAD / HTTP/1.0\r\n\r\n"),
    8443:("HTTPS-Alt",b""),9200:("Elasticsearch",b""),27017:("MongoDB",b""),
}
TOP_1000_EXTRAS = list(range(1,1024))
SERVICE_MITRE_MAP = {
    "FTP":[("T1021.004","Remote Services: FTP"),("T1078","Valid Accounts")],
    "SSH":[("T1021.004","Remote Services: SSH"),("T1110","Brute Force")],
    "Telnet":[("T1021.004","Remote Services: Telnet"),("T1040","Network Sniffing")],
    "SMB":[("T1021.002","Remote Services: SMB"),("T1570","Lateral Tool Transfer")],
    "MSRPC":[("T1021.003","DCOM"),("T1569.001","MSRPC")],
    "NetBIOS":[("T1046","Network Service Discovery"),("T1135","Network Share Discovery")],
    "RDP":[("T1021.001","Remote Desktop Protocol"),("T1110.001","Password Guessing")],
    "HTTP":[("T1190","Exploit Public-Facing Application"),("T1505.003","Web Shell")],
    "HTTPS":[("T1190","Exploit Public-Facing Application"),("T1505.003","Web Shell")],
    "HTTP-Alt":[("T1190","Exploit Public-Facing Application")],
    "HTTPS-Alt":[("T1190","Exploit Public-Facing Application")],
    "MySQL":[("T1190","Exploit Public-Facing Application"),("T1078","Valid Accounts")],
    "MSSQL":[("T1190","Exploit Public-Facing Application"),("T1078","Valid Accounts")],
    "Oracle":[("T1190","Exploit Public-Facing Application"),("T1078","Valid Accounts")],
    "PostgreSQL":[("T1190","Exploit Public-Facing Application"),("T1078","Valid Accounts")],
    "Redis":[("T1190","Exploit Public-Facing Application"),("T1505","Server Software")],
    "MongoDB":[("T1190","Exploit Public-Facing Application"),("T1078","Valid Accounts")],
    "Elasticsearch":[("T1190","Exploit Public-Facing Application"),("T1213","Data from Repositories")],
    "VNC":[("T1021.005","Remote Services: VNC")],
}
SERVICE_REMEDIATION = {
    "FTP":"Disable FTP; use SFTP/SCP. Enforce strong credentials.",
    "Telnet":"Disable Telnet immediately - cleartext protocol. Replace with SSH.",
    "SMB":"Restrict SMB to required hosts. Patch MS17-010. Disable SMBv1.",
    "RDP":"Enable NLA, restrict to VPN only, use MFA. Apply latest patches.",
    "Redis":"Bind to localhost only. Enable requirepass. Never expose to internet.",
    "MongoDB":"Enable authentication. Bind to localhost. Audit exposed collections.",
    "Elasticsearch":"Enable security features. Never expose port 9200 publicly.",
    "VNC":"Use VPN tunnel. Enable encryption. Prefer RDP/SSH with MFA.",
    "MySQL":"Restrict remote root login. Use per-app credentials. Audit privileges.",
    "MSSQL":"Disable SA account or use strong password. Enable Windows Auth.",
}
DEFAULT_REMEDIATION = "Review necessity of this service. Restrict access via firewall. Apply latest patches."
 
@dataclass
class OpenPort:
    port:int; service:str; banner:str=""; protocol:str="tcp"
 
@dataclass
class CVEMatch:
    cve_id:str; description:str; cvss_score:float; severity:str
    cvss_vector:str=""; published:str=""; references:list=field(default_factory=list)
 
@dataclass
class VulnFinding:
    port:int; service:str; banner:str
    cves:list=field(default_factory=list)
    mitre_techniques:list=field(default_factory=list)
    risk_score:float=0.0; risk_level:str="INFO"; remediation:str=""
 
@dataclass
class ScanResult:
    target:str; scan_start:str; scan_end:str=""
    open_ports:list=field(default_factory=list)
    findings:list=field(default_factory=list)
    total_critical:int=0; total_high:int=0
    total_medium:int=0; total_low:int=0
    scanner_version:str="1.0"
    def to_dict(self): return asdict(self)
 
class CVECache:
    def __init__(self,db_path=CVE_DB_PATH):
        os.makedirs(os.path.dirname(db_path),exist_ok=True)
        self.db_path=db_path; self._init_db()
    def _init_db(self):
        with sqlite3.connect(self.db_path) as c:
            c.execute("CREATE TABLE IF NOT EXISTS cve_cache(keyword TEXT NOT NULL,cve_id TEXT NOT NULL,data TEXT NOT NULL,cached_at TEXT NOT NULL,PRIMARY KEY(keyword,cve_id))")
            c.execute("CREATE INDEX IF NOT EXISTS idx_kw ON cve_cache(keyword)"); c.commit()
    def get(self,keyword):
        cutoff=(datetime.utcnow()-timedelta(hours=24)).isoformat()
        with sqlite3.connect(self.db_path) as c:
            rows=c.execute("SELECT data FROM cve_cache WHERE keyword=? AND cached_at>?",(keyword.lower(),cutoff)).fetchall()
        return [json.loads(r[0]) for r in rows] if rows else None
    def put(self,keyword,cves):
        now=datetime.utcnow().isoformat()
        with sqlite3.connect(self.db_path) as c:
            for cve in cves:
                c.execute("INSERT OR REPLACE INTO cve_cache VALUES(?,?,?,?)",(keyword.lower(),cve["cve_id"],json.dumps(cve),now))
            c.commit()
 
def _score_to_severity(s):
    if s>=9.0:return "CRITICAL"
    if s>=7.0:return "HIGH"
    if s>=4.0:return "MEDIUM"
    if s>=0.1:return "LOW"
    return "INFO"
 
def _query_nvd(keyword,max_results=10):
    headers={"apiKey":NVD_API_KEY} if NVD_API_KEY else {}
    try:
        resp=requests.get(NVD_API_BASE,headers=headers,params={"keywordSearch":keyword,"resultsPerPage":max_results},timeout=10)
        resp.raise_for_status(); data=resp.json()
    except Exception as e:
        logger.warning("NVD error for %s: %s",keyword,e); return []
    results=[]
    for item in data.get("vulnerabilities",[]):
        cn=item.get("cve",{}); cid=cn.get("id","")
        desc=next((d["value"] for d in cn.get("descriptions",[]) if d.get("lang")=="en"),"No description")
        score,vector=0.0,""
        for key in("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            entries=cn.get("metrics",{}).get(key,[])
            if entries:
                cd=entries[0].get("cvssData",{}); score=cd.get("baseScore",0.0); vector=cd.get("vectorString",""); break
        results.append({"cve_id":cid,"description":desc[:400],"cvss_score":score,"severity":_score_to_severity(score),"cvss_vector":vector,"published":cn.get("published","")[:10],"references":[r.get("url","") for r in cn.get("references",[])[:3]]})
    results.sort(key=lambda x:x["cvss_score"],reverse=True); return results
 
def lookup_cves(service,banner="",cache=None):
    keyword=service.split("/")[0].strip()
    if banner:
        parts=banner.split()
        if len(parts)>=2: keyword=f"{keyword} {parts[1][:20].strip('.,;:')}"
    if cache:
        cached=cache.get(keyword)
        if cached is not None: return [CVEMatch(**c) for c in cached]
    raw=_query_nvd(keyword)
    if cache and raw: cache.put(keyword,raw)
    return [CVEMatch(**c) for c in raw]
 
def _nmap_available():
    return False  # nmap.exe not installed - using socket fallback
 
def _grab_banner(target,port,probe):
    try:
        with socket.create_connection((target,port),timeout=BANNER_TIMEOUT) as s:
            if probe: s.sendall(probe)
            s.settimeout(BANNER_TIMEOUT); return s.recv(256).decode("utf-8",errors="ignore").strip()[:200]
    except: return ""
 
def _socket_scan_port(target,port):
    try:
        with socket.create_connection((target,port),timeout=SCAN_TIMEOUT):
            service,probe=COMMON_PORTS.get(port,(f"unknown-{port}",b""))
            banner=_grab_banner(target,port,probe) if probe else _grab_banner(target,port,b"")
            return OpenPort(port=port,service=service,banner=banner)
    except: return None
 
def _nmap_scan(target,ports):
    import nmap; nm=nmap.PortScanner()
    try: nm.scan(hosts=target,ports=",".join(str(p) for p in ports),arguments="-sV -T4")
    except Exception as e: logger.error("nmap error: %s",e); return []
    results=[]
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port,data in nm[host][proto].items():
                if data.get("state")=="open":
                    results.append(OpenPort(port=port,service=data.get("name",f"port-{port}"),banner=f"{data.get('product','')} {data.get('version','')}".strip()))
    return results
 
def scan_ports(target,ports,emit_fn=None):
    if _nmap_available():
        if emit_fn: emit_fn("vuln_progress",{"stage":"port_scan","message":f"Running nmap on {target}..."})
        return _nmap_scan(target,ports)
    if emit_fn: emit_fn("vuln_progress",{"stage":"port_scan","message":f"Socket scanning {len(ports)} ports on {target}..."})
    results=[]; lock=threading.Lock(); sem=threading.Semaphore(MAX_THREADS)
    def worker(p):
        with sem:
            found=_socket_scan_port(target,p)
            if found:
                with lock: results.append(found)
    threads=[threading.Thread(target=worker,args=(p,),daemon=True) for p in ports]
    for t in threads: t.start()
    for t in threads: t.join()
    results.sort(key=lambda x:x.port); return results
 
def calculate_risk(cves,service):
    if not cves:
        score={"Telnet":8.5,"FTP":5.0,"VNC":6.0,"NetBIOS":5.5,"MSRPC":4.5}.get(service,0.0)
    else:
        score=max(c.cvss_score for c in cves)
    score=min(10.0,score+{"Telnet":1.5,"FTP":0.5,"VNC":0.5,"SMB":0.5,"RDP":0.5}.get(service,0.0))
    return round(score,1),_score_to_severity(score)
 
def run_scan(target,port_range="common",emit_fn=None,cve_cache=None):
    if cve_cache is None: cve_cache=CVECache()
    scan_start=datetime.utcnow().isoformat()
    result=ScanResult(target=target,scan_start=scan_start)
    def _emit(event,data):
        if emit_fn:
            try: emit_fn(event,data)
            except Exception as e: logger.warning("emit error: %s",e)
    if port_range=="common": ports=list(COMMON_PORTS.keys())
    elif port_range=="full": ports=list(set(list(COMMON_PORTS.keys())+TOP_1000_EXTRAS))
    else:
        try:
            if "-" in port_range:
                lo,hi=port_range.split("-"); ports=list(range(int(lo),int(hi)+1))
            else: ports=[int(p.strip()) for p in port_range.split(",")]
        except: ports=list(COMMON_PORTS.keys())
    _emit("vuln_scan_start",{"target":target,"port_count":len(ports),"scan_start":scan_start})
    open_ports=scan_ports(target,ports,emit_fn=_emit)
    result.open_ports=open_ports
    _emit("vuln_ports_found",{"target":target,"open_ports":[asdict(p) for p in open_ports],"count":len(open_ports)})
    if not open_ports:
        result.scan_end=datetime.utcnow().isoformat(); _emit("vuln_scan_complete",result.to_dict()); return result
    findings=[]; counts={"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for i,op in enumerate(open_ports):
        _emit("vuln_progress",{"stage":"cve_lookup","port":op.port,"service":op.service,"current":i+1,"total":len(open_ports),"message":f"Looking up CVEs for {op.service} (port {op.port})..."})
        cves=lookup_cves(op.service,op.banner,cache=cve_cache)
        mitre=SERVICE_MITRE_MAP.get(op.service,[])
        risk_score,risk_level=calculate_risk(cves,op.service)
        remediation=SERVICE_REMEDIATION.get(op.service,DEFAULT_REMEDIATION)
        findings.append(VulnFinding(port=op.port,service=op.service,banner=op.banner,cves=cves,mitre_techniques=mitre,risk_score=risk_score,risk_level=risk_level,remediation=remediation))
        for cve in cves:
            if cve.severity in counts: counts[cve.severity]+=1
    result.findings=findings; result.total_critical=counts["CRITICAL"]; result.total_high=counts["HIGH"]
    result.total_medium=counts["MEDIUM"]; result.total_low=counts["LOW"]
    result.scan_end=datetime.utcnow().isoformat()
    _emit("vuln_scan_complete",result.to_dict())
    if result.total_critical>0:
        _emit("vuln_critical_alert",{"target":target,"critical":result.total_critical,"message":f"CRITICAL: {result.total_critical} critical CVE(s) found on {target}"})
    return result
 
def run_scan_async(target,port_range="common",emit_fn=None,cve_cache=None):
    t=threading.Thread(target=run_scan,args=(target,port_range,emit_fn,cve_cache),daemon=True,name=f"vuln-scan-{target}")
    t.start(); return t

