# Ternary color patterns - conditional colors  
# Pattern: "color_value" where value is a hex in quotes within ternary
# These all use ternary conditionals like condition?"#ff4757":"#2ed573"

# Risk gauge colors (line 551) - special case, leave as-is since it's for Chart.js canvas
# Scenario badge (line 601) 
s/threat?"#ff4757":"#2ed573"/threat?"var(--critical)":"var(--ok)"/g

# Module health status (line 739)
s/r.status==="ok"?"#2ed573":"#ff4757"/r.status==="ok"?"var(--ok)":"var(--critical)"/g

# Anomaly bar color (line 796) 
s/sc>0.7?"#ff4757":sc>0.4?"#ffa502":"#2ed573"/sc>0.7?"var(--critical)":sc>0.4?"var(--warning)":"var(--ok)"/g

# SAP tool color (line 897)
s/flagged ? "#ff4757" : "#5b8def"/flagged ? "var(--critical)" : "var(--accent)"/g

# SAP result (line 906)
s/e.result==="success"?flagged?"#ff4757":"#2ed573":"#ffa502"/e.result==="success"?flagged?"var(--critical)":"var(--ok)":"var(--warning)"/g

# Framework color maps (lines 929, 957)
s/SOX:"#ff4757",GDPR:"#5b8def","PCI-DSS":"#ff8b3d","NIST-CSF":"#2ed573",ISO27001:"#a17fe0",HIPAA:"#39c5cf"/SOX:"var(--critical)",GDPR:"var(--accent)","PCI-DSS":"var(--orange)","NIST-CSF":"var(--ok)",ISO27001:"var(--purple)",HIPAA:"var(--cyan)"/g
s/"#7a93b4"/"var(--text-muted)"/g

# Compliance score colors (line 961)
s/score>90?"#2ed573":score>80?"#5b8def":score>70?"#ffa502":"#ff4757"/score>90?"var(--ok)":score>80?"var(--accent)":score>70?"var(--warning)":"var(--critical)"/g

# Incident status colors (line 993)
s/open:"#ff4757",investigating:"#ffa502",in_progress:"#ffa502",active:"#ffa502",resolved:"#2ed573",closed:"#2ed573",contained:"#2ed573"/open:"var(--critical)",investigating:"var(--warning)",in_progress:"var(--warning)",active:"var(--warning)",resolved:"var(--ok)",closed:"var(--ok)",contained:"var(--ok)"/g

# Incident severity (line 1008)
s/e.severity==="critical"?"#ff4757":e.severity==="high"?"#ff8b3d":"#ffa502"/e.severity==="critical"?"var(--critical)":e.severity==="high"?"var(--orange)":"var(--warning)"/g

# Playbook step colors (line 1040)
s/isDone?"#2ed573":isActive?"#ffa502":"#4a6080"/isDone?"var(--ok)":isActive?"var(--warning)":"var(--text-dim)"/g

# SBOM vuln (line 1071,1075)  
s/vuln?"#ff4757":"#2ed573"/vuln?"var(--critical)":"var(--ok)"/g
s/vuln?"rgba(255,71,87,.2)":"rgba(46,213,115,.15)"/vuln?"var(--critical-bg)":"var(--ok-bg)"/g
s/parseInt(e.cve_count||0)>0?"#ff4757":"#2ed573"/parseInt(e.cve_count||0)>0?"var(--critical)":"var(--ok)"/g
s/parseInt(e.insecure_rfc_count||0)>0?"#ffa502":"#2ed573"/parseInt(e.insecure_rfc_count||0)>0?"var(--warning)":"var(--ok)"/g

# Rules color map (line 1102) 
s/bulk_extraction:"#ff4757",off_hours_rfc:"#ffa502",shadow_endpoint:"#ff8b3d",velocity_anomaly:"#5b8def",data_staging:"#ff4757",credential_abuse:"#a17fe0",privilege_escalation:"#ff4757",geo_anomaly:"#ffa502"/bulk_extraction:"var(--critical)",off_hours_rfc:"var(--warning)",shadow_endpoint:"var(--orange)",velocity_anomaly:"var(--accent)",data_staging:"var(--critical)",credential_abuse:"var(--purple)",privilege_escalation:"var(--critical)",geo_anomaly:"var(--warning)"/g

# ZT decision (line 1142)
s/dec==="allow"?"#2ed573":dec==="deny"?"#ff4757":"#ffa502"/dec==="allow"?"var(--ok)":dec==="deny"?"var(--critical)":"var(--warning)"/g

# ZT risk (line 1150)  
s/risk>0.7?"#ff4757":risk>0.4?"#ffa502":"#2ed573"/risk>0.7?"var(--critical)":risk>0.4?"var(--warning)":"var(--ok)"/g

# Credentials action (line 1185)
s/act.includes("revok")?"#ff4757":act.includes("rotat")?"#ffa502":"#2ed573"/act.includes("revok")?"var(--critical)":act.includes("rotat")?"var(--warning)":"var(--ok)"/g

# Cloud provider map (line 1217)
s/provC = {aws:"#ff9900",gcp:"#4285f4",azure:"#00a4ef"}/provC = {aws:"var(--aws)",gcp:"var(--gcp)",azure:"var(--azure)"}/g

# Detail drawer ternaries (lines 1374-1411)
s/parseFloat(ev.anomaly_score||0)>0.7?"#ff4757":"#ffa502"/parseFloat(ev.anomaly_score||0)>0.7?"var(--critical)":"var(--warning)"/g
s/(ev.result||"")==="violation"?"#ff4757":"#2ed573"/(ev.result||"")==="violation"?"var(--critical)":"var(--ok)"/g
s/(ev.result||"")=="violation"?"#ff4757":"#2ed573"/(ev.result||"")=="violation"?"var(--critical)":"var(--ok)"/g
s/(ev.status||"open")==="open"?"#ff4757":(ev.status||"")==="investigating"?"#ffa502":"#2ed573"/(ev.status||"open")==="open"?"var(--critical)":(ev.status||"")==="investigating"?"var(--warning)":"var(--ok)"/g
s/ev.scan_status==="VULNERABLE"?"#ff4757":"#2ed573"/ev.scan_status==="VULNERABLE"?"var(--critical)":"var(--ok)"/g
s/parseInt(ev.cve_count||0)>0?"#ff4757":"#2ed573"/parseInt(ev.cve_count||0)>0?"var(--critical)":"var(--ok)"/g
s/parseInt(ev.insecure_rfc_count||0)>0?"#ffa502":"#2ed573"/parseInt(ev.insecure_rfc_count||0)>0?"var(--warning)":"var(--ok)"/g
s/(ev.decision||"")==="deny"?"#ff4757":(ev.decision||"")==="allow"?"#2ed573":"#ffa502"/(ev.decision||"")==="deny"?"var(--critical)":(ev.decision||"")==="allow"?"var(--ok)":"var(--warning)"/g
s/parseFloat(ev.risk_score||0)>0.7?"#ff4757":"#ffa502"/parseFloat(ev.risk_score||0)>0.7?"var(--critical)":"var(--warning)"/g
s/(ev.action||"").includes("revok")?"#ff4757":(ev.action||"").includes("rotat")?"#ffa502":"#2ed573"/(ev.action||"").includes("revok")?"var(--critical)":(ev.action||"").includes("rotat")?"var(--warning)":"var(--ok)"/g
s/(ev.provider||"")==="aws"?"#ff9900":(ev.provider||"")==="gcp"?"#4285f4":"#00a4ef"/(ev.provider||"")==="aws"?"var(--aws)":(ev.provider||"")==="gcp"?"var(--gcp)":"var(--azure)"/g

# Cloud risk score (line 1234) 
s/parseFloat(e.risk_score||0)>0.7?"#ff4757":"#ffa502"/parseFloat(e.risk_score||0)>0.7?"var(--critical)":"var(--warning)"/g
