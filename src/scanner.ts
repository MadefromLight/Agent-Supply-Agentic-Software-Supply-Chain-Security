import type {AgentManifest,Finding,ScanReport,Severity} from "./types.js";
function finding(id:string,severity:Severity,title:string,message:string,path:string,remediation:string):Finding{return{id,severity,title,message,path,remediation};}
export function scanManifest(manifest:AgentManifest,target="manifest.json"):ScanReport {
 const findings:Finding[]=[];
 for(const permission of manifest.permissions ?? []) if(permission==="*" || permission.endsWith(":*")) findings.push(finding("AGENT-001","high","Wildcard permission","Agent declares broad permission "+permission,"permissions","Replace wildcard access with the smallest required capability."));
 for(const [script,command] of Object.entries(manifest.scripts ?? {})) if(/curl|wget|powershell|bash -c|sh -c|rm -rf/i.test(command)) findings.push(finding("AGENT-002","high","High-risk script","Script "+script+" contains a command associated with remote execution or destructive behavior.","scripts."+script,"Review the command and remove unnecessary execution."));
 if(/(sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{12,}|-----BEGIN .*PRIVATE KEY-----)/.test(JSON.stringify(manifest))) findings.push(finding("AGENT-003","critical","Credential-like secret detected","Manifest contains a credential/private-key pattern.","manifest","Remove the secret, rotate it, and use a secret manager."));
 for(const [name,version] of Object.entries(manifest.dependencies ?? {})) if(/^\^|^~|\*|latest$/i.test(version)) findings.push(finding("AGENT-004","medium","Dependency is not tightly pinned","Dependency "+name+" uses version "+version,"dependencies."+name,"Pin production dependencies to an audited version or immutable lockfile."));
 for(const [index,tool] of (manifest.tools ?? []).entries()) if(tool.source && !/@[0-9]+(?:\.[0-9]+){0,2}$/.test(tool.source)) findings.push(finding("AGENT-005","medium","External tool source is not pinned","Tool "+tool.name+" does not appear to reference an exact version.","tools["+index+"].source","Pin the tool to an exact reviewed version or digest."));
 const severities:Severity[]=["low","medium","high","critical"];
 const summary=Object.fromEntries(severities.map(s=>[s,findings.filter(f=>f.severity===s).length])) as Record<Severity,number>;
 return {target,findings,summary};
}