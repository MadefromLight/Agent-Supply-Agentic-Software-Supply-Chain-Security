export interface AgentManifest { name:string; runtime?:string; permissions?:string[]; tools?:Array<{name:string;source?:string;version?:string}>; dependencies?:Record<string,string>; scripts?:Record<string,string>; credentials?:string[]; }
export type Severity="low"|"medium"|"high"|"critical";
export interface Finding { id:string; severity:Severity; title:string; message:string; path:string; remediation:string; }
export interface ScanReport { target:string; findings:Finding[]; summary:Record<Severity,number>; }