import {readFile} from "node:fs/promises";
import {scanManifest} from "./scanner.js";
const target=process.argv[2];
if(!target){console.error("Usage: npm run scan -- ./manifest.json");process.exit(1);}
const manifest=JSON.parse(await readFile(target,"utf8"));
console.log(JSON.stringify(scanManifest(manifest,target),null,2));