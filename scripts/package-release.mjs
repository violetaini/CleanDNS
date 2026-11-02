import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const arch=process.argv[2], nodeBinary=process.argv[3], goBinary=process.argv[4];
if(!['amd64','arm64'].includes(arch)||!nodeBinary||!goBinary)throw new Error('Usage: node scripts/package-release.mjs amd64|arm64 NODE_BINARY GO_BINARY');
const version=fs.readFileSync(path.join(root,'VERSION'),'utf8').trim();
if(!/^\d+\.\d+\.\d+$/.test(version))throw new Error('Invalid VERSION');
const base=path.join(root,'dist',arch), stage=path.join(base,'CleanDNS');
if(fs.existsSync(stage))throw new Error('Package staging directory already exists');
fs.mkdirSync(stage,{recursive:true});
const tracked=execFileSync('git',['ls-files','-z'],{cwd:root}).toString().split('\0').filter(Boolean);
const include=file=> /^[^/]+\.js$/.test(file)||['start.mjs','setup.html','panel.html','favicon.ico','VERSION','package.json','package-lock.json','config.example.json','install.sh','README.md','README_zh.md','README_zh-TW.md','README_ja.md'].includes(file)||file.startsWith('assets/')||file.startsWith('docs/')||file.startsWith('nginx/')||file.startsWith('systemd/')||['bin/apply-doq-port','bin/apply-nginx-doh-path','cmd/update-blocked-services.mjs','data/blocked-services.json'].includes(file);
for(const file of tracked.filter(include)){
  const destination=path.join(stage,file);fs.mkdirSync(path.dirname(destination),{recursive:true});
  if(/\.(js|mjs|html|md|json)$/.test(file)||file==='VERSION'||file==='install.sh'||file.startsWith('bin/')||file.startsWith('systemd/')||file.startsWith('nginx/'))fs.writeFileSync(destination,fs.readFileSync(path.join(root,file),'utf8').replace(/\r\n/g,'\n'));
  else fs.copyFileSync(path.join(root,file),destination);
  fs.chmodSync(destination,file.startsWith('bin/')||file==='install.sh'?0o755:0o644);
}
for(const [source,destination]of [[nodeBinary,'runtime/bin/node'],[goBinary,'bin/cleandns-dns']]){const target=path.join(stage,destination);fs.mkdirSync(path.dirname(target),{recursive:true});fs.copyFileSync(source,target);fs.chmodSync(target,0o755);}
const nodeLicense=path.resolve(nodeBinary,'../../LICENSE');
if(!fs.existsSync(nodeLicense))throw new Error('Official Node distribution LICENSE is required');
fs.copyFileSync(nodeLicense,path.join(stage,'runtime/LICENSE'));
for(const line of execFileSync('go',['list','-m','-f','{{.Path}}\t{{.Dir}}','all'],{cwd:root}).toString().trim().split('\n')){
  const [name,dir]=line.trim().split('\t');if(!dir||name==='cleandns')continue;
  const license=['LICENSE','LICENSE.md','LICENSE.txt','COPYING'].find(file=>fs.existsSync(path.join(dir,file)));
  if(!license)throw new Error('Missing third-party license for '+name);
  const target=path.join(stage,'third-party-licenses',name.replaceAll('/','_')+'.txt');fs.mkdirSync(path.dirname(target),{recursive:true});fs.copyFileSync(path.join(dir,license),target);
}
for(const file of ['start.mjs','setup.js','setup.html','server.js'])if(!fs.existsSync(path.join(stage,file)))throw new Error('Missing release file '+file+'; ensure it is tracked in git.');
const output=path.join(root,'dist',`CleanDNS_v${version}_linux_${arch}.tar.gz`);
execFileSync('tar',['-czf',output,'-C',base,'CleanDNS']);console.log(output);
