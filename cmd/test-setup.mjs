import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { startSetup } from '../setup.js';

const root=fs.mkdtempSync(path.join(os.tmpdir(),'cleandns-setup-test-')), app=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const configPath=path.join(root,'config.json'), dataDir=path.join(root,'data');let setup,child;
const freePort=async()=>{const server=net.createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;};
try{
 const settings={httpHost:'127.0.0.1',httpPort:await freePort(),corePort:await freePort(),plainHost:'127.0.0.1',plainPort:await freePort(),plainEnabled:true,upstreams:'1.1.1.1',username:'test',password:'first-run-test-password',confirmPassword:'first-run-test-password',queryLogEnabled:false};
 if(process.env.CLEANDNS_SETUP_UI_FIXTURE==='1'){
   child=spawn(process.execPath,['start.mjs'],{cwd:app,env:{...process.env,CLEANDNS_CONFIG:configPath,CLEANDNS_DATA_DIR:dataDir,CLEANDNS_SETUP_PORT:'0',CLEANDNS_SETUP_TOKEN_FILE:path.join(dataDir,'setup-token')},stdio:['ignore','pipe','pipe'],windowsHide:true});let output='';child.stdout.on('data',b=>{output+=b;});child.stderr.on('data',()=>{});
   const until=Date.now()+8000;while(!output.includes('Setup access token file:')){assert.equal(child.exitCode,null);assert(Date.now()<until,'fixture timeout');await new Promise(resolve=>setTimeout(resolve,20));}
   const base=output.match(/http:\/\/127.0.0.1:(\d+)\/setup\//)[0];console.log('FIXTURE_READY '+JSON.stringify({base,token:fs.readFileSync(path.join(dataDir,'setup-token'),'utf8').trim(),settings}));process.stdin.resume();await new Promise(resolve=>process.stdin.once('end',resolve));
 }else{
   const tokenFile=path.join(dataDir,'setup-token');let completed=0;
   setup=await startSetup({configPath,dataDir,port:0,tokenFile,onComplete:async()=>{completed++;}});const base=`http://127.0.0.1:${setup.port}`;
   const request=(endpoint,body,token=setup.token,headers={})=>fetch(base+'/api/setup/'+endpoint,{method:body?'POST':'GET',headers:{'content-type':'application/json','x-setup-token':token,...headers},...(body?{body:JSON.stringify(body)}:{})});
   assert.equal((await request('status',null,'invalid')).status,401);assert.equal((await request('status',null,'é'.repeat(64))).status,401);
   const initial=await request('status');assert.equal(initial.status,200);assert.ok(Array.isArray((await initial.json()).interfaces));
   assert.equal((await request('check',settings,setup.token,{origin:'https://untrusted.invalid'})).status,403);
   assert.equal((await fetch(base+'/api/setup/apply',{method:'POST',headers:{'x-setup-token':setup.token,'content-type':'text/plain'},body:JSON.stringify(settings)})).status,415);
   assert.equal((await request('check',settings)).status,200);
   const occupied=net.createServer();await new Promise(resolve=>occupied.listen(settings.httpPort,'127.0.0.1',resolve));assert.equal((await request('check',settings)).status,400);await new Promise(resolve=>occupied.close(resolve));assert(!fs.existsSync(configPath));
   for(const patch of [{httpHost:'not-an-ip'},{httpPort:setup.port},{plainPort:settings.httpPort},{corePort:settings.plainPort},{password:'short',confirmPassword:'short'},{confirmPassword:'different'},{username:'<script>'},{upstreams:'https://bad.invalid/' }]){const r=await request('apply',{...settings,...patch});assert.equal(r.status,400);assert(!fs.existsSync(configPath));}
   const responses=await Promise.all([request('apply',settings),request('apply',settings)]);assert.deepEqual(responses.map(r=>r.status).sort(),[200,409]);
   const saved=JSON.parse(fs.readFileSync(configPath));assert.equal(saved.http.port,settings.httpPort);assert.equal(saved.admin.username,'test');assert.equal(saved.queryLog.enabled,false);assert.equal(saved.service.doqEnabled,false);assert.equal(saved.udp.host,'127.0.0.1');assert(path.isAbsolute(saved.rules.blockFile));
   assert(!fs.readFileSync(configPath,'utf8').includes(settings.password));assert(!fs.existsSync(tokenFile));const [method,salt,expected]=fs.readFileSync(saved.admin.passwordFile,'utf8').trim().split('$');assert.equal(method,'scrypt');assert.equal(crypto.scryptSync(settings.password,salt,64).toString('base64url'),expected);
   await new Promise(resolve=>setTimeout(resolve,300));assert.equal(completed,1);await assert.rejects(()=>startSetup({configPath,dataDir,port:0}),/already_configured/);
   await setup.close();setup=null;
   child=spawn(process.execPath,['start.mjs'],{cwd:app,env:{...process.env,CLEANDNS_CONFIG:configPath},stdio:['ignore','pipe','pipe'],windowsHide:true});let output='';child.stdout.on('data',b=>{output+=b;});child.stderr.on('data',b=>{output+=b;});const until=Date.now()+8000;
   while(!output.includes(`cleandns http listening on 127.0.0.1:${settings.httpPort}`)){assert.equal(child.exitCode,null);assert(Date.now()<until,'configured server startup timeout');await new Promise(resolve=>setTimeout(resolve,20));}
   assert(!output.includes('first-run setup'));assert(!output.includes(settings.password));const api=`http://127.0.0.1:${settings.httpPort}/api`;
   let r=await fetch(api+'/login',{method:'POST',headers:{'content-type':'application/json','x-forwarded-proto':'https'},body:JSON.stringify({username:'test',password:settings.password})});assert.equal(r.status,200);const cookie=r.headers.get('set-cookie');assert(!cookie.includes('Secure'),'untrusted forwarding headers must not force Secure on HTTP');assert(cookie.includes('HttpOnly'));r=await fetch(api+'/settings',{headers:{cookie:cookie.split(';')[0]}});assert.equal(r.status,200);
   assert.equal((await fetch(api+'/setup/apply',{method:'POST',body:'{}'})).status,401);const original=fs.readFileSync(configPath,'utf8');await childStop();assert.equal(fs.readFileSync(configPath,'utf8'),original);
   console.log('first-run setup tests passed: one-time token, Origin/JSON guard, port conflicts, validation, atomic config/password, concurrent commit, existing-instance bypass, HTTP login and restart');
 }
}finally{if(setup)await setup.close();await childStop();const absolute=path.resolve(root);assert(absolute.startsWith(path.resolve(os.tmpdir())+path.sep)&&path.basename(absolute).startsWith('cleandns-setup-test-'));fs.rmSync(absolute,{recursive:true,force:true});}
async function childStop(){const target=child;child=null;if(!target||target.exitCode!==null||target.signalCode!==null)return;target.kill();await new Promise(resolve=>target.once('exit',resolve));}
