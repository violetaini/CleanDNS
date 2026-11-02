import assert from 'node:assert/strict';
import { DynamicAccess, normalizeAllowedDomains, normalizeDynamicRefresh } from '../dynamic-access.js';
import { normalizeProtocolAccess } from '../protocol-access.js';

assert.deepEqual(normalizeAllowedDomains('# note\nHOME.Example.COM.\nhome.example.com'), ['home.example.com']);
assert.deepEqual(normalizeAllowedDomains(['例子.测试']), ['xn--fsqu00a.xn--0zwm56d']);
for (const bad of [null, {}, [1], ['https://home.example.com'], ['*.example.com'], ['127.0.0.1'], ['2001:db8::1'], ['-home.example.com'], ['example.com/path'], ['example.com:53'], ['localhost'], Array.from({length:65},(_,i)=>`${i}.example.com`)]) assert.throws(()=>normalizeAllowedDomains(bad));
for (const bad of [null, true, '', -1, 1, 9, 86401, 12.5]) assert.throws(()=>normalizeDynamicRefresh(bad));
assert.equal(normalizeDynamicRefresh(),0);assert.equal(normalizeDynamicRefresh('30'),30);
const normalized = normalizeProtocolAccess({doh:{mode:'custom',allowedDomains:['home.example.com']}}, value=>value);
assert.deepEqual(normalized.doh.allowedDomains,['home.example.com']);
let clock=1000000, failure='', v4='192.0.2.1', v6='2001:db8::1', ttl=20, calls=0;
const manager = new DynamicAccess({now:()=>clock,timers:false,lookup:async(host,family)=>{
 calls++; if(failure)throw Object.assign(new Error('fixture'),{code:failure});return [{address:family===4?v4:v6,ttl:family===4?ttl:ttl*2}];
}});
const access={allowedDomains:['home.example.com'],protocols:normalized,dynamicRefreshSeconds:0};manager.configure(access);
assert.deepEqual(manager.addresses(access.allowedDomains),[],'first resolution must fail closed');
await manager.refresh();assert.deepEqual(manager.addresses(access.allowedDomains),[v4,v6]);assert.equal(calls,2,'a shared domain is resolved once per family');
let state=manager.snapshot().domains[0];assert.equal(state.families[0].nextCheckAt,clock+20000);assert.equal(state.families[1].nextCheckAt,clock+40000);
clock+=20001;v4='192.0.2.2';await manager.refresh();assert.deepEqual(manager.addresses(access.allowedDomains),[v4,v6]);assert.equal(calls,3,'only due families refresh');
failure='ETIMEOUT';clock+=40000;await manager.refresh();assert.ok(manager.addresses(access.allowedDomains).length);assert.equal(manager.snapshot().domains[0].families[0].state,'stale');
clock+=310000;assert.deepEqual(manager.addresses(access.allowedDomains),[],'time passing alone expires old IPs, even without a timer');
failure='';manager.requestRefresh();await manager.refresh();assert.deepEqual(manager.addresses(access.allowedDomains),[v4,v6]);assert.equal(manager.requestRefresh(),false,'manual checks are throttled');
clock+=10001;failure='ENODATA';manager.requestRefresh();await manager.refresh();assert.deepEqual(manager.addresses(access.allowedDomains),[],'explicit negative response withdraws addresses immediately');
failure='';ttl=1;clock+=30001;await manager.refresh();assert.equal(manager.snapshot().domains[0].families[0].nextCheckAt,clock+10000,'TTL floor prevents busy loops');
manager.configure({...access,dynamicRefreshSeconds:60});clock+=10001;await manager.refresh();assert.equal(manager.snapshot().domains[0].families[0].nextCheckAt,clock+60000,'manual interval overrides TTL');
manager.configure({allowedDomains:[],protocols:{doh:{mode:'inherit',allowedDomains:access.allowedDomains}}});assert.equal(manager.snapshot().domains.length,0,'dormant protocol domains are not queried');manager.close();

// Removing a domain cannot resurrect its in-flight results.
let release;const deferred=new Promise(resolve=>{release=resolve;});
const removed = new DynamicAccess({timers:false,lookup:()=>deferred});removed.configure(access);const inFlight=removed.refresh();removed.configure({allowedDomains:[]});release([{address:'192.0.2.99',ttl:10}]);await inFlight;assert.deepEqual(removed.addresses(access.allowedDomains),[]);removed.close();
console.log('dynamic access tests passed: validation, TTL/fixed scheduling, IP replacement, per-family freshness, bounded stale cache, negative withdrawal, throttling, removal races');
