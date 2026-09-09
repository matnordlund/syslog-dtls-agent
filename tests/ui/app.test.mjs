import { readFile } from 'node:fs/promises';
import test from 'node:test';
import assert from 'node:assert/strict';

const source = await readFile(new URL('../../ui/app.js',import.meta.url),'utf8');
const html = await readFile(new URL('../../ui/index.html',import.meta.url),'utf8');
const defaults = {schema_version:1,listener:{address:'127.0.0.1',port:1514,max_message_bytes:8192},remote:{host:'collector.test',port:6514,expected_server_name:null},identity:{provider:'pem',certificate_chain:'/cert.pem',private_key:'/key.pem'},trust:{provider:'pem_ca',ca_bundle:'/ca.pem'},queue:{max_messages:10000,max_bytes:16777216},dtls:{handshake_timeout_ms:10000,retry_initial_ms:1000,retry_max_ms:60000,datagram_bytes:1200,messages_per_second:1000,shutdown_drain_ms:2000}};
const stopped = {running:false,dtls_status:'stopped',messages_received:0,messages_forwarded:0,messages_dropped:0,queue_depth:0,queue_bytes:0};
class Element {
  value='';textContent='';disabled=false;hidden=false;dataset={};events={};valid=true;
  classList={toggle(){}};
  children=[];attributes={};
  append(...elements){this.children.push(...elements);}
  replaceChildren(...elements){this.children=[...elements];}
  setAttribute(key,value){this.attributes[key]=value;}
  addEventListener(name,fn){this.events[name]=fn;}
  checkValidity(){return this.valid;}
  reportValidity(){return this.valid;}
  async click(){await this.events.click?.({preventDefault(){}});}
}
async function mount(overrides={}){
  const elements=new Map([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1],new Element()]));
  const nav=['overview','settings','diagnostics'].map(name=>{const e=new Element();e.dataset.tab=name;return e;});
  const brand=new Element();
  const calls=[];
  const handlers={default_config:()=>structuredClone(defaults),status:()=>stopped,start:()=>({...stopped,running:true,dtls_status:'handshaking'}),stop:()=>stopped,...overrides};
  const invoke=async(name,args)=>{calls.push({name,args});return handlers[name]?.(args);};
  const doc={createElement:()=>new Element(),getElementById:id=>{assert.ok(elements.has(id),`Missing DOM id: ${id}`);return elements.get(id);},querySelector:()=>brand,querySelectorAll:selector=>selector==='[data-tab]'||selector==='.nav-item'?nav:selector==='.page'?['overview','settings','diagnostics'].map(id=>Object.assign(elements.get(id),{id})):[]};
  const fn=new (Object.getPrototypeOf(async function(){}).constructor)('window','document','setTimeout',source);
  await fn({__TAURI__:{core:{invoke}},scrollTo(){}},doc,()=>{});
  return{get:id=>elements.get(id),calls};
}
test('start sends configurable input port and secret references; locks settings until stopped',async()=>{
  const {get,calls}=await mount();
  assert.equal(get('listen-port').value,1514);
  get('listen-port').value='2514';
  await get('toggle-relay').click();
  const sent=calls.find(c=>c.name==='start').args.config;
  assert.equal(sent.listener.port,2514);assert.deepEqual(sent.identity,defaults.identity);
  assert.equal(get('config-fields').disabled,true);
  await get('toggle-relay').click();
  assert.equal(get('config-fields').disabled,false);
  assert.equal(calls.filter(c=>c.name==='stop').length,1);
});
test('invalid form prevents starting; backend errors return controls to editable state',async()=>{
  const {get,calls}=await mount({start:()=>{throw new Error('Server identity invalid');}});
  get('config-form').valid=false;
  await get('toggle-relay').click();
  assert.equal(calls.some(c=>c.name==='start'),false);
  get('config-form').valid=true;
  await get('toggle-relay').click();
  assert.match(get('notice').textContent,/Server identity invalid/);
  assert.equal(get('toggle-relay').disabled,false);assert.equal(get('config-fields').disabled,false);
});
test('status errors and metadata render as literal text rather than HTML',async()=>{
  const payload='<img src=x onerror=alert(1)>';
  const {get}=await mount({status:()=>({...stopped,last_error:payload,peer_fingerprint:payload})});
  assert.equal(get('last-error').textContent,payload);assert.equal(get('peer-fingerprint').textContent,payload);
  assert.equal(get('last-error-panel').hidden,false);
});
test('allowlist add/remove preserves entries when toggled and serializes settings',async()=>{
  const {get,calls}=await mount({normalize_source_ip:({ip})=>ip==='::ffff:127.0.0.1'?'127.0.0.1':ip});
  assert.equal(get('source-mode').value,'any');
  get('source-mode').value='allowlist';get('source-mode').events.change();
  get('allowlist-ip').value='::ffff:127.0.0.1';await get('add-allowed-ip').click();
  get('allowlist-ip').value='127.0.0.1';await get('add-allowed-ip').click();
  assert.equal(get('allowed-ip-list').children.length,1);
  get('allowlist-ip').value='::1';await get('add-allowed-ip').click();
  await get('allowed-ip-list').children[0].children[1].click();
  get('source-mode').value='any';get('source-mode').events.change();
  assert.equal(get('allowlist-editor').hidden,true);
  get('source-mode').value='allowlist';get('source-mode').events.change();
  await get('toggle-relay').click();
  assert.deepEqual(calls.find(c=>c.name==='start').args.config.source_access,{mode:'allowlist',allowed_ips:['::1']});
});
test('source table renders forwarded rates, blocked status and tracking overflow',async()=>{
  const source={ip:'192.0.2.1',allowed:false,messages_received:6,messages_forwarded:0,messages_dropped:6,messages_per_second:0,messages_per_minute:0,messages_last_24h:0,last_seen_ms:1};
  const {get}=await mount({status:()=>({...stopped,sources:[source],untracked_source_messages:2,source_tracking_limit:256})});
  assert.deepEqual(get('source-rows').children[0].children.slice(0,8).map(e=>e.textContent),['192.0.2.1','Blocked','6','0','0','0','0','6']);
  assert.equal(get('sources-empty').hidden,true);
  assert.equal(get('source-overflow').hidden,false);
  assert.match(get('source-overflow').textContent,/2 datagrams/);
});
