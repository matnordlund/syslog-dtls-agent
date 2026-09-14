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
  focus(){this.focused=true;}
  contains(target){return this===target||this.children.includes(target);}
  checkValidity(){return this.valid;}
  reportValidity(){return this.valid;}
  async click(){await this.events.click?.({preventDefault(){}});}
}
async function mount(overrides={},http=false,oidc=false){
  const elements=new Map([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1],new Element()]));
  const nav=['overview','settings','diagnostics'].map(name=>{const e=new Element();e.dataset.tab=name;return e;});
  const brand=new Element();
  const calls=[];
  const handlers={default_config:()=>structuredClone(defaults),status:()=>stopped,start:()=>({...stopped,running:true,dtls_status:'handshaking'}),stop:()=>stopped,...overrides};
  const invoke=async(name,args)=>{calls.push({name,args});return handlers[name]?.(args);};
  const documentEvents={};
  const navigations=[];
  const doc={addEventListener:(name,fn)=>{documentEvents[name]=fn;},createElement:()=>new Element(),getElementById:id=>{assert.ok(elements.has(id),`Missing DOM id: ${id}`);return elements.get(id);},querySelector:()=>brand,querySelectorAll:selector=>selector==='[data-tab]'||selector==='.nav-item'?nav:selector==='.page'?['overview','settings','diagnostics'].map(id=>Object.assign(elements.get(id),{id})):[]};
  const fn=new (Object.getPrototypeOf(async function(){}).constructor)('window','document','setTimeout','fetch',source);
  const browserFetch=async(url,options)=>{
    if(url==='/auth/session'){assert.equal(options.method,'GET');return{ok:true,json:async()=>({username:overrides.username??'test-user'})};}
    if(url==='/auth/logout'){assert.equal(options.method,'POST');assert.equal(options.headers['X-Syslog-UI'],'1');return{ok:true,json:async()=>({redirect:overrides.logoutRedirect??'/auth/signed-out'})};}
    assert.equal(options.method,'POST');
    assert.equal(options.headers['X-Syslog-UI'],'1');
    const result=await invoke(url.slice('/api/'.length),JSON.parse(options.body));
    return{ok:true,json:async()=>result};
  };
  await fn(http?{__SYSLOG_HTTP__:true,__SYSLOG_OIDC__:oidc,location:{assign:value=>navigations.push(value)},scrollTo(){}}:{__TAURI__:{core:{invoke}},scrollTo(){}},doc,()=>{},browserFetch);
  return{get:id=>elements.get(id),calls,nav,documentEvents,navigations};
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

test('relay notices stay inside Overview and remain visible when navigating to settings',async()=>{
  const {get,nav}=await mount();
  await get('toggle-relay').click();
  assert.match(get('relay-notice').textContent,/Relay started/);
  assert.equal(get('relay-notice').hidden,false);
  assert.equal(get('notice').hidden,true);
  await nav[1].click();
  assert.equal(get('notice').hidden,false);
  await nav[0].click();
  assert.equal(get('notice').hidden,true);
  await get('toggle-relay').click();
  assert.match(get('relay-notice').textContent,/Relay stopped/);
});

test('HTTP bridge uses agent API for status and relay controls',async()=>{
  const {get,calls}=await mount({},true);
  assert.equal(get('load-config').textContent,'Reload configuration');
  assert.equal(get('save-config').textContent,'Save configuration');
  await get('toggle-relay').click();
  assert.ok(calls.some(call=>call.name==='start'));
  assert.equal(get('config-fields').disabled,true);
  await get('toggle-relay').click();
  assert.ok(calls.some(call=>call.name==='stop'));
});

test('HTTP settings load defaults, save edits and fall back when blank',async()=>{
  const {get,calls}=await mount({save_config:()=>true},true);
  assert.equal(get('http-address').value,'127.0.0.1');
  assert.equal(get('http-port').value,1080);
  get('http-address').value='::1'; get('http-port').value='2080';
  await get('save-config').click();
  assert.equal(calls.filter(c=>c.name==='save_config').at(-1).args.config.http.port,2080);
  assert.equal(calls.filter(c=>c.name==='save_config').at(-1).args.config.http.address,'::1');
  assert.match(get('notice').textContent,/restarting the agent process/);
  get('http-address').value=' '; get('http-port').value='';
  await get('save-config').click();
  assert.equal(calls.filter(c=>c.name==='save_config').at(-1).args.config.http.port,1080);
  assert.equal(calls.filter(c=>c.name==='save_config').at(-1).args.config.http.address,'127.0.0.1');
});

test('OIDC settings are optional, editable, and serialize a client secret for TOML persistence',async()=>{
  const {get,calls}=await mount({save_config:()=>true},true);
  assert.match(html,/id="oidc-client-secret" type="password"/);
  assert.equal(get('oidc-enabled').value,'false');
  assert.equal(get('oidc-fields').hidden,true);
  get('oidc-enabled').value='true';get('oidc-enabled').events.change();
  assert.equal(get('oidc-fields').hidden,false);
  assert.equal(get('oidc-required-group').required,true);
  get('oidc-discovery').value='http://id.internal/custom-discovery.json';
  get('oidc-client-id').value='agent';
  get('oidc-client-secret').value='  test-secret  ';
  get('oidc-public-url').value='https://agent.example';
  get('oidc-groups-claim').value='roles';
  get('oidc-required-group').value='operators';
  get('oidc-scopes').value='profile   groups';
  await get('save-config').click();
  assert.deepEqual(calls.find(c=>c.name==='save_config').args.config.http.oidc,{
    enabled:true,discovery_uri:'http://id.internal/custom-discovery.json',client_id:'agent',client_secret:'  test-secret  ',
    public_url:'https://agent.example',groups_claim:'roles',required_group:'operators',scopes:['profile','groups']
  });
});

test('account menu shows identity as text, closes accessibly, and signs out via provider continuation',async()=>{
  const username='<img src=x onerror=alert(1)>';
  const {get,documentEvents,navigations}=await mount({username,logoutRedirect:'/auth/end-session'},true,true);
  assert.equal(get('user-account').hidden,false);
  assert.equal(get('user-menu-name').textContent,username);
  get('user-menu').hidden=true;
  await get('user-menu-toggle').click();
  assert.equal(get('user-menu').hidden,false);
  assert.equal(get('user-menu-toggle').attributes['aria-expanded'],'true');
  documentEvents.keydown({key:'Escape'});
  assert.equal(get('user-menu').hidden,true);
  assert.equal(get('user-menu-toggle').focused,true);
  await get('user-menu-toggle').click();
  documentEvents.click({target:new Element()});
  assert.equal(get('user-menu').hidden,true);
  await get('oidc-logout').click();
  assert.deepEqual(navigations,['/auth/end-session']);
});
test('account menu is hidden without OIDC and logout supports a local fallback',async()=>{
  const native=await mount();assert.equal(native.get('user-account').hidden,true);
  const browser=await mount({},true);assert.equal(browser.get('user-account').hidden,true);
  const signedIn=await mount({},true,true);
  await signedIn.get('oidc-logout').click();
  assert.deepEqual(signedIn.navigations,['/auth/signed-out']);
});
