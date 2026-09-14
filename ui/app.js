const $ = id => document.getElementById(id);
const httpMode = window.__SYSLOG_HTTP__ === true;
const invoke = window.__TAURI__?.core.invoke ?? (httpMode ? async (command,args={}) => {
  const response = await fetch(`/api/${command}`, {method:'POST',headers:{'Content-Type':'application/json','X-Syslog-UI':'1'},body:JSON.stringify(args)});
  const result = await response.json();
  if(response.status===401){if(!loggingOut)window.location.assign('/auth/login');throw new Error('Sign in required');}
  if(!response.ok)throw new Error(result.error || 'Agent request failed');
  return result;
} : null);
if(httpMode){
  $('session-note').textContent='Counters reset on each start. Queue depth includes in-flight messages. Kernel and network loss may be unobservable. Closing this browser does not stop the agent.';
  $('load-config').textContent='Reload configuration';
  $('save-config').textContent='Save configuration';
  document.querySelectorAll('[data-pick]').forEach(el=>{el.hidden=true;});
  document.querySelectorAll('.file-input input').forEach(el=>{el.placeholder='Path on the agent machine';});
  document.querySelector('.local-label').textContent='Browser connected to agent';
}
let loggingOut = false;
$('user-account').hidden=!httpMode||window.__SYSLOG_OIDC__!==true;
function closeUserMenu(restoreFocus=false){
  $('user-menu').hidden=true;
  $('user-menu-toggle').setAttribute('aria-expanded','false');
  if(restoreFocus)$('user-menu-toggle').focus();
}
$('user-menu-toggle').addEventListener('click',()=>{
  const open=$('user-menu').hidden;
  $('user-menu').hidden=!open;
  $('user-menu-toggle').setAttribute('aria-expanded',String(open));
});
document.addEventListener('click',event=>{
  if(!$('user-account').contains(event.target))closeUserMenu();
});
document.addEventListener('keydown',event=>{
  if(event.key==='Escape'&&!$('user-menu').hidden)closeUserMenu(true);
});
$('oidc-logout').addEventListener('click',()=>action(async()=>{
  loggingOut=true;
  try{
    const response=await fetch('/auth/logout',{method:'POST',headers:{'X-Syslog-UI':'1'}});
    if(!response.ok)throw new Error('Could not sign out');
    const result=await response.json();
    closeUserMenu();
    window.location.assign(result.redirect==='/auth/end-session'?'/auth/end-session':'/auth/signed-out');
  }catch(error){loggingOut=false;throw error;}
}));
async function loadUser(){
  if($('user-account').hidden)return;
  const response=await fetch('/auth/session',{method:'GET'});
  if(response.status===401){window.location.assign('/auth/login');return;}
  if(!response.ok)throw new Error('Could not load signed-in user');
  const session=await response.json();
  $('user-menu-name').textContent=session.username;
}
let running = false, busy = false, config, allowedIps = [], activeTab = 'overview';
const count = value => new Intl.NumberFormat().format(value ?? 0);
const timestamp = value => value ? new Date(value).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}) : '—';
const bytes = value => value >= 1048576 ? `${(value/1048576).toFixed(1).replace('.0','')} MiB` : value >= 1024 ? `${(value/1024).toFixed(1)} KiB` : `${value} B`;
const set = (id,value) => { $(id).textContent = value; };
function notice(message,error=false) {
  for(const id of ['notice','relay-notice']) {
    set(id,message);
    $(id).classList.toggle('error',error);
  }
  noticeVisibility();
}
function noticeVisibility() {
  $('notice').hidden=activeTab==='overview'||!$('notice').textContent;
  $('relay-notice').hidden=!$('relay-notice').textContent;
}
function tab(name) {
  activeTab=name;
  noticeVisibility();
  document.querySelectorAll('.page').forEach(el=>{el.hidden=el.id!==name;});
  document.querySelectorAll('.nav-item').forEach(el=>el.classList.toggle('active',el.dataset.tab===name));
  set('page-name',{overview:'Overview',settings:'Connection',diagnostics:'Diagnostics'}[name]);
  window.scrollTo(0,0);
}
document.querySelectorAll('[data-tab]').forEach(el=>el.addEventListener('click',()=>tab(el.dataset.tab)));
document.querySelector('.brand').addEventListener('click',e=>{e.preventDefault();tab('overview');});
function controls() {
  $('config-fields').disabled=running||busy;
  for(const id of ['load-config','save-config','validate-config','start-from-settings']) $(id).disabled=busy||running||!invoke;
  updateAccessControls();
  updateOidcControls();
  $('toggle-relay').disabled=busy||!invoke;
  $('toggle-relay').classList.toggle('danger',running);
  set('toggle-relay',busy?'Working…':running?'■  Stop relay':'▶  Start relay');
}
async function action(fn) {
  if(busy)return;
  if(!invoke){notice('Open this interface in the desktop application to control the relay.',true);return;}
  busy=true;controls();
  try{await fn();}catch(error){notice(String(error),true);}finally{busy=false;controls();}
}
const fields={
 'oidc-enabled':c=>String(c.http?.oidc?.enabled??false),
 'oidc-discovery':c=>c.http?.oidc?.discovery_uri??'','oidc-client-id':c=>c.http?.oidc?.client_id??'',
 'oidc-client-secret':c=>c.http?.oidc?.client_secret??'','oidc-public-url':c=>c.http?.oidc?.public_url??'',
 'oidc-groups-claim':c=>c.http?.oidc?.groups_claim??'groups','oidc-required-group':c=>c.http?.oidc?.required_group??'',
 'oidc-scopes':c=>(c.http?.oidc?.scopes??[]).join(' '),
 'http-address':c=>c.http?.address??'127.0.0.1','http-port':c=>c.http?.port??1080,
 'listen-address':c=>c.listener.address,'listen-port':c=>c.listener.port,'max-input':c=>c.listener.max_message_bytes,
 'remote-host':c=>c.remote.host,'remote-port':c=>c.remote.port,'server-name':c=>c.remote.expected_server_name??'',
 'client-cert':c=>c.identity.certificate_chain,'client-key':c=>c.identity.private_key,'ca-bundle':c=>c.trust.ca_bundle,
 'max-messages':c=>c.queue.max_messages,'max-bytes':c=>c.queue.max_bytes,
 'datagram-bytes':c=>c.dtls.datagram_bytes,'send-rate':c=>c.dtls.messages_per_second,'drain-timeout':c=>c.dtls.shutdown_drain_ms,
 'handshake-timeout':c=>c.dtls.handshake_timeout_ms,'retry-initial':c=>c.dtls.retry_initial_ms,'retry-max':c=>c.dtls.retry_max_ms
};
function populate(c){config=c;for(const[id,get]of Object.entries(fields))$(id).value=get(c);$('source-mode').value=c.source_access?.mode??'any';allowedIps=[...(c.source_access?.allowed_ips??[])];renderAllowlist();updateOidcControls();preview();}
function read(){
  const value=id=>String($(id).value).trim(),num=id=>Number($(id).value);
  return{schema_version:1,http:{address:value('http-address')||'127.0.0.1',port:value('http-port')?num('http-port'):1080,oidc:{enabled:value('oidc-enabled')==='true',discovery_uri:value('oidc-discovery'),client_id:value('oidc-client-id'),client_secret:String($('oidc-client-secret').value),public_url:value('oidc-public-url'),groups_claim:value('oidc-groups-claim')||'groups',required_group:value('oidc-required-group'),scopes:value('oidc-scopes').split(/\s+/).filter(Boolean)}},source_access:{mode:$('source-mode').value,allowed_ips:[...allowedIps]},listener:{address:value('listen-address'),port:num('listen-port'),max_message_bytes:num('max-input')},remote:{host:value('remote-host'),port:num('remote-port'),expected_server_name:value('server-name')||null},identity:{provider:'pem',certificate_chain:value('client-cert'),private_key:value('client-key')},trust:{provider:'pem_ca',ca_bundle:value('ca-bundle')},queue:{max_messages:num('max-messages'),max_bytes:num('max-bytes')},dtls:{datagram_bytes:num('datagram-bytes'),messages_per_second:num('send-rate'),shutdown_drain_ms:num('drain-timeout'),handshake_timeout_ms:num('handshake-timeout'),retry_initial_ms:num('retry-initial'),retry_max_ms:num('retry-max')}};
}
function preview(){if(!running){set('listener-endpoint',`${$('listen-address').value}:${$('listen-port').value}`);set('remote-endpoint',`${$('remote-host').value||'Not configured'}:${$('remote-port').value}`);set('queue-limit',count(Number($('max-messages').value)));}}
$('config-form').addEventListener('input',preview);
$('config-form').addEventListener('submit',e=>e.preventDefault());
function render(s){
  running=s.running;
  const state=s.dtls_status||'stopped';
  set('overall-state',running?(state==='established'?'Association established':state[0].toUpperCase()+state.slice(1)):'Stopped');
  $('overall-state').className=`badge ${running?(state==='established'?'ok':'pending'):''}`;
  set('listener-state',s.listener_status==='listening'?'Listening · UDP':s.listener_status||'Not listening');
  set('dtls-state',state==='established'?'DTLS 1.2 · verified peer':state==='stopped'?'No association':state);
  if(running){set('listener-endpoint',s.listener_address);set('remote-endpoint',s.remote_destination);}
  for(const[id,key]of Object.entries({received:'messages_received',forwarded:'messages_forwarded',dropped:'messages_dropped','queue-depth':'queue_depth','retry-count':'retry_attempts'}))set(id,count(s[key]));
  const limits=config?.queue??{max_messages:10000,max_bytes:16777216};
  set('queue-limit',count(limits.max_messages));
  $('queue-progress').max=100; $('queue-progress').value=Math.max((s.queue_depth||0)/limits.max_messages,(s.queue_bytes||0)/limits.max_bytes)*100;
  set('queue-bytes',`${bytes(s.queue_bytes||0)} of ${bytes(limits.max_bytes)}`);set('in-flight',s.in_flight?'1 write in progress':'No write in progress');
  for(const[id,key]of Object.entries({'last-received':'last_received_ms','last-forwarded':'last_forwarded_ms','last-handshake':'last_handshake_ms'})){set(id,timestamp(s[key]));$(id).title=s[key]?new Date(s[key]).toLocaleString():'';}
  for(const[id,key]of Object.entries({'drop-denied':'source_denied','drop-invalid':'invalid','drop-oversized':'oversized','drop-full':'queue_full','drop-shutdown':'shutdown'}))set(id,count(s.drops?.[key]));
  for(const[id,key]of Object.entries({'active-address':'remote_address',protocol:'protocol',cipher:'cipher','client-fingerprint':'client_fingerprint','peer-fingerprint':'peer_fingerprint'}))set(id,s[key]||'—');
  renderSources(s);
  $('last-error-panel').hidden=!s.last_error;set('last-error',s.last_error||'');controls();
}
async function startRelay(){
  if(!validForm())return;
  config=read();
  const result=await invoke('start',{config});
  render(result);notice('Relay started. The listener is active while DTLS connects.');tab('overview');
}
function validForm(){
  const fields=$('config-fields');
  fields.disabled=false;
  const valid=$('config-form').checkValidity();
  if(!valid){tab('settings');$('config-form').reportValidity();}
  controls();
  return valid;
}
$('toggle-relay').addEventListener('click',()=>action(async()=>{if(running){render(await invoke('stop'));notice('Relay stopped. Pending messages were drained or counted as shutdown drops.');}else await startRelay();}));
$('start-from-settings').addEventListener('click',()=>action(startRelay));
$('load-config').addEventListener('click',()=>action(async()=>{const result=await invoke('load_config');if(result){populate(result);notice('Configuration loaded. Start the relay to apply it.');}}));
$('save-config').addEventListener('click',()=>action(async()=>{if(validForm()&&await invoke('save_config',{config:read()}))notice('Configuration saved. HTTP listener and login changes apply after restarting the agent process.');}));
$('validate-config').addEventListener('click',()=>action(async()=>{if(validForm())notice(await invoke('validate',{config:read()}));}));
document.querySelectorAll('[data-pick]').forEach(el=>el.addEventListener('click',()=>action(async()=>{const path=await invoke('pick_file');if(path)$(el.dataset.pick).value=path;})));
async function refresh(){
  if(!busy&&invoke){try{render(await invoke('status'));}catch{notice('Cannot read relay status from the agent.',true);}}
  setTimeout(refresh,500);
}
if(invoke){try{await loadUser();populate(await invoke('default_config'));render(await invoke('status'));refresh();}catch(error){notice(String(error),true);}}
else{notice('Desktop preview. Launch the Tauri application to configure and run the relay.');}
controls();

function updateAccessControls(){
  const enabled=$('source-mode').value==='allowlist';
  $('allowlist-editor').hidden=!enabled;
  $('allowlist-ip').disabled=!enabled||running||busy;
  $('add-allowed-ip').disabled=!enabled||running||busy||!invoke;
}
function renderAllowlist(){
  $('allowed-ip-list').replaceChildren();
  for(const ip of allowedIps){
    const item=document.createElement('li');
    const label=document.createElement('span');label.textContent=ip;
    const remove=document.createElement('button');remove.type='button';remove.className='text-button';remove.textContent='Remove';remove.setAttribute('aria-label',`Remove ${ip}`);
    remove.addEventListener('click',()=>{if(running||busy)return;allowedIps=allowedIps.filter(value=>value!==ip);renderAllowlist();});
    item.append(label,remove);$('allowed-ip-list').append(item);
  }
  $('allowlist-empty').hidden=allowedIps.length>0;
  updateAccessControls();
}
$('source-mode').addEventListener('change',updateAccessControls);
async function addAllowedIp(){
  const ip=await invoke('normalize_source_ip',{ip:$('allowlist-ip').value.trim()});
  if(!allowedIps.includes(ip))allowedIps.push(ip);
  $('allowlist-ip').value='';renderAllowlist();
}
$('add-allowed-ip').addEventListener('click',()=>action(addAllowedIp));
$('allowlist-ip').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();if(!running&&!busy&&$('source-mode').value==='allowlist')action(addAllowedIp);}});
function renderSources(s){
  const sources=s.sources??[];
  set('source-count',`${count(sources.length)} SOURCES`);
  $('source-rows').replaceChildren();
  for(const source of sources){
    const row=document.createElement('tr');
    const values=[source.ip,source.allowed?'Allowed':'Blocked',count(source.messages_received),count(source.messages_forwarded),count(source.messages_per_second),count(source.messages_per_minute),count(source.messages_last_24h),count(source.messages_dropped),timestamp(source.last_seen_ms)];
    values.forEach((value,index)=>{const cell=document.createElement('td');cell.textContent=value;if(index===1)cell.className=source.allowed?'source-allowed':'source-blocked';row.append(cell);});
    $('source-rows').append(row);
  }
  $('sources-empty').hidden=sources.length>0;
  const overflow=s.untracked_source_messages??0;
  $('source-overflow').hidden=overflow===0;
  set('source-overflow',`${count(overflow)} datagrams from additional IPs are not individually tracked: the ${count(s.source_tracking_limit??256)}-source limit is reached. Filtering and global counters still apply.`);
}

function updateOidcControls(){
  const enabled=$('oidc-enabled').value==='true';
  $('oidc-fields').hidden=!enabled;
  for(const id of ['oidc-discovery','oidc-client-id','oidc-public-url','oidc-required-group'])$(id).required=enabled;
}
$('oidc-enabled').addEventListener('change',updateOidcControls);
