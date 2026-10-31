#pragma once
const char PAGE[] = R"HTML(<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>C3 AdBlock</title><link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 16 16%22><text y=%2214%22 font-size=%2214%22>🛡️</text></svg>"><style>
body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d}
h1{margin:0;font-size:18px}h1 span{color:#3fb950}
.wrap{padding:16px;max-width:1000px;margin:auto}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:18px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
th{background:#21262d;color:#8b949e}tr:hover td{background:#1c2128}
.b{color:#f85149}.a{color:#3fb950}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:4px 9px;cursor:pointer}
button:hover{background:#30363d}.ban{color:#f85149}
input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
h2{font-size:14px;color:#8b949e;margin:18px 0 8px}
</style></head><body>
<header><h1>🛡️ C3 AdBlock <span id=host></span>
<button id=langbtn style=float:right onclick=toggleLang()></button></h1></header>
<div class=wrap>
<div id=blockbar style="display:flex;align-items:center;gap:12px;margin-bottom:14px;padding:12px 14px;background:#161b22;border:1px solid #30363d;border-radius:8px">
<span id=blockdot style=font-size:20px>🛡️</span><b id=blockstate style=flex:1 data-on=1></b>
<select id=pausedur style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:5px"></select>
<button id=pausebtn onclick=togglePause()></button></div>
<div class=cards id=sys></div>
<h2 id=h_clients>客户端</h2><div style="max-height:200px;overflow-y:auto;border:1px solid #30363d;border-radius:6px"><table id=ct><thead><tr><th id=th_ip>IP</th><th>MAC</th><th id=th_blk>拦截</th><th id=th_alw>放行</th><th></th></tr></thead><tbody></tbody></table></div>
<h2 id=h_updns>上游 DNS</h2>
<div style=margin-bottom:6px><input id=upip placeholder="9.9.9.9" size=15 value=""><button id=btn_setupstream onclick=saveUp()></button> <span id=upmsg style=color:#8b949e></span></div>
<div id=updns_hint style="color:#8b949e;font-size:12px;margin-bottom:18px"></div>
<h2 id=h_mdns>mDNS 主机名</h2>
<div style=margin-bottom:6px><input id=mdnsinp placeholder="c3adblock" size=20 value=""><button id=btn_setmdns onclick=saveMdns()></button> <span id=mdnsmsg style=color:#8b949e></span></div>
<div id=mdns_hint style="color:#8b949e;font-size:12px;margin-bottom:18px"></div>
<h2 id=h_cdns>自定义解析</h2>
<div style=margin-bottom:6px><input id=cdnd placeholder="a.com" size=12> → <input id=cdnip placeholder="10.0.0.123" size=15><button id=btn_adddns onclick=addCDns()></button></div>
<div style="max-height:200px;overflow-y:auto;border:1px solid #30363d;border-radius:6px"><table id=cdn><thead><tr><th id=th_domain>域名</th><th>IP</th><th></th></tr></thead><tbody></tbody></table></div>
<h2 id=h_blockdom>自定义拦截域名</h2>
<div style=margin-bottom:8px><input id=dom placeholder="ads.example.com" size=24><button id=btn_addblock onclick=addDom()></button></div>
<div style=margin-bottom:6px><form id=impcf style=display:inline><input type=file id=impf accept=".txt" ><button id=btn_import></button></form> <button id=btn_clear onclick="if(confirm(L.clearConfirm[lang==='cn'?0:1]))clearCustom()"></button> <span id=impmsg style=color:#8b949e></span></div>
<div style="max-height:200px;overflow-y:auto;border:1px solid #30363d;border-radius:6px"><table id=cl><tbody></tbody></table></div>
<h2 id=h_dnslog>DNS 查询日志</h2>
<div style="max-height:300px;overflow-y:auto;border:1px solid #30363d;border-radius:6px"><table id=dlg><thead><tr><th id=th_logdom>域名</th><th id=th_logip>来源IP</th><th id=th_logres>结果</th><th id=th_logcnt>次数</th><th id=th_logtime>时间</th><th></th></tr></thead><tbody></tbody></table></div>
<h2 id=h_upload>拦截列表上传</h2>
<form id=upf style=margin-bottom:6px><input type=file id=blf accept=.bin><button id=btn_upload></button> <span id=upmsg2 style=color:#8b949e></span></form>
<h2 id=h_fw>固件 OTA 更新</h2>
<form id=fwf style=margin-bottom:6px><input type=file id=fwb accept=.bin><button id=btn_flash></button> <span id=fwmsg style=color:#8b949e></span></form>
<h2>WiFi</h2>
<div style=margin-bottom:18px><button id=btn_forget onclick="if(confirm(L.forget[lang]))forgetWifi()"></button></div>
</div>
<script>
let lang=localStorage.getItem('lang')||'cn';
const L={
 hostname:['@ ','@ '],
 defcreds:['⚠️ 默认密码未修改。secrets.h 中的 WEB_PASS/OTA_PASS 仍为占位符，任何人均可在公开仓库中查看到。请设置真实密码后重新烧录。','⚠️ Default credentials in use. Set real passwords in secrets.h and reflash.'],
 blocking:['拦截中','Blocking active'],
 paused:['已暂停','Paused'],
 pausedResume:['已暂停 — ', 'Paused — resumes in '],
 resume:['s后恢复','s'],
 pause:['暂停','Pause'],
 resumeBtn:['恢复','Resume'],
 totalBlocked:['总拦截','Total blocked'],
 totalAllowed:['总放行','Total allowed'],
 blocklist:['拦截列表','Blocklist'],
 domains:['个域名',' domains'],
 clients:['客户端数','Clients'],
 wifi:['信号','WiFi'],
 temp:['温度','Temp'],
 freeRam:['可用内存','Free RAM'],
 uptime:['运行时间','Uptime'],
 clients_h:['客户端','CLIENTS'],
 ip:['IP','IP'],
 blk:['拦截','Blocked'],
 alw:['放行','Allowed'],
 ban:['封禁','Ban'],
 unban:['解封','Unban'],
 updns:['上游 DNS','UPSTREAM DNS'],
 mdns:['mDNS 主机名','MDNS HOSTNAME'],
 setmdns:['保存','Save'],
 mdnsHint:['设备在局域网中的名称，修改后自动重启。访问 http://<名称>.local 打开仪表盘。仅允许字母、数字和连字符，最长 63 字符。','Device hostname on the LAN. Changing this reboots the device. Access the dashboard at http://<name>.local. Letters, digits, hyphens only; max 63 chars.'],
 setupstream:['设置','Set'],
 updnsHint:['配置上游 DNS 服务器（默认 Quad9 9.9.9.9）。阿里DNS: 223.5.5.5，Cloudflare: 1.1.1.1','Configure upstream DNS resolver (default: 9.9.9.9). AliDNS: 223.5.5.5, Cloudflare: 1.1.1.1'],
 cdns:['自定义解析','CUSTOM DNS RESOLUTION'],
 addOverride:['添加','Add override'],
 domain:['域名','Domain'],
 blockdom:['自定义拦截域名','CUSTOM BLOCKED DOMAINS'],
 addBlock:['添加拦截','Block domain'],
 importBtn:['导入txt','Import .txt'],
 clearCustom:['清空','Clear all'],
 clearConfirm:['确定清空所有自定义拦截域名？','Clear all custom blocked domains?'],
 importHint:['每行一个域名，#开头为注释，支持hosts格式','One domain per line, # for comments, hosts format supported'],
 dnslog:['DNS 查询日志','DNS QUERY LOG'],
 logdom:['域名','Domain'],
 logip:['来源IP','Client'],
 logres:['结果','Result'],
 logtime:['时间(s前)','Time(s ago)'],
 logcnt:['次数','Count'],
 blockBtn:['拦截','Block'],
 upload:['拦截列表上传','BLOCKLIST UPLOAD'],
 uploadBtn:['上传','Upload'],
 fw:['固件 OTA 更新','FIRMWARE OTA UPDATE'],
 flashBtn:['烧录','Flash firmware'],
 forget:['确定清除 WiFi 配置并重启进入配置模式？','Forget saved WiFi and reboot into setup portal?'],
 forgetBtn:['清除 WiFi','Forget WiFi'],
 none:['无','none'],
 blocked:['拦截','Blocked'],
 allowed:['放行','Allowed'],
 override:['自定义','Override'],
 remove:['删除','Remove'],
 sec:['秒','s'],
};
const CSRF_HDRS={'X-Requested-With':'c3-adblock'};
function t(k){return L[k]?L[k][lang==='cn'?0:1]:k}
function fmt(n){return n.toLocaleString()}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function toggleLang(){lang=lang==='cn'?'en':'cn';localStorage.setItem('lang',lang);applyLang();load()}
function applyLang(){
 document.title=lang==='cn'?'C3 广告拦截':'C3 AdBlock';
 langbtn.textContent=lang==='cn'?'EN':'中文';
 let ids={h_clients:'clients_h',h_updns:'updns',h_mdns:'mdns',h_cdns:'cdns',h_blockdom:'blockdom',h_dnslog:'dnslog',h_upload:'upload',h_fw:'fw'};
 for(let[id,k]of Object.entries(ids)){let el=document.getElementById(id);if(el)el.textContent=t(k)}
 let ths={th_ip:'ip',th_blk:'blk',th_alw:'alw',th_domain:'domain',th_logdom:'logdom',th_logip:'logip',th_logres:'logres',th_logtime:'logtime',th_logcnt:'logcnt'};
 for(let[id,k]of Object.entries(ths)){let el=document.getElementById(id);if(el)el.textContent=t(k)}
 btn_setupstream.textContent=t('setupstream');
 btn_setmdns.textContent=t('setmdns');
 mdns_hint.textContent=t('mdnsHint');
 btn_adddns.textContent=t('addOverride');
 btn_addblock.textContent=t('addBlock');
 btn_import.textContent=t('importBtn');
 btn_clear.textContent=t('clearCustom');
 btn_import.textContent=t('importBtn');
 btn_upload.textContent=t('uploadBtn');
 btn_flash.textContent=t('flashBtn');
 btn_forget.textContent=t('forgetBtn');
 updns_hint.textContent=t('updnsHint');
 let opts=['<option value=30>30'+t('sec')+'</option>','<option value=300 selected>5'+t('sec')+'</option>','<option value=1800>30'+t('sec')+'</option>','<option value=0>'+t('paused')+'</option>'];
 pausedur.innerHTML=opts.join('');
}
function togglePause(){fetch(blockstate.dataset.on=='1'?'/pause?s='+pausedur.value:'/resume',{headers:CSRF_HDRS}).then(load)}
async function load(){
 let s=await(await fetch('/stats.json')).json();
 host.textContent=t('hostname')+s.ip;
   let on=s.blocking!==false;blockstate.dataset.on=on?'1':'0';
 blockdot.textContent=on?'🛡️':'⏸️';blockbar.style.borderColor=on?'#30363d':'#f0883e';
 blockstate.textContent=on?t('blocking'):(s.resumeIn>0?t('pausedResume')+s.resumeIn+t('resume'):t('paused'));
 pausebtn.textContent=on?t('pause'):t('resumeBtn');pausedur.style.display=on?'':'none';
 sys.innerHTML=[['totalBlocked',fmt(s.blocked),'b'],['totalAllowed',fmt(s.allowed),'a'],['blocklist',fmt(s.domains)+t('domains'),''],['clients',s.clients.length,''],['wifi',s.rssi+' dBm',''],['temp',s.temp+' °C',''],['freeRam',Math.round(s.heap/1024)+' KB',''],['uptime',s.uptime,'']]
.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${t(c[0])}</div></div>`).join('');
 ct.tBodies[0].innerHTML=s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
`<tr><td>${c.ip}${c.banned?' <span class=tag style=color:#f85149>BAN</span>':''}</td><td>${c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td>
<td><button class=ban data-ip="${c.ip}">${c.banned?t('unban'):t('ban')}</button></td></tr>`).join('');
 cl.tBodies[0].innerHTML=s.custom.map(d=>`<tr><td>${esc(d)}</td><td style=text-align:right><button class=rmbtn data-d="${esc(d)}">${t('remove')}</button></td></tr>`).join('')||`<tr><td style=color:#8b949e>${t('none')}</td></tr>`;
 if(document.activeElement!=upip&&s.upstream)upip.value=s.upstream;
 if(document.activeElement!=mdnsinp&&s.mdns)mdnsinp.value=s.mdns;
 cdn.tBodies[0].innerHTML=(s.customDns||[]).map(o=>`<tr><td>${esc(o.domain)}</td><td>${esc(o.ip)}</td><td><button onclick="delCDns('${esc(o.domain)}')">${t('remove')}</button></td></tr>`).join('')||`<tr><td colspan=3 style=color:#8b949e>${t('none')}</td></tr>`;
}
async function loadLog(){
 let arr=await(await fetch('/log.json')).json();
 let now=Math.floor(Date.now()/1000);
 // Merge by domain: count queries, keep latest client/result/time
 let map={};
 arr.forEach(e=>{
  if(!map[e.domain]) map[e.domain]={domain:e.domain,client:e.client,result:e.result,ts:e.ts,count:1};
  else{map[e.domain].count++;if(e.ts>map[e.domain].ts){map[e.domain].ts=e.ts;map[e.domain].client=e.client;map[e.domain].result=e.result;}}
 });
 let merged=Object.values(map).sort((a,b)=>b.ts-a.ts).slice(0,60);
 dlg.tBodies[0].innerHTML=merged.map(e=>
`<tr><td>${esc(e.domain)}</td><td>${esc(e.client)}</td><td class=${e.result=='blocked'?'b':'a'}>${t(e.result)}</td><td>${e.count}</td><td style=color:#8b949e>${Math.max(0,now-e.ts)}${t('sec')}</td><td><button class=blkbtn data-d="${esc(e.domain)}">${t('blockBtn')}</button></td></tr>`).join('')||`<tr><td colspan=6 style=color:#8b949e>${t('none')}</td></tr>`;
}
function saveMdns(){let n=mdnsinp.value.trim();if(!n)return;mdnsmsg.textContent='...';fetch('/setmdns?name='+encodeURIComponent(n),{headers:CSRF_HDRS}).then(r=>r.text()).then(s=>{mdnsmsg.textContent=s;setTimeout(load,2000)})}
function saveUp(){let ip=upip.value.trim();if(!ip)return;fetch('/setupstream?ip='+ip,{headers:CSRF_HDRS}).then(r=>r.text()).then(s=>{upmsg.textContent=s;load()})}
function addCDns(){let d=cdnd.value.trim();let ip=cdnip.value.trim();if(!d||!ip)return;fetch('/addcustomdns?d='+encodeURIComponent(d)+'&ip='+ip,{headers:CSRF_HDRS}).then(r=>r.text()).then(s=>{cdnd.value='';cdnip.value='';load()})}
function delCDns(d){fetch('/delcustomdns?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(load)}
function clearCustom(){fetch('/clearcustom',{headers:CSRF_HDRS}).then(r=>r.text()).then(()=>load())}
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{dom.value='';load()})}}
impcf.onsubmit=async e=>{e.preventDefault();let f=impf.files[0];if(!f)return;impmsg.textContent='...';let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/importcustom',{method:'POST',headers:CSRF_HDRS,body:fd});let t=await r.text();impmsg.textContent=t;setTimeout(load,500);}
catch(_){impmsg.textContent='error'}impf.value=''};
function forgetWifi(){fetch('/forgetwifi',{headers:CSRF_HDRS}).then(r=>r.text()).then(s=>alert(s))}
ct.addEventListener('click',e=>{if(e.target.classList.contains('ban'))fetch('/ban?ip='+e.target.dataset.ip,{headers:CSRF_HDRS}).then(load)});
cl.addEventListener('click',e=>{if(e.target.classList.contains('rmbtn'))fetch('/unblock?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
dlg.addEventListener('click',e=>{if(e.target.classList.contains('blkbtn'))fetch('/addblock?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(()=>{e.target.textContent='✓';setTimeout(load,500)})});
fwf.onsubmit=async e=>{e.preventDefault();let f=fwb.files[0];if(!f)return;fwmsg.textContent='...';let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/update',{method:'POST',headers:CSRF_HDRS,body:fd});fwmsg.textContent=r.ok?'✓':'✗ '+await r.text();}catch(_){fwmsg.textContent='✓'}};
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;upmsg2.textContent='...';let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/upload',{method:'POST',headers:CSRF_HDRS,body:fd});upmsg2.textContent=r.ok?'✓':'✗';}catch(_){upmsg2.textContent='✗'}blf.value='';setTimeout(load,600)};
applyLang();load();setInterval(load,3000);setInterval(loadLog,2000);
</script></body></html>)HTML";
