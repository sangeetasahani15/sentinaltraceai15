'use strict';
const $=s=>document.querySelector(s);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const PAGES=[['overview','Overview'],['analyzer','Email Analyzer'],['headers','Header Forensics'],['trace','Email Trace'],['geo','Geolocation'],['domains','Domain Intelligence'],['threat','Threat Intelligence'],['graph','Relationship Graph'],['campaigns','Campaigns'],['history','Detection History'],['cases','Cases'],['evidence','Evidence'],['reports','Reports'],['privacy','Privacy & Settings']];
const NEEDS=['headers','trace','geo','domains','threat','graph','reports'];
const SAMPLE=`Received: from mail-out.paypa1-support.com (unknown [185.220.101.45]) by mx.company.com with ESMTP; Wed, 7 Oct 2026 13:41:02 +0000
Received: from relay2.bulkmailer.example (relay2.bulkmailer.example [91.214.124.77]) by mail-out.paypa1-support.com with ESMTP; Wed, 7 Oct 2026 13:40:55 +0000
Received: from [10.0.0.5] (host-5.dyn.example [203.0.113.9]) by relay2.bulkmailer.example with SMTP; Wed, 7 Oct 2026 13:40:50 +0000
From: "PayPal Billing Department" <accounts@paypa1-support.com>
Reply-To: billing-help@xyzmail.com
To: finance@company.com
Subject: Urgent: Account suspended - verify payment immediately
Date: Wed, 7 Oct 2026 13:40:48 +0000
Message-ID: <demo-78291@mail.example>
Return-Path: <bounce@bulkmailer.example>
Authentication-Results: mx.company.com; spf=fail smtp.mailfrom=bulkmailer.example; dkim=none; dmarc=fail header.from=paypa1-support.com
Content-Type: text/plain

Dear customer,

Your PayPal billing account has been suspended. Action required within 24 hours:
an outstanding invoice must be paid by bank transfer. Verify your payment details here:
http://paypa1-support.com/verify?id=78291

PayPal Billing Department`;
let cur='overview',A=null,draft='',filter='',busy=false,H={items:null,err:null};
let S={cases:[{id:'CASE-1001',title:'Invoice fraud - vendor spoof',risk:88,status:'Open'},{id:'CASE-1002',title:'Credential harvest - M365 lookalike',risk:94,status:'Investigating'}],evidence:[],redact:false};
try{const x=JSON.parse(localStorage.getItem('stz')||'null');if(x)S=Object.assign(S,x)}catch(e){}
const save=()=>{try{localStorage.setItem('stz',JSON.stringify(S))}catch(e){}};

/* ---------- server API ---------- */
const KEYN='stkey';
function clientKey(){let k='';try{k=localStorage.getItem(KEYN)||''}catch(e){}if(!/^[A-Za-z0-9_-]{32,128}$/.test(k)){const b=new Uint8Array(32);crypto.getRandomValues(b);k=[...b].map(x=>x.toString(16).padStart(2,'0')).join('');try{localStorage.setItem(KEYN,k)}catch(e){}}return k}
async function api(path,opt={}){const r=await fetch(path,{...opt,headers:{'Content-Type':'application/json','X-Client-Key':clientKey()}});let j={};try{j=await r.json()}catch(e){}if(!r.ok)throw new Error(j.error||('Request failed ('+r.status+')'));return j}
async function loadHistory(){H.err=null;try{H.items=(await api('/api/history?limit=100')).items}catch(e){H.err=e.message;H.items=[]}if(cur==='history')render()}
fetch('/api/health').then(r=>r.json().then(j=>{const e=$('#hc');if(e){e.textContent=j.database==='connected'?'● API & database connected':'● Service degraded: database '+(j.database||'unavailable');e.style.color=j.database==='connected'?'':'#b45f06'}})).catch(()=>{const e=$('#hc');if(e)e.textContent='● API unreachable'});
function toast(m){const t=$('#toast');if(!t)return;t.textContent=m;t.className='show';clearTimeout(toast.t);toast.t=setTimeout(()=>{t.className=''},1800)}

const {IP,priv,BRANDS,FREE,normD,official,lookalike,dom,parseAddr,parseEmail}=window.SentinelEngine;
const iocs=()=>[...A.ips.map(i=>['IP',i,priv(i)?'Internal':'Unrated']),...A.domains.map(d=>['Domain',d.d,d.flag?'Suspicious - '+d.flag:'Unrated']),...A.urls.map(u=>['URL',u.u,lookalike(u.d)?'Suspicious - lookalike':'Unrated'])];
const GEO={'185.220':['Germany','Demo hosting range'],'91.214':['Netherlands','Demo bulk-mail range'],'203.0':['Documentation range','TEST-NET-3 (not routable)']};
const geo=ip=>priv(ip)?['Private network','Internal / RFC1918']:(GEO[ip.split('.').slice(0,2).join('.')]||GEO[ip.split('.').slice(0,2).join('.')]||['Unknown','No GeoIP database bundled']);
async function sha(t){try{const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(t));return[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')}catch(e){let h=2166136261;for(const c of t){h=Math.imul(h^c.charCodeAt(0),16777619)}return'fnv-'+(h>>>0).toString(16)}}
const report=()=>({tool:'SentinelTrace AI',generated:new Date().toISOString(),messageId:A.id,risk:A.risk,riskLabel:A.label,threatType:A.threatType,sender:A.from.addr,replyTo:A.rt.addr,recipient:S.redact?'[redacted]':A.to.addr,subject:A.subject,auth:A.auth,indicators:A.sig.map(s=>s.t),iocs:iocs().map(x=>x[0]+' '+x[1])});

/* ---------- views ---------- */
const tone=r=>r>=75?'r':r>=40?'a':'g';
const tg=(t,c)=>`<span class="tag ${c}">${esc(t)}</span>`;
const tbl=(head,rows)=>`<table><tr>${head.map(x=>`<th>${x}</th>`).join('')}</tr>${rows.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('')||`<tr><td colspan="${head.length}">No data</td></tr>`}</table>`;
const idrow=(l,v)=>`<div class="idr"><span>${l}</span><em>${esc(v||'-')}</em><button class="cp" data-copy="${esc(v||'')}">Copy</button></div>`;
const result=()=>`<div class="card"><div class="hd"><h3>Threat Summary - ${esc(A.id)}</h3><span class="pill">UNDER INVESTIGATION</span></div>
<div class="kpis4"><div class="k ${tone(A.risk)}"><small>FRAUD RISK</small><b>${A.risk}% - ${A.label}</b></div><div class="k a"><small>ORIGIN CONFIDENCE</small><b>${A.oc}% - ${A.ocl}</b></div><div class="k"><small>THREAT TYPE</small><b style="font-size:18px">${esc(A.threatType)}</b></div><div class="k"><small>AI CLASSIFICATION</small><b style="font-size:16px">${esc(A.cls)}</b></div></div>
<p class="note">Analysis completed just now · Origin confidence reflects reliability of available technical evidence, not the identity of a person.</p>
<div class="row" style="justify-content:flex-start;margin-top:14px"><button class="btn" data-act="newcase">Create Case</button><button class="btn" data-act="addevidence">Save Evidence</button><button class="btn" data-act="dljson">Download Report</button></div></div>
<div class="two"><div class="card"><h3 style="margin-bottom:8px">Email Identity</h3>${idrow('Sender',A.from.addr)}${idrow('Display Name',A.from.name)}${idrow('Reply-To',A.rt.addr)}${idrow('Recipient',S.redact?'[redacted]':A.to.addr)}${idrow('Return-Path',A.ret.addr)}${idrow('Subject',A.subject)}${idrow('Date',A.date)}</div>
<div class="card"><h3 style="margin-bottom:8px">AI Fraud Detection - ${A.risk}% confidence</h3>${A.probs.map(p=>`<div class="bar"><span>${p[0]}</span><div><i style="width:${p[1]}%;background:${p[2]}"></i></div><b>${p[1]}%</b></div>`).join('')}
<h3 style="margin:16px 0 6px">Indicators</h3><ul class="ind">${A.sig.map(s=>`<li>${esc(s.t)}</li>`).join('')||'<li>No suspicious indicators found</li>'}</ul></div></div>`;
const empty=()=>`<div class="card empty">No email analysed yet.<br><button class="btn pri" data-act="demo">Load Demo Threat</button> <button class="btn" data-go="analyzer">Open Email Analyzer</button></div>`;
function graph(){const N=[['Sender',A.from.addr,'#c0392b'],['Reply-To',A.rt.addr,'#b45f06'],['Recipient',A.to.addr,'#0f7b55'],...A.hops.map(x=>['Relay',x.from,'#64748b']),...A.urls.slice(0,3).map(u=>['URL',u.d,'#6d28d9'])].filter(n=>n[1]&&n[1]!=='-');
 const cx=320,cy=190,k=N.length,pts=N.map((n,i)=>{const a=2*Math.PI*i/k-Math.PI/2;return[cx+220*Math.cos(a),cy+140*Math.sin(a)]});let s='<svg viewBox="0 0 640 380" class="gr">';
 pts.forEach(p=>{s+=`<line x1="${cx}" y1="${cy}" x2="${p[0].toFixed(1)}" y2="${p[1].toFixed(1)}" stroke="#cbd5e1"/>`});
 s+=`<circle cx="${cx}" cy="${cy}" r="34" fill="#2557d6"/><text x="${cx}" y="${cy+4}" text-anchor="middle" fill="#fff" font-size="12">Email</text>`;
 N.forEach((n,i)=>{const x=pts[i][0].toFixed(1),y=pts[i][1].toFixed(1);s+=`<circle cx="${x}" cy="${y}" r="9" fill="${n[2]}"/><text x="${x}" y="${(pts[i][1]+24).toFixed(1)}" text-anchor="middle" font-size="11" fill="#334155">${esc(n[1].slice(0,28))}</text><text x="${x}" y="${(pts[i][1]-14).toFixed(1)}" text-anchor="middle" font-size="10" fill="#94a3b8">${n[0]}</text>`});return s+'</svg>'}
const D=[['Legitimate',46,'#0f7b55'],['Suspicious',17,'#b45f06'],['Phishing',21,'#c0392b'],['Impersonation',9,'#6d28d9'],['Fraud / BEC',7,'#94a3b8']];
const CAMP=[['CMP-2291','PayPal lookalike billing','paypa1-support.com',184,'Active'],['CMP-2288','Microsoft 365 credential harvest','m1crosoft-login.net',132,'Active'],['CMP-2275','Vendor invoice BEC','various free-mail',61,'Monitoring'],['CMP-2260','Parcel delivery lure','dhl-track-parcel.top',47,'Closed']];
const pages={
overview:()=>{let a=0;const cg=D.map(d=>{const s=a;a+=d[1];return`${d[2]} ${s}% ${a}%`}).join(',');
 return`<div class="hd"><div><h1>Security Overview</h1><p class="sub" style="margin:4px 0 0">Real-time snapshot of email threat activity across your organization</p></div><button class="btn pri" data-act="demo">Load Demo Threat</button></div>
<div class="kp6">${[['Emails Analyzed','12,842','+12.4% this week'],['Threats Detected','1,426','+8.1% this week'],['High Risk','218','+3.6% this week'],['Active Campaigns','37','+2 new'],['Cases Under Investigation',String(S.cases.length+12),'+1 today'],['Threat Detection Rate','94.7%','+0.4pt']].map(k=>`<div class="k"><small>${k[0]}</small><b>${k[1]}</b><em>${k[2]}</em></div>`).join('')}</div>
<div class="card"><h3 style="margin-bottom:14px">Threat Distribution</h3><div class="dn"><div class="donut" style="background:conic-gradient(${cg})"></div><ul class="leg">${D.map(d=>`<li><i style="background:${d[2]}"></i>${d[0]} - ${d[1]}%</li>`).join('')}</ul></div></div>
<div class="card"><h3 style="margin-bottom:8px">Recent Detections (demo data)</h3>${tbl(['Sender','Type','Risk'],[['accounts@paypa1-support.com','Phishing',tg('92% HIGH','r')],['ceo.office@company-mail.top','BEC',tg('81% HIGH','r')],['news@shopdeals.example','Suspicious',tg('46% MEDIUM','a')],['hr@company.com','Legitimate',tg('3% LOW','g')]])}</div>`},
analyzer:()=>`<h1>Email Forensic Analyzer</h1><p class="sub">Upload or paste a raw email to run a full forensic investigation</p>
<div class="card"><div class="drop" id="drop"><b>Drop .eml file here</b><span>or paste raw email source below</span><i>- or -</i><textarea id="raw" placeholder="Paste raw email headers and body here…">${esc(draft)}</textarea><div class="row"><button class="btn" data-act="upload">Upload Email</button><button class="btn pri" data-act="analyze">Analyze Email</button><button class="btn" data-act="demo">Load Demo Threat</button></div><input type="file" id="file" accept=".eml,.txt,message/rfc822" hidden></div></div>${A?result():''}`,
headers:()=>`<h1>Header Forensics</h1><p class="sub">Authentication results and every header field</p><div class="card"><h3 style="margin-bottom:8px">Authentication</h3>${tbl(['Check','Result'],Object.entries(A.auth).map(([k,v])=>[k.toUpperCase(),tg(v,v==='pass'?'g':v==='none'?'a':'r')]))}</div><div class="card"><h3 style="margin-bottom:8px">All Headers</h3>${tbl(['Header','Value'],Object.entries(A.h).flatMap(([k,v])=>v.map(x=>[esc(k),esc(x)])))}</div>`,
trace:()=>`<h1>Email Trace</h1><p class="sub">Delivery path, oldest hop first</p><div class="card">${A.hops.map(x=>`<div class="hop"><b>Hop ${x.n}: ${esc(x.from)} → ${esc(x.by)}</b><small>${esc(x.time||'no timestamp')} · IP: ${esc(x.ips.join(', ')||'none')}</small></div>`).join('')||'No Received headers found.'}</div>`,
geo:()=>`<h1>Geolocation</h1><p class="sub">Network origin of each relay IP (built-in demo table)</p><div class="card">${tbl(['IP','Country / Range','Network','Type'],A.ips.map(i=>{const g=geo(i);return[esc(i),esc(g[0]),esc(g[1]),priv(i)?tg('Private','a'):tg('Public','r')]}))}<p class="note">Add a GeoIP database for real lookups. Location indicates network infrastructure, not a person.</p></div>`,
domains:()=>`<h1>Domain Intelligence</h1><p class="sub">Every domain seen in the email with local risk checks</p><div class="card">${tbl(['Domain','Seen as','Findings'],A.domains.map(d=>[esc(d.d),esc(d.roles.join(', ')),d.flag?tg(d.flag,'r'):tg('No local flags','g')]))}</div>`,
threat:()=>{const f=filter.toLowerCase(),r=iocs().filter(x=>!f||x[1].toLowerCase().includes(f));return`<h1>Threat Intelligence</h1><p class="sub">Indicators of compromise extracted from this email${filter?' · filter: '+esc(filter):''}</p><div class="card"><div class="hd"><h3>IOCs (${r.length})</h3><button class="btn" data-copy="${esc(iocs().map(x=>x[1]).join('\n'))}">Copy all</button></div>${tbl(['Type','Indicator','Verdict'],r.map(x=>[x[0],esc(x[1]),x[2].startsWith('Susp')?tg(x[2],'r'):esc(x[2])]))}<p class="note">Verdicts come from local heuristics; no external feeds are queried.</p></div>`},
graph:()=>`<h1>Relationship Graph</h1><p class="sub">How the sender, relays, recipient and links connect</p><div class="card">${graph()}</div>`,
campaigns:()=>`<h1>Campaigns</h1><p class="sub">Tracked threat campaigns (demo data)</p><div class="card">${tbl(['ID','Campaign','Indicator','Emails','Status',''],CAMP.map(c=>[c[0],c[1],c[2],c[3],c[4],A&&A.domains.some(d=>d.d===c[2])?tg('Matches current email','r'):'']))}</div>`,
history:()=>{const rows=(H.items||[]).map(r=>[esc(new Date(r.created_at).toLocaleString()),esc(r.sender||'-'),esc(r.subject||'-'),tg(r.risk_score+'% '+r.risk_label,tone(r.risk_score)),esc(r.threat_type),`<button class="btn" data-del="${esc(r.id)}">Delete</button>`]);
 return`<div class="hd"><div><h1>Detection History</h1><p class="sub" style="margin:4px 0 0">Results saved in the database for this browser. Email bodies are never stored.</p></div><button class="btn" data-act="reload">Refresh</button></div><div class="card">${H.items===null?'Loading…':H.err?'<span class="tag r">'+esc(H.err)+'</span>':tbl(['When','Sender','Subject','Risk','Threat type',''],rows)}</div>`},
cases:()=>`<div class="hd"><div><h1>Cases</h1><p class="sub" style="margin:4px 0 0">Investigations in progress</p></div><button class="btn pri" data-act="newcase">New case from current analysis</button></div><div class="card">${tbl(['Case','Title','Risk','Status'],S.cases.map(c=>[c.id,esc(c.title),tg(c.risk+'%',tone(c.risk)),c.status]))}</div>`,
evidence:()=>`<div class="hd"><div><h1>Evidence</h1><p class="sub" style="margin:4px 0 0">Hashed copies of analysed emails</p></div><button class="btn pri" data-act="addevidence">Save current email</button></div><div class="card">${tbl(['Item','SHA-256','Size','Saved'],S.evidence.map(e=>[esc(e.name),`<code>${esc(e.hash.slice(0,32))}…</code>`,e.size+' bytes',esc(e.time)]))}</div>`,
reports:()=>`<h1>Reports</h1><p class="sub">Export the current investigation</p><div class="card"><div class="hd"><h3>${esc(A.id)}</h3>${tg(A.risk+'% '+A.label,tone(A.risk))}</div><p><b>Threat type:</b> ${esc(A.threatType)}<br><b>Sender:</b> ${esc(A.from.addr)}<br><b>Indicators:</b> ${A.sig.length}<br><b>IOCs:</b> ${iocs().length}</p><div class="row" style="justify-content:flex-start"><button class="btn pri" data-act="dljson">Download JSON</button><button class="btn" data-act="print">Print / Save PDF</button></div></div>`,
privacy:()=>`<h1>Privacy &amp; Settings</h1><p class="sub">How your data is handled</p><div class="card"><label><input type="checkbox" data-act="redact" ${S.redact?'checked':''}> Redact recipient address in reports and views</label><p class="note">The raw email is sent over HTTPS to the analysis API, scored in memory and discarded. Only sender, subject, scores, indicators and a SHA-256 of the email are saved to the database, keyed to an anonymous per-browser key. Cases and evidence remain in this browser only.</p><button class="btn" data-act="clear">Clear all saved data</button></div>`};

/* ---------- app shell ---------- */
function render(){if(cur==='history'&&H.items===null)loadHistory();$('#nav').innerHTML=PAGES.map(p=>`<button data-go="${p[0]}" class="${p[0]===cur?'on':''}">${p[1]}</button>`).join('');
 const v=$('#view');try{v.innerHTML=(NEEDS.includes(cur)&&!A)?'<h1>'+PAGES.find(p=>p[0]===cur)[1]+'</h1><p class="sub">Analyse an email to populate this view</p>'+empty():pages[cur]()}catch(e){v.innerHTML='<div class="card empty">Could not render this view: '+esc(e.message)+'</div>'}window.scrollTo(0,0)}
const go=p=>{cur=p;render()};
async function run(raw){if(!raw||!raw.trim()){toast('Paste or upload an email first');return}if(busy)return;draft=raw;busy=true;document.body.classList.add('busy');toast('Analysing…');
 try{const r=await api('/api/analyze',{method:'POST',body:JSON.stringify({raw})});r.raw=raw;r.size=raw.length;A=r;H.items=null;go('analyzer');toast('Analysis complete and saved')}
 catch(e){toast('Error: '+e.message)}finally{busy=false;document.body.classList.remove('busy')}}
const readFile=f=>{if(!f)return;const r=new FileReader();r.onload=()=>run(String(r.result));r.readAsText(f)};
document.addEventListener('click',async e=>{const t=e.target.closest('[data-go],[data-copy],[data-act],[data-del]');if(!t)return;
 if(t.dataset.del){try{await api('/api/history?id='+encodeURIComponent(t.dataset.del),{method:'DELETE'});toast('Record deleted')}catch(x){toast('Error: '+x.message)}H.items=null;render();return}
 if(t.dataset.go){go(t.dataset.go);return}
 if(t.dataset.copy!==undefined){try{await navigator.clipboard.writeText(t.dataset.copy);toast('Copied')}catch(x){toast('Copy not available')}return}
 const a=t.dataset.act;
 if(a==='demo'){run(SAMPLE)}
 else if(a==='analyze'){run(($('#raw')||{}).value||draft)}
 else if(a==='upload'){const f=$('#file');if(f)f.click()}
 else if(a==='newcase'){if(!A){toast('Analyse an email first');return}S.cases.push({id:'CASE-'+(1001+S.cases.length),title:A.subject||A.id,risk:A.risk,status:'Open'});save();go('cases');toast('Case created')}
 else if(a==='addevidence'){if(!A){toast('Analyse an email first');return}const hash=await sha(A.raw);S.evidence.push({name:A.id+'.eml',hash,size:A.size,time:new Date().toLocaleString()});save();go('evidence');toast('Evidence saved')}
 else if(a==='dljson'){const b=new Blob([JSON.stringify(report(),null,2)],{type:'application/json'}),l=document.createElement('a');l.href=URL.createObjectURL(b);l.download='sentineltrace-report.json';document.body.appendChild(l);l.click();l.remove();toast('Report downloaded')}
 else if(a==='print'){window.print()}
 else if(a==='reload'){H.items=null;render()}
 else if(a==='redact'){S.redact=t.checked;save()}
 else if(a==='clear'){S.cases=S.cases.slice(0,2);S.evidence=[];save();toast('Saved data cleared');render()}});
document.addEventListener('input',e=>{if(e.target.id==='raw')draft=e.target.value});
document.addEventListener('change',e=>{if(e.target.id==='file')readFile(e.target.files[0])});
document.addEventListener('dragover',e=>{const d=e.target.closest&&e.target.closest('#drop');if(d){e.preventDefault();d.classList.add('over')}});
document.addEventListener('dragleave',e=>{const d=$('#drop');if(d)d.classList.remove('over')});
document.addEventListener('drop',e=>{if(e.target.closest&&e.target.closest('#drop')){e.preventDefault();readFile(e.dataTransfer.files[0])}});
$('#q').addEventListener('keydown',e=>{if(e.key!=='Enter')return;const v=e.target.value.trim();if(!v)return;
 if(/^case/i.test(v)){go('cases')}else if(/^cmp/i.test(v)){go('campaigns')}else if(!A){toast('Analyse an email first to search its indicators')}else{filter=v;go('threat')}});
render();
