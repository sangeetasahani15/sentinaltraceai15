'use strict';
/* SentinelTrace engine: rule-based email analysis, extracted verbatim from the original app.js.
   Runs in Node (API) and in the browser (helpers for views). */
(function(root){
/* ---------- parsing & analysis ---------- */
const IP=/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const priv=i=>/^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(i);
const BRANDS=['paypal','microsoft','amazon','google','apple','netflix','dhl'];
const FREE=['gmail.com','yahoo.com','outlook.com','hotmail.com','proton.me','aol.com'];
const normD=d=>d.replace(/1/g,'l').replace(/0/g,'o').replace(/rn/g,'m').replace(/vv/g,'w');
const official=(d,b)=>d===b+'.com'||d.endsWith('.'+b+'.com');
const lookalike=d=>{const n=normD(d||'');for(const b of BRANDS){if(n.includes(b)&&!official(d,b))return b}return null};
const dom=a=>(a.split('@')[1]||'').toLowerCase();
function parseAddr(s){s=s||'';const m=s.match(/^\s*"?([^"<]*?)"?\s*<([^>]+)>/);if(m)return{name:m[1].trim(),addr:m[2].trim().toLowerCase()};const a=(s.match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/i)||[''])[0].toLowerCase();return{name:'',addr:a}}
function parseEmail(raw){raw=raw.replace(/\r\n/g,'\n');const i=raw.search(/\n[ \t]*\n/);const head=i<0?raw:raw.slice(0,i),body=i<0?'':raw.slice(i).trim();const h={};
 head.replace(/\n[ \t]+/g,' ').split('\n').forEach(l=>{const m=l.match(/^([A-Za-z0-9-]+):\s*(.*)$/);if(m){const k=m[1].toLowerCase();(h[k]=h[k]||[]).push(m[2])}});return{h,body}}
function analyze(raw){
 const {h,body}=parseEmail(raw);const g=k=>(h[k]||[''])[0];
 const from=parseAddr(g('from')),rt=parseAddr(g('reply-to')),ret=parseAddr(g('return-path')),to=parseAddr(g('to'));
 const fd=dom(from.addr),rd=dom(rt.addr),retd=dom(ret.addr),ar=g('authentication-results');
 const au=k=>((ar.match(new RegExp(k+'=(\\w+)','i'))||[,'none'])[1]).toLowerCase();
 const auth={spf:au('spf'),dkim:au('dkim'),dmarc:au('dmarc')};
 const hops=(h['received']||[]).slice().reverse().map((r,i)=>({n:i+1,from:(r.match(/from\s+([^\s(;]+)/i)||[,'-'])[1],by:(r.match(/by\s+([^\s(;]+)/i)||[,'-'])[1],ips:r.match(IP)||[],time:(r.split(';').pop()||'').trim()}));
 const urls=[...new Set(body.match(/https?:\/\/[^\s<>"')]+/gi)||[])].map(u=>{let d='';try{d=new URL(u).hostname.toLowerCase()}catch(e){}return{u,d}});
 const ips=[...new Set(hops.flatMap(x=>x.ips))];
 const sig=[];const add=(t,w,c)=>sig.push({t,w,c});
 if(['fail','softfail'].includes(auth.spf))add('SPF '+auth.spf+' - sending server not authorised',15,'p');
 if(['fail','none','temperror','permerror'].includes(auth.dkim))add('DKIM '+auth.dkim+' - message not signed/verified',8,'p');
 if(auth.dmarc==='fail')add('DMARC fail - From domain not aligned',12,'p');
 const lb=lookalike(fd);if(lb)add('Sender domain '+fd+' imitates "'+lb+'"',30,'i');
 const db=BRANDS.find(b=>from.name.toLowerCase().includes(b));if(db&&!official(fd,db))add('Display name claims "'+db+'" but domain is '+fd,15,'i');
 if(rd&&rd!==fd)add('Reply-To domain ('+rd+') differs from sender domain',12,'b');
 if(retd&&fd&&retd!==fd)add('Return-Path domain ('+retd+') differs from sender domain',6,'p');
 if(/urgent|immediately|suspend|verify|within 24|action required|final notice|locked/i.test(g('subject')+' '+body))add('Urgency / pressure language',10,'p');
 if(/invoice|payment|wire|bank|billing|transfer/i.test(g('subject')+' '+body))add('Financial request wording',8,'b');
 if(urls.some(x=>lookalike(x.d)))add('Link points to lookalike domain',12,'p');
 if(urls.some(x=>/^http:/i.test(x.u)))add('Link uses unencrypted HTTP',5,'p');
 if(urls.some(x=>/^\d+\.\d+\.\d+\.\d+$/.test(x.d)))add('Link uses a raw IP address',10,'p');
 if(FREE.includes(rd))add('Reply-To uses a free mail provider',6,'b');
 const sum=sig.reduce((a,s)=>a+s.w,0),risk=Math.round(100*(1-Math.exp(-sum/50))),label=risk>=75?'HIGH':risk>=40?'MEDIUM':'LOW';
 const cs={p:0,i:0,b:0};sig.forEach(s=>{cs[s.c]+=s.w});
 const susp=Math.round(risk*.05),rest=risk-susp,tc=(cs.p+cs.i+cs.b)||1,p=Math.round(rest*cs.p/tc),i=Math.round(rest*cs.i/tc),b=Math.max(0,rest-p-i);
 const probs=[['Legitimate',100-risk,'#0f7b55'],['Suspicious',susp,'#b45f06'],['Phishing',p,'#c0392b'],['Impersonation',i,'#6d28d9'],['Fraud / BEC',b,'#9b1c1c']];
 const cats=[['Phishing',cs.p,'Credential Phishing'],['Impersonation',cs.i,'Impersonation'],['BEC',cs.b,'Financial Fraud']].filter(x=>x[1]>0).sort((x,y)=>y[1]-x[1]).slice(0,2);
 const pub=ips.filter(x=>!priv(x)).length,oc=Math.min(95,35+14*Math.min(pub,3)+(auth.spf==='pass'?10:0));
 const roles=[['Sender',fd],['Reply-To',rd],['Return-Path',retd],...urls.map(x=>['Link',x.d])].filter(x=>x[1]);const dm={};
 roles.forEach(([r,d])=>{if(!dm[d]){const f=[];const l=lookalike(d);if(l)f.push('lookalike of '+l);if(FREE.includes(d))f.push('free mail provider');if(/xn--/.test(d))f.push('punycode');if((d.match(/-/g)||[]).length>=2)f.push('many hyphens');dm[d]={d,roles:[r],flag:f.join('; ')}}else if(!dm[d].roles.includes(r))dm[d].roles.push(r)});
 return{h,raw,size:raw.length,id:(g('message-id')||'unknown').replace(/[<>]/g,''),from,rt,ret,to,subject:g('subject'),date:g('date'),auth,hops,urls,ips,sig,risk,label,probs,
  threatType:cats.map(x=>x[0]).join(' / ')||'None detected',cls:cats.map(x=>x[2]).join(' + ')||'Likely Legitimate',oc,ocl:oc>=80?'HIGH':oc>=50?'MEDIUM':'LOW',domains:Object.values(dm)}}

const api={IP,priv,BRANDS,FREE,normD,official,lookalike,dom,parseAddr,parseEmail,analyze};
if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.SentinelEngine=api;
})(typeof window!=='undefined'?window:globalThis);
