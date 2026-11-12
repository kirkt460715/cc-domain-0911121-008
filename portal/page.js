
async function render(background){const params=new URLSearchParams(location.search);const drift=params.get('drift')||'';const token=params.get('token')||'';
if(drift==='navigate-always'){const next=new URL(location.href);next.searchParams.set('bounce',Date.now());location.href=next.toString();return;}
const el=document.getElementById('record');if(!background)el.dataset.ready='false';
const contentUrl='/content?drift='+encodeURIComponent(drift)+'&token='+encodeURIComponent(token);
const data=await(await fetch(contentUrl)).json();await new Promise(r=>setTimeout(r,80));el.replaceChildren();const title=document.createElement('h2');title.textContent=data.title;const text=document.createElement('p');text.textContent=data.text;el.append(title,text);el.dataset.revision=data.revision;el.dataset.ready='true';}
document.getElementById('revise').onclick=async()=>{await fetch('/revision',{method:'POST'});await render();};document.getElementById('navigate').onclick=()=>location.href='/?visit='+Date.now();
render(false);setInterval(()=>render(true),300);
