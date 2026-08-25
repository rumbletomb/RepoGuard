const $ = s => document.querySelector(s);
const api = async (url, options={}) => { const r=await fetch(url,{headers:{'content-type':'application/json'},...options}); if(!r.ok) throw new Error((await r.json().catch(()=>({}))).error||`HTTP ${r.status}`); return r.status===204?null:r.json(); };
const esc=s=>String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
async function load(){
  const [d,repos]=await Promise.all([api('/api/dashboard'),api('/api/repositories')]);
  $('#metrics').innerHTML=[['Repositories',d.repositories],['Scans completed',d.scans],['Open findings',d.openFindings],['Critical risk',d.critical]].map(x=>`<div class="metric"><span>${x[0]}</span><strong>${x[1]}</strong></div>`).join('');
  $('#repos').innerHTML=repos.length?repos.map(r=>`<div class="repo"><div><b>${esc(r.name)}</b><small>${esc(r.path)}</small></div><button onclick="scan('${r.id}',this)">Scan</button></div>`).join(''):'<div class="empty">No repositories connected.</div>';
  const scan=d.latestScan; $('#policy').innerHTML=scan?`<b class="${scan.policy.passed?'pass':'fail'}">${scan.policy.passed?'✓ POLICY PASSED':'✕ POLICY FAILED'}</b>`:'';
  $('#findings').innerHTML=scan?.findings?.length?scan.findings.map(f=>`<div class="finding"><div class="finding-head"><b>${esc(f.title)}</b><span class="sev ${f.severity}">${f.severity}</span></div><p>${esc(f.file)}:${f.line} · ${esc(f.ruleId)} · ${esc(f.category)}</p><small>${esc(f.remediation)}</small></div>`).join(''):'<div class="empty">No findings in the latest scan.</div>';
}
async function scan(id,b){b.disabled=true;b.textContent='Scanning…';try{await api(`/api/repositories/${id}/scans`,{method:'POST',body:'{}'});await load()}catch(e){alert(e.message)}finally{b.disabled=false;b.textContent='Scan'}}
$('#refresh').onclick=load; $('#addRepo').onclick=()=>$('#repoDialog').showModal();
$('#repoForm').onsubmit=async e=>{if(e.submitter?.value==='cancel')return; e.preventDefault();const f=new FormData(e.target);try{await api('/api/repositories',{method:'POST',body:JSON.stringify(Object.fromEntries(f))});$('#repoDialog').close();e.target.reset();await load()}catch(err){$('#formError').textContent=err.message}};
load().catch(e=>$('#metrics').textContent=e.message);
