"""Minimal analyst web UI (upload -> analyze -> report)."""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["ui"])

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>APKScan</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{font-family:system-ui,Arial,sans-serif;max-width:880px;margin:2rem auto;padding:0 1rem;color:#1b2733}
 h1{color:#22303f} fieldset{border:1px solid #ccd;border-radius:8px;margin:1rem 0;padding:1rem}
 label{display:block;font-size:.85rem;color:#456;margin:.4rem 0 .15rem}
 input,select,button{font-size:1rem;padding:.45rem;border:1px solid #ccd;border-radius:6px}
 button{background:#22303f;color:#fff;cursor:pointer;border:0;padding:.55rem 1rem}
 pre{background:#0f1720;color:#d7e3ee;padding:1rem;border-radius:8px;overflow:auto;font-size:.8rem}
 .verdict{display:inline-block;padding:.2rem .6rem;border-radius:6px;color:#fff;font-weight:700}
 .Malicious{background:#b00020}.Suspicious{background:#b8860b}.Benign{background:#1b7f3b}
 .muted{color:#789;font-size:.8rem}
</style></head><body>
<h1>APKScan</h1>
<p class="muted">Self-hosted Android banking-malware analysis. GenAI is interpretive only;
deterministic analysis decides the verdict. High/Critical require analyst sign-off.</p>

<fieldset><legend>1 · Sign in</legend>
 <label>Username</label><input id="u" value="admin">
 <label>Password</label><input id="p" type="password" value="admin">
 <p><button onclick="login()">Get token</button> <span id="who" class="muted"></span></p>
</fieldset>

<fieldset><legend>2 · Upload APK</legend>
 <label>APK file</label><input id="f" type="file" accept=".apk">
 <label>Priority</label><select id="pr"><option>default</option><option>urgent</option></select>
 <p><button onclick="upload()">Analyze</button></p>
 <div id="status" class="muted"></div>
</fieldset>

<fieldset><legend>3 · Report</legend>
 <div id="verdict"></div>
 <p id="links"></p>
 <pre id="out">No report yet.</pre>
</fieldset>

<script>
let TOKEN=null;
const h=()=>({"Authorization":"Bearer "+TOKEN});
async function login(){
 const r=await fetch("/auth/token",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({username:u.value,password:p.value})});
 if(!r.ok){who.textContent="login failed";return;}
 const d=await r.json();TOKEN=d.access_token;who.textContent="signed in as "+d.role;
}
async function upload(){
 if(!TOKEN){alert("sign in first");return;}
 if(!f.files[0]){alert("choose an APK");return;}
 const fd=new FormData();fd.append("file",f.files[0]);fd.append("priority",pr.value);
 status.textContent="uploading...";
 const r=await fetch("/api/v1/samples",{method:"POST",headers:h(),body:fd});
 if(!r.ok){status.textContent="upload failed";return;}
 const d=await r.json();status.textContent="job "+d.job_id+" ("+(d.deduped?"dedup ":"")+d.status+")";
 poll(d.job_id);
}
async function poll(job){
 for(let i=0;i<60;i++){
  const r=await fetch("/api/v1/jobs/"+job,{headers:h()});const d=await r.json();
  status.textContent="job "+job+": "+d.status;
  if(d.status==="completed"&&d.report_id){return show(d.report_id);}
  if(d.status==="failed"){out.textContent=d.error||"failed";return;}
  await new Promise(s=>setTimeout(s,1000));
 }
}
async function show(rid){
 const r=await fetch("/api/v1/reports/"+rid,{headers:h()});const d=await r.json();
 const v=(d.verdict&&d.verdict.verdict)||"?";
 verdict.innerHTML='<span class="verdict '+v+'">'+v+'</span> '+
   'score '+(d.verdict?d.verdict.risk_score:"?")+' · confidence '+(d.verdict?d.verdict.confidence:"?");
 links.innerHTML='<a href="/api/v1/reports/'+rid+'/pdf" target="_blank">PDF</a> · '+
   '<a href="/api/v1/reports/'+rid+'/export" target="_blank">Export (IOC/STIX)</a>';
 out.textContent=JSON.stringify(d,null,2);
}
</script></body></html>"""


@router.get("/", response_class=HTMLResponse)
def index() -> str:
    return _PAGE
