
const status=document.getElementById('status'),form=document.getElementById('setup');
fetch('/api/v1/setup/status',{cache:'no-store'}).then(r=>r.json()).then(v=>{
 if(!v.setup_required){form.hidden=true;status.textContent='初始化已完成，请返回首页登录。';}
}).catch(()=>{status.textContent='无法获取初始化状态，请检查服务。'});
form.addEventListener('submit',async e=>{
 e.preventDefault();status.textContent='正在验证并保存…';
 const payload=Object.fromEntries(new FormData(form).entries());
 try{
  const resp=await fetch('/api/v1/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const data=await resp.json();
  if(!resp.ok)throw Error(typeof data.detail==='string'?data.detail:'初始化失败');
  form.hidden=true;
  status.textContent='初始化成功。请确认飞书开放平台的回调地址为 '+payload.web_protocol+'://'+payload.web_public_host+'/api/v1/auth/callback ，再返回首页使用飞书登录。';
 }catch(err){status.textContent=err.message;}
});
