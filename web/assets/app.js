
let csrf='',settings={},currentUser={};
const title={dashboard:'总览仪表盘',config:'系统配置',debug:'连接调试',ask:'AI 诊断助手',logs:'任务与审计',tokens:'Token 分析'};
const configGroups=[
  {name:'平台与访问',keys:['web_protocol','web_public_host']},
  {name:'AI 模型与提示词',keys:['openai_base_url','openai_model','openai_api_key','ai_alert_prompt','ai_qa_prompt','ai_analysis_profile','ai_tool_loading']},
  {name:'Zabbix MCP',keys:['mcp_url','mcp_token',]},
  {name:'飞书与告警',keys:['lark_app_id','lark_app_secret','allowed_chat_ids','feishu_enabled','feishu_alert_chat_ids','feishu_admin_open_ids','zabbix_webhook_secret','ai_min_severity']}
];
const labels={web_protocol:'Web 访问协议（http / https）',web_public_host:'Web 外部访问主机（例：172.20.200.93:8088）',openai_base_url:'AI API Base URL',openai_model:'AI 模型',openai_api_key:'AI API Key',mcp_url:'Zabbix MCP URL',mcp_token:'只读 MCP Token',lark_app_id:'飞书 App ID',lark_app_secret:'飞书 App Secret',allowed_chat_ids:'允许群聊 ID',feishu_enabled:'飞书通知开关（true/false）',feishu_alert_chat_ids:'企业应用告警群 Chat ID（逗号分隔；留空沿用允许群聊 ID）',feishu_admin_open_ids:'飞书管理员 Open ID（唯一配置来源，ou_ 开头，多个用英文逗号分隔）',zabbix_webhook_secret:'Zabbix Webhook 密钥',ai_min_severity:'AI 分析最低级别（0–5，默认4=严重）',ai_alert_prompt:'告警分析提示词',ai_qa_prompt:'主动问答提示词',ai_analysis_profile:'AI 分析档位（快速 / 标准 / 深度）',ai_tool_loading:'MCP 工具加载模式（动态 / 完整兼容）'};
const secrets=new Set(['openai_api_key','mcp_token','lark_app_secret','zabbix_webhook_secret']);
async function api(path,options={}){const response=await fetch(path,{credentials:'same-origin',...options,headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,...options.headers}});let data;try{data=await response.json()}catch{throw Error('HTTP '+response.status)}if(!response.ok)throw Error(typeof data.detail==='string'?data.detail:'HTTP '+response.status);return data}
function page(id){document.querySelectorAll('.page').forEach(el=>el.classList.toggle('active',el.id===id));document.querySelectorAll('.nav button').forEach(el=>el.classList.toggle('active',el.dataset.page===id));document.getElementById('pagetitle').textContent=title[id];if(id==='config')loadSettings();if(id==='dashboard')refreshStatus();if(id==='logs')loadLogs();if(id==='tokens')loadTokenAnalytics()}
async function bootstrap(){try{currentUser=await api('/api/v1/auth/me');csrf=currentUser.csrf;document.getElementById('login').style.display='none';document.getElementById('app').style.display='block';document.getElementById('username').textContent=currentUser.name;document.getElementById('avatar').textContent=(currentUser.name||'A').slice(0,1);refreshStatus();checkMuteLink();fetch('/healthz',{cache:'no-store'}).then(r=>r.json()).then(v=>{document.getElementById('app-version').textContent='版本 v'+(v.version||'未知')}).catch(()=>{document.getElementById('app-version').textContent='版本未知'})}catch(e){document.getElementById('login-error').textContent='请点击飞书账号登录。如首次配置，确认回调地址和管理员白名单。'}}
async function logout(){try{await api('/api/v1/auth/logout',{method:'POST'})}catch(e){}location.href='/'}
async function loadSettings(){try{settings=await api('/api/v1/settings');document.getElementById('fields').replaceChildren(...configGroups.flatMap(group=>{const heading=document.createElement('div');heading.className='ops-section-title';heading.textContent=group.name;return [heading,...group.keys.map(key=>{const label=labels[key];const wrap=document.createElement('div');if(['ai_alert_prompt','ai_qa_prompt'].includes(key))wrap.className='span2';const l=document.createElement('label');l.textContent=label;const input=document.createElement(['web_protocol','feishu_enabled','ai_analysis_profile','ai_tool_loading'].includes(key)?'select':(['ai_alert_prompt','ai_qa_prompt','ai_prompt'].includes(key)?'textarea':'input'));if(['web_protocol','feishu_alert_mode','feishu_enabled','ai_analysis_profile','ai_tool_loading'].includes(key)){const choices=key==='web_protocol'?['http','https']:(key==='ai_analysis_profile'?['quick','standard','deep']:(key==='ai_tool_loading'?['dynamic','full']:['false','true']));for(const choice of choices){const opt=document.createElement('option');opt.value=choice;opt.textContent=key==='ai_analysis_profile'?({'quick':'快速分析（2轮/4次）','standard':'标准分析（4轮/8次，默认）','deep':'深度分析（6轮/16次）'}[choice]):(key==='ai_tool_loading'?({'dynamic':'动态按需加载（推荐）','full':'完整工具加载（兼容）'}[choice]):choice);input.append(opt)}}input.id='field-'+key;if(secrets.has(key))input.type='password';input.value=settings[key]||'';wrap.append(l,input);return wrap})]}))}catch(e){document.getElementById('save-result').textContent=e.message}}
async function saveSettings(){const values={};for(const key of Object.keys(labels)){const el=document.getElementById('field-'+key);if(el&&el.value!==(settings[key]||''))values[key]=el.value}try{await api('/api/v1/settings',{method:'PUT',body:JSON.stringify({values})});document.getElementById('save-result').textContent='✓ 保存成功';await loadSettings()}catch(e){document.getElementById('save-result').textContent='保存失败：'+e.message}}
async function muteAlert(){const host_id=document.getElementById('mute-host').value.trim(),trigger_id=document.getElementById('mute-trigger').value.trim(),hours=Number(document.getElementById('mute-hours').value);const out=document.getElementById('mute-result');if(!/^\d+$/.test(host_id)||!/^\d+$/.test(trigger_id)){out.textContent='请先从告警卡片打开，或填写有效数字主机 ID、触发器 ID';return}if(!confirm('确认只屏蔽此主机此触发器的飞书重复告警 '+hours+' 小时？Zabbix 监控与恢复消息不受影响。'))return;try{const r=await api('/api/v1/alert-mutes',{method:'POST',body:JSON.stringify({host_id,trigger_id,hours})});out.textContent='已设置屏蔽，到期自动恢复。结束时间：'+new Date(r.expires_at*1000).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai'})}catch(e){out.textContent='屏蔽失败：'+e.message}}
async function unmuteAlert(){const host=document.getElementById('mute-host').value.trim(),trigger=document.getElementById('mute-trigger').value.trim(),out=document.getElementById('mute-result');if(!/^\d+$/.test(host)||!/^\d+$/.test(trigger)){out.textContent='请填写要解除的主机 ID 和触发器 ID';return}if(!confirm('确认立即恢复此类飞书告警通知？'))return;try{await api('/api/v1/alert-mutes/'+encodeURIComponent(host)+'/'+encodeURIComponent(trigger),{method:'DELETE'});out.textContent='已解除屏蔽，后续同类告警将正常发送'}catch(e){out.textContent='操作失败：'+e.message}}
async function listMutes(){const out=document.getElementById('mute-result');try{const rows=await api('/api/v1/alert-mutes');out.textContent=rows.length?rows.map(x=>'主机 '+x.host_id+'｜触发器 '+x.trigger_id+'｜到期 '+new Date(x.expires_at*1000).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai'})).join('\n'):'当前无有效屏蔽'}catch(e){out.textContent=e.message}}
function checkMuteLink(){const p=new URLSearchParams(location.search),host=p.get('mute_host'),trigger=p.get('mute_trigger');if(!host||!trigger)return;page('config');document.getElementById('mute-host').value=host;document.getElementById('mute-trigger').value=trigger;history.replaceState(null,'',location.pathname)}
async function refreshMetrics(){try{const m=await api('/api/v1/alert-stats');document.getElementById('metric-problems').textContent=m.problems;document.getElementById('metric-recoveries').textContent=m.recoveries;document.getElementById('metric-ai').textContent=m.ai_analyses;const q=await api('/api/v1/qa-stats');document.getElementById('metric-qa').textContent=q.total;document.getElementById('metric-qa-breakdown').textContent=`成功 ${q.success} · 失败 ${q.failed} · 待完成 ${q.pending+q.running}`}catch(e){console.warn('metric load failed')}}
function tokenDetail(row){if(row.token_total===null||row.token_total===undefined)return '—';const f=n=>Number(n).toLocaleString('zh-CN');return f(row.token_total)+'（输入 '+f(row.token_input)+' / 输出 '+f(row.token_output)+'）'}
async function openQaMetric(){const panel=document.getElementById('qa-detail');panel.style.display='block';const body=document.getElementById('qa-detail-body');body.replaceChildren();try{const rows=await api('/api/v1/qa-events?limit=100');const sources={feishu:'飞书',web:'Web'};const statuses={pending:'待处理',running:'分析中',success:'成功',failed:'失败'};for(const row of rows){const tr=document.createElement('tr');for(const value of [row.created_at,sources[row.source]||row.source,row.question,statuses[row.status]||row.status,row.completed_at||'—',row.error_type||'—',tokenDetail(row)]){const td=document.createElement('td');td.textContent=value??'';tr.append(td)}body.append(tr)}if(!rows.length){const tr=document.createElement('tr');const td=document.createElement('td');td.colSpan=7;td.textContent='暂无问答记录';tr.append(td);body.append(tr)}}catch(e){body.textContent='读取失败：'+e.message}panel.scrollIntoView({behavior:'smooth',block:'start'})}
async function openMetric(kind){const names={problems:'接收告警明细',recoveries:'接收恢复明细',ai:'自动 AI 分析明细'};document.getElementById('metric-detail-title').textContent=names[kind];document.getElementById('metric-detail').style.display='block';const body=document.getElementById('metric-detail-body');body.replaceChildren();try{const rows=await api('/api/v1/alert-events?kind='+encodeURIComponent(kind)+'&limit=100');for(const row of rows){const tr=document.createElement('tr');for(const field of ['received_at','event_id','host_name','event_name','severity','notify_status','ai_status','token_usage']){const td=document.createElement('td');if(field==='severity'){const levels=['未分类','信息','警告','一般严重','严重','灾难'];const colors=['#718096','#3b82f6','#b7791f','#dd6b20','#dc2626','#a31545'];const n=Number(row[field]);td.textContent=Number.isInteger(n)&&n>=0&&n<=5?levels[n]:'未知';td.style.fontWeight='700';td.style.color=colors[n]||'#718096'}else if(field==='token_usage'){td.textContent=tokenDetail(row)}else{td.textContent=row[field]??''}tr.append(td)}body.append(tr)}if(!rows.length){const tr=document.createElement('tr');const td=document.createElement('td');td.colSpan=8;td.textContent='暂无记录';tr.append(td);body.append(tr)}}catch(e){const tr=document.createElement('tr');const td=document.createElement('td');td.colSpan=8;td.textContent='读取失败：'+e.message;tr.append(td);body.append(tr)}document.getElementById('metric-detail').scrollIntoView({behavior:'smooth',block:'nearest'})}
async function refreshStatus(){refreshMetrics();const out=document.getElementById('status-output'),debug=document.getElementById('debug-output');try{const r=await api('/api/v1/status');document.getElementById('db-state').textContent=r.database==='ok'?'正常':'异常';document.getElementById('redis-state').textContent=r.redis==='ok'?'正常':'异常';document.getElementById('alert-count').textContent=r.queues?.['ai-alerts']??0;document.getElementById('qa-count').textContent=r.queues?.['ai-questions']??0;out.textContent=JSON.stringify(r,null,2);debug.textContent=out.textContent}catch(e){out.textContent=e.message;debug.textContent=e.message}}
async function testMcp(){const out=document.getElementById('debug-output');out.textContent='正在检查 MCP...';try{out.textContent=JSON.stringify(await api('/api/v1/test/mcp',{method:'POST'}),null,2)}catch(e){out.textContent='测试失败：'+e.message}}
async function testAi(){const out=document.getElementById('debug-output');out.textContent='正在调用 AI 模型...';try{out.textContent=JSON.stringify(await api('/api/v1/test/ai',{method:'POST'}),null,2)}catch(e){out.textContent='测试失败：'+e.message}}
async function askAi(){const b=document.getElementById('ask-btn'),out=document.getElementById('ask-answer'),question=document.getElementById('ask-question').value.trim();if(!question){out.textContent='请输入问题';return}b.disabled=true;out.textContent='正在查询 Zabbix MCP 并分析…';try{const r=await api('/api/v1/ask',{method:'POST',body:JSON.stringify({question})});out.textContent=r.answer||'模型未返回分析'}catch(e){out.textContent='问答失败：'+e.message}finally{b.disabled=false}}
const TASK_NAMES={'ai-alerts':'告警处理','ai-questions':'AI 问答','ai-changes':'变更任务'};
const AUDIT_NAMES={alert_mute_feishu:'暂时屏蔽',alert_unmute_feishu:'解除屏蔽',settings_update:'修改系统配置',feishu_login:'飞书登录'};
function renderCell(value){const td=document.createElement('td');td.textContent=String(value??'—');return td}
function emptyTable(body,message,columns){const tr=document.createElement('tr');const td=renderCell(message);td.colSpan=columns;td.className='task-empty';tr.append(td);body.append(tr)}
async function loadLogs(){
  const queueBox=document.getElementById('queue-info');
  const failedBody=document.getElementById('failed-jobs');
  const auditBody=document.getElementById('log-body');
  const status=document.getElementById('task-load-status');
  queueBox.replaceChildren();failedBody.replaceChildren();auditBody.replaceChildren();
  status.textContent='正在加载任务与审计数据…';
  try {
    const data=await api('/api/v1/logs');
    const queues=data.queues||{};
    for(const name of ['ai-alerts','ai-questions','ai-changes']){
      const q=queues[name]||{};
      const card=document.createElement('div');card.className='task-queue-card';
      const title=document.createElement('div');title.className='task-queue-title';title.textContent=TASK_NAMES[name]||name;
      const code=document.createElement('div');code.className='task-queue-code';code.textContent=name;
      const counts=document.createElement('div');counts.className='task-queue-counts';
      for(const [label,key] of [['等待任务','queued'],['历史失败','failed']]){
        const cell=document.createElement('div');cell.className='task-queue-metric';
        const num=document.createElement('strong');num.textContent=Number.isFinite(Number(q[key]))?String(q[key]):'—';
        if(key==='failed'&&Number(q[key])>0)num.className='task-warning';
        const nameEl=document.createElement('span');nameEl.textContent=label;
        cell.append(num,nameEl);counts.append(cell);
      }
      card.append(title,code,counts);queueBox.append(card);
    }
    const jobs=Array.isArray(data.failed_jobs)?data.failed_jobs:[];
    if(jobs.length){for(const job of jobs){const tr=document.createElement('tr');tr.append(renderCell(TASK_NAMES[job.queue]||job.queue),renderCell(job.id));failedBody.append(tr)}}else emptyTable(failedBody,'暂无失败任务',2);
    const audits=Array.isArray(data.audit)?data.audit:[];
    if(audits.length){for(const row of audits){const tr=document.createElement('tr');tr.append(renderCell(row.time),renderCell(AUDIT_NAMES[row.action]||row.action),renderCell(row.key));auditBody.append(tr)}}else emptyTable(auditBody,'暂无审计记录',3);
    status.textContent=data.error?'队列状态读取失败：'+data.error:'已更新 · 共 '+jobs.length+' 条失败任务记录、'+audits.length+' 条审计记录';
  }catch(e){status.textContent='加载失败：'+e.message;emptyTable(failedBody,'无法读取失败任务',2);emptyTable(auditBody,'无法读取审计记录',3)}
}


function tokenFmt(v){return v===null||v===undefined?'—':Number(v).toLocaleString('zh-CN')}
function tokenCell(value){const el=document.createElement('td');el.textContent=String(value??'—');return el}
async function loadTokenAnalytics(){
 const status=document.getElementById('token-status'),cards=document.getElementById('token-stats');
 const daily=document.getElementById('token-daily'),records=document.getElementById('token-records');
 status.textContent='正在读取使用量…';cards.replaceChildren();daily.replaceChildren();records.replaceChildren();
 try{
  const params=new URLSearchParams({days:document.getElementById('token-days').value,source:document.getElementById('token-source').value});
  const data=await api('/api/v1/ai-token-usage?'+params);
  for(const [label,value] of [['总 Token',data.total_tokens],['输入 Token',data.total_input],['输出 Token',data.total_output],['分析次数',data.runs]]){
   const card=document.createElement('div');card.className='task-queue-card';
   const t=document.createElement('div');t.className='task-queue-title';t.textContent=label;
   const n=document.createElement('div');n.className='token-stat-number';n.textContent=tokenFmt(value);
   card.append(t,n);cards.append(card);
  }
  for(const day of data.daily){
   const tr=document.createElement('tr');
   tr.append(tokenCell(day.date),tokenCell(day.runs),tokenCell(tokenFmt(day.input)),tokenCell(tokenFmt(day.output)),tokenCell(tokenFmt(day.tokens)));
   daily.append(tr);
  }
  if(!data.daily.length){const tr=document.createElement('tr');const td=tokenCell('暂无逐轮统计数据');td.colSpan=5;tr.append(td);daily.append(tr)}
  for(const run of data.records){
   const details=document.createElement('details');details.className='token-run';
   const summary=document.createElement('summary');
   summary.textContent=(run.time||'')+' · '+(run.source==='alert'?'告警分析':'AI 问答')+' · '+run.model+' · '+run.profile+' · '+tokenFmt(run.total)+' Token · '+run.tools+' 次工具调用';
   details.append(summary);
   const table=document.createElement('table');table.className='table';
   const head=document.createElement('thead');head.innerHTML='<tr><th>类型 / 轮次</th><th>工具</th><th>输入</th><th>输出</th><th>耗时(ms)</th><th>结果字符数</th></tr>';table.append(head);
   const tbody=document.createElement('tbody');
   for(const part of run.details||[]){
    const tr=document.createElement('tr');
    tr.append(tokenCell(part.kind==='round'?'第 '+part.round+' 轮':'MCP 工具'),
      tokenCell(part.kind==='tool'?part.name:'—'),tokenCell(tokenFmt(part.input)),tokenCell(tokenFmt(part.output)),
      tokenCell(part.ms??'—'),tokenCell(part.kind==='tool'?tokenFmt(part.chars)+' / 原始 '+tokenFmt(part.raw_chars):'—'));
    tbody.append(tr);
   }table.append(tbody);details.append(table);records.append(details);
  }
  if(!data.records.length)records.textContent='暂无分析记录。部署后完成新一轮 AI 分析即可开始记录。';
  status.textContent='已加载 '+data.runs+' 次分析'+(data.truncated?' · 记录已达到本次查询上限':'');
 }catch(e){status.textContent='加载失败：'+e.message}
}

bootstrap();

/* Centralized event registration; legacy inline handlers removed. */
document.querySelectorAll('[data-ui-click="0"]').forEach(el=>el.addEventListener('click',event=>{page('dashboard');}));
document.querySelectorAll('[data-ui-click="1"]').forEach(el=>el.addEventListener('click',event=>{page('config');}));
document.querySelectorAll('[data-ui-click="2"]').forEach(el=>el.addEventListener('click',event=>{page('debug');}));
document.querySelectorAll('[data-ui-click="3"]').forEach(el=>el.addEventListener('click',event=>{page('ask');}));
document.querySelectorAll('[data-ui-click="4"]').forEach(el=>el.addEventListener('click',event=>{page('logs');}));
document.querySelectorAll('[data-ui-click="5"]').forEach(el=>el.addEventListener('click',event=>{logout();}));
document.querySelectorAll('[data-ui-click="6"]').forEach(el=>el.addEventListener('click',event=>{openMetric('problems');}));
document.querySelectorAll('[data-ui-key="7"]').forEach(el=>el.addEventListener('keydown',event=>{if(event.key==='Enter')openMetric('problems');}));
document.querySelectorAll('[data-ui-click="8"]').forEach(el=>el.addEventListener('click',event=>{openMetric('recoveries');}));
document.querySelectorAll('[data-ui-key="9"]').forEach(el=>el.addEventListener('keydown',event=>{if(event.key==='Enter')openMetric('recoveries');}));
document.querySelectorAll('[data-ui-click="10"]').forEach(el=>el.addEventListener('click',event=>{openMetric('ai');}));
document.querySelectorAll('[data-ui-key="11"]').forEach(el=>el.addEventListener('keydown',event=>{if(event.key==='Enter')openMetric('ai');}));
document.querySelectorAll('[data-ui-click="12"]').forEach(el=>el.addEventListener('click',event=>{openQaMetric();}));
document.querySelectorAll('[data-ui-key="13"]').forEach(el=>el.addEventListener('keydown',event=>{if(event.key==='Enter')openQaMetric();}));
document.querySelectorAll('[data-ui-click="14"]').forEach(el=>el.addEventListener('click',event=>{document.getElementById('qa-detail').style.display='none';}));
document.querySelectorAll('[data-ui-click="15"]').forEach(el=>el.addEventListener('click',event=>{document.getElementById('metric-detail').style.display='none';}));
document.querySelectorAll('[data-ui-click="16"]').forEach(el=>el.addEventListener('click',event=>{refreshStatus();}));
document.querySelectorAll('[data-ui-click="17"]').forEach(el=>el.addEventListener('click',event=>{muteAlert();}));
document.querySelectorAll('[data-ui-click="18"]').forEach(el=>el.addEventListener('click',event=>{listMutes();}));
document.querySelectorAll('[data-ui-click="19"]').forEach(el=>el.addEventListener('click',event=>{unmuteAlert();}));
document.querySelectorAll('[data-ui-click="20"]').forEach(el=>el.addEventListener('click',event=>{saveSettings();}));
document.querySelectorAll('[data-ui-click="21"]').forEach(el=>el.addEventListener('click',event=>{loadSettings();}));
document.querySelectorAll('[data-ui-click="22"]').forEach(el=>el.addEventListener('click',event=>{refreshStatus();}));
document.querySelectorAll('[data-ui-click="23"]').forEach(el=>el.addEventListener('click',event=>{testMcp();}));
document.querySelectorAll('[data-ui-click="24"]').forEach(el=>el.addEventListener('click',event=>{testAi();}));
document.querySelectorAll('[data-ui-click="25"]').forEach(el=>el.addEventListener('click',event=>{askAi();}));
document.querySelectorAll('[data-ui-click="26"]').forEach(el=>el.addEventListener('click',event=>{loadLogs();}));

document.querySelectorAll('[data-ui-click="27"]').forEach(el=>el.addEventListener('click',()=>page('tokens')));
document.querySelectorAll('[data-ui-click="28"]').forEach(el=>el.addEventListener('click',loadTokenAnalytics));
for(const id of ['token-days','token-source'])document.getElementById(id)?.addEventListener('change',loadTokenAnalytics);
