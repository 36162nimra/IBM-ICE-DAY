import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { ReactFlow, Background, Controls, Handle, Position, MarkerType, type Node, type Edge, type NodeProps } from '@xyflow/react';
import { Activity, AlertTriangle, ArrowDownToLine, ArrowUpRight, Box, Braces, Check, ChevronDown, ChevronRight, Code2, Copy, FileCode2, FileText, FolderOpen, GitBranch, Layers, LoaderCircle, Network, PanelLeftClose, PanelLeftOpen, Search, Send, ShieldCheck, Sparkles, Upload, X } from 'lucide-react';
import { buildImpactReport, edgeKey, explainSymbol, type ImpactReport } from './intelligence';
import '@xyflow/react/dist/style.css';
import './style.css';

type Module = {id:string;name:string;file:string;lines:number;docstring:string;source?:string};
type Symbol = {id:string;name:string;module:string;kind:string;signature:string;docstring:string;file:string;line:number;parameters?:{name:string;kind:string;annotation:string;default:string|null}[];return_annotation?:string;return_expressions?:{line:number;expression:string}[];decorators?:string[];bases?:string[];imports?:{name:string;line:number}[]};
type SecurityFinding = {rule_id:string;title:string;severity:'Critical'|'High'|'Medium'|'Low';confidence:'high'|'medium'|'low';file:string;line:number;snippet:string;risk:string;remediation:string};
type Route = {method:string;path:string;handler:string;signature:string;docstring:string;file:string;line:number;response_model:string;status_code:string;mounted:boolean};
type Finding = {kind:string;message:string;file:string;line:number};
type Result = {name:string;modules:Module[];symbols:Symbol[];routes:Route[];findings:Finding[];security_findings?:SecurityFinding[];cycles:string[][];edges:{source:string;target:string;kind:string;file?:string|null;line?:number|null;locations?:{file:string;line:number}[]}[];stats:{modules:number;symbols:number;routes:number;lines:number;coverage:number;missing_docstrings:number};markdown:string;limitations:string[]};
type GItem = {id:string;label:string;kind:string;module:string};
type View = 'Insights'|'API'|'Impact'|'Security'|'Quality'|'Docs';
const colors:Record<string,string>={module:'#35c6df',class:'#deac54',function:'#ac7af7'};
function download(content:string,name:string,type='text/markdown'){
 const url=URL.createObjectURL(new Blob([content],{type}));const link=document.createElement('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function Code({source,selectedLine=0}:{source:string;selectedLine?:number}){
 const lines=source.split('\n');
 const lineRef=useRef<HTMLDivElement>(null);useEffect(()=>{lineRef.current?.scrollIntoView({block:'center'});},[selectedLine,source]);
 return <div className="source-code">{lines.map((line,i)=><div key={i} ref={i+1===selectedLine?lineRef:undefined} className={'source-line '+(i+1===selectedLine?'highlight':'')}><span className="line-number">{i+1}</span><code>{line.split(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|#.*$|\b(?:async|await|def|class|from|import|return|if|else|for|in|pass|raise|with|as|None|True|False)\b|\b\d+\b)/g).map((part,j)=><span key={j} className={/^["']/.test(part)?'str':part.startsWith('#')?'comment':/^(async|await|def|class|from|import|return|if|else|for|in|pass|raise|with|as|None|True|False)$/.test(part)?'keyword':/^\d+$/.test(part)?'number':''}>{part}</span>)}</code></div>)}</div>;
}
function ConstellationNode({data}:NodeProps){
 const kind=String(data.kind),isSelected=Boolean(data.selected);
 return <div className={'constellation-node '+kind+(isSelected?' selected':'')+(data.impacted?' impacted':'')+(data.cycle?' cycle':'')} style={{'--node-color':colors[kind]} as React.CSSProperties}>
   <Handle type="target" position={Position.Top}/><div className="node-orb"><span/></div><span className="node-label">{String(data.label)}</span>{data.cycle?<span className="cycle-mark">!</span>:null}<Handle type="source" position={Position.Bottom}/>
 </div>;
}
const nodeTypes={constellation:ConstellationNode};
function App(){
 const [result,setResult]=useState<Result|null>(null),[selected,setSelected]=useState(''),[focusLine,setFocusLine]=useState<number|undefined>(undefined),[search,setSearch]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState(''),[view,setView]=useState<View>('Insights'),[types,setTypes]=useState(['module','class','function']),[depth,setDepth]=useState(0),[inspector,setInspector]=useState(true),[question,setQuestion]=useState(''),[answer,setAnswer]=useState(''),[drag,setDrag]=useState(false),[help,setHelp]=useState(false),[leftTab,setLeftTab]=useState('Explorer'),[mobile,setMobile]=useState('Graph'),[impactReport,setImpactReport]=useState<ImpactReport|null>(null),[impactStatus,setImpactStatus]=useState<'idle'|'loading'|'error'|'success'>('idle'),[impactError,setImpactError]=useState(''),[showExplanation,setShowExplanation]=useState(false),[copyStatus,setCopyStatus]=useState(''),[securitySeverity,setSecuritySeverity]=useState('All'),[securityQuery,setSecurityQuery]=useState('');
 const input=useRef<HTMLInputElement>(null),loading=useRef(false);
 async function load(file?:File){
  if(loading.current)return;
  if(file&&(!file.name.toLowerCase().endsWith('.zip')||file.size>10*1024*1024)){setError('Choose a Python repository ZIP up to 10 MB.');return;}
  loading.current=true;setBusy(true);setError('');
  try{
   const response=await fetch(file?'/api/analyze?filename='+encodeURIComponent(file.name):'/api/demo',file?{method:'POST',headers:{'Content-Type':'application/zip'},body:file,signal:AbortSignal.timeout(60000)}:{signal:AbortSignal.timeout(60000)});
   if(!response.ok){let msg='Could not analyze this ZIP.';try{msg=(await response.json()).detail||msg;}catch{}throw new Error(msg);}
   const data:Result=await response.json();setResult(data);setSelected(data.modules.find(m=>m.name.endsWith('.routes'))?.id||data.modules[0]?.id||'');setFocusLine(undefined);setImpactReport(null);setImpactStatus('idle');setSearch('');setAnswer('');setDepth(0);
  }catch(e){setError(e instanceof Error?(e.message==='Failed to fetch'?'Analyzer unavailable. Start the FastAPI server and retry the demo or upload.':e.message):'Analysis failed.');}
  finally{loading.current=false;setBusy(false);if(input.current)input.current.value='';}
 }
 useEffect(()=>{void load();},[]);
 const items=useMemo<GItem[]>(()=>result?[...result.modules.map(m=>({id:m.id,label:m.file.split('/').pop()||m.name,kind:'module',module:m.id})),...result.symbols.map(s=>({id:s.id,label:s.name,kind:s.kind,module:s.module}))]:[],[result]);
 const allEdges=useMemo(()=>result?[...result.edges,...result.symbols.map(s=>({source:s.module,target:s.id,kind:'contains'}))]:[],[result]);
 const {nodes,edges,shown,total}=useMemo(()=>{
  let visible=items.filter(i=>types.includes(i.kind)&&(i.id+' '+i.label).toLowerCase().includes(search.toLowerCase()));
  if(depth&&selected){
   const allowed=new Set([selected]);for(let d=0;d<depth;d++){const prev=new Set(allowed);allEdges.forEach(e=>{if(prev.has(e.source))allowed.add(e.target);if(prev.has(e.target))allowed.add(e.source);});}
   visible=visible.filter(i=>allowed.has(i.id));
  }
  const total=visible.length;visible=visible.slice(0,150);const ids=new Set(visible.map(i=>i.id));
  const modules=result?.modules||[],count=Math.max(modules.length,1);
  const coords=new Map<string,{x:number;y:number}>();
  modules.forEach((m,i)=>{
   const angle=-Math.PI/2+i*Math.PI*2/count,rad=count===1?0:Math.max(175,count*28);
   const center={x:Math.cos(angle)*rad,y:Math.sin(angle)*rad*.85};coords.set(m.id,center);
   const symbols=items.filter(s=>s.module===m.id&&s.kind!=='module');
   symbols.forEach((s,j)=>{const a=angle+(j-(symbols.length-1)/2)*.7;const r=95+Math.floor(j/6)*70;coords.set(s.id,{x:center.x+Math.cos(a)*r,y:center.y+Math.sin(a)*r});});
  });
  const impactIds=new Set(impactReport?[impactReport.target.id,...impactReport.direct.map(item=>item.id),...impactReport.transitive.map(item=>item.id)]:[]);
  const impactEdges=new Set(impactReport?.edgeKeys||[]);
  const nodes:Node[]=visible.map(i=>({id:i.id,type:'constellation',position:coords.get(i.id)||{x:0,y:0},data:{label:i.label,kind:i.kind,selected:i.id===selected,impacted:impactIds.has(i.id),cycle:result?.cycles.some(c=>c.includes(i.module))&&i.kind==='module'},ariaLabel:i.label+' '+i.kind,style:{width:140,height:60},selected:i.id===selected}));
  const edges:Edge[]=allEdges.filter(e=>ids.has(e.source)&&ids.has(e.target)).map((e,i)=>{const active=e.source===selected||e.target===selected,highlight=impactEdges.has(edgeKey(e));return {id:String(i),source:e.source,target:e.target,type:'default',style:{stroke:highlight?'#e4ae62':e.kind!=='import'?'#7652a5':active?'#36b7cb':'#365263',strokeWidth:highlight?2.5:active?1.4:.7,opacity:impactReport?(highlight?.98:.12):(active?.85:.4)},markerEnd:e.kind==='contains'?undefined:{type:MarkerType.ArrowClosed,color:highlight?'#e4ae62':active?'#36b7cb':'#365263',width:11,height:11}};});
  return {nodes,edges,shown:visible.length,total};
 },[items,types,search,depth,selected,result,allEdges,impactReport]);
 const symbol=result?.symbols.find(s=>s.id===selected),module=result?.modules.find(m=>m.id===(symbol?.module||selected));
 const moduleSymbols=result?.symbols.filter(s=>s.module===module?.id)||[];
 const tree=result?.modules.filter(m=>(m.file+' '+m.name).toLowerCase().includes(search.toLowerCase()))||[];
 const filename=(result?.name||'repository').replace(/[^a-zA-Z0-9_-]/g,'_');
 function select(id:string,line?:number){setSelected(id);setFocusLine(line);setMobile('Code');}
 function runImpact(target=symbol){
  if(!result||!target){setImpactStatus('error');setImpactError('Select a function or class to analyze its impact.');setView('Impact');return;}
  setImpactStatus('loading');setImpactError('');setView('Impact');
  requestAnimationFrame(()=>{try{setImpactReport(buildImpactReport(target.id,result));setImpactStatus('success');}catch(e){setImpactStatus('error');setImpactError(e instanceof Error?e.message:'Impact analysis failed.');}});
 }
 async function copyExplanation(){
  if(!result||!symbol)return;
  try{await navigator.clipboard.writeText(explainSymbol(symbol,result));setCopyStatus('Copied');}
  catch{setCopyStatus('Clipboard unavailable in this browser.');}
 }
 function openSecuritySource(finding:SecurityFinding){
  if(!result)return;
  const declarations=result.symbols.filter(item=>item.file===finding.file&&item.line<=finding.line).sort((a,b)=>b.line-a.line);
  const module=result.modules.find(item=>item.file===finding.file);
  select(declarations[0]?.id||module?.id||'',finding.line);
 }
 const securityFindings=result?.security_findings||[];
 const filteredSecurity=securityFindings.filter(item=>(securitySeverity==='All'||item.severity===securitySeverity)&&(`${item.rule_id} ${item.title} ${item.file} ${item.risk}`).toLowerCase().includes(securityQuery.toLowerCase()));
 function ask(value=question){
  if(!result||!value.trim())return;const q=value.toLowerCase();setQuestion('');
  if(/cycle|circular/.test(q))setAnswer(result.cycles.length?result.cycles.map(c=>'Circular import group: '+c.join(' ↔ ')).join('\n'):'No circular import groups were detected.');
  else if(/route|endpoint|api/.test(q))setAnswer(result.routes.length?result.routes.map(r=>r.method+' '+r.path+' → '+r.handler).join('\n'):'No statically recognized FastAPI routes were detected.');
  else if(/doc|quality|missing/.test(q))setAnswer(result.stats.coverage+'% docstring coverage. '+result.stats.missing_docstrings+' declarations are missing docstrings.\n'+result.findings.slice(0,6).map(f=>f.file+':'+f.line+' — '+f.message).join('\n'));
  else{
   const match=result.modules.find(m=>q.includes(m.name.toLowerCase())||q.includes(m.file.toLowerCase()));
   setAnswer(match?match.name+'\n'+(match.docstring||'No module docstring.')+'\n'+result.symbols.filter(s=>s.module===match.id).map(s=>s.signature).join('\n'):result.name+' contains '+result.stats.modules+' Python modules, '+result.stats.symbols+' symbols, and '+result.stats.routes+' detected routes.\nAsk about endpoints, circular imports, missing docstrings, or use an exact module name. Answers are drawn from AST facts; no language model is connected.');
  }
 }
 return <div className={'studio mobile-'+mobile.toLowerCase()} onDragOver={e=>{e.preventDefault();if(e.dataTransfer.types.includes('Files'))setDrag(true)}} onDrop={e=>{e.preventDefault();setDrag(false);const f=e.dataTransfer.files[0];if(f)void load(f)}}>
  <input ref={input} type="file" className="sr-only" accept=".zip" aria-label="Upload repository ZIP" onChange={e=>{if(e.target.files?.[0])void load(e.target.files[0])}}/>
  <header className="topbar">
   <a className="brand" href="#" onClick={e=>{e.preventDefault();setSearch('');setDepth(0)}}><span><Network size={18}/></span>AutoDoc <b>AI</b></a>
   <button className="repo-switch" title="Upload a different repository" onClick={()=>input.current?.click()} disabled={busy}><i/>{result?.name||'Choose repository'}<ChevronDown size={12}/></button>
   <label className="global-search"><Search size={14}/><input aria-label="Search nodes" value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search modules, functions, classes…"/>{search?<button aria-label="Clear search" onClick={()=>setSearch('')}><X size={12}/></button>:<kbd>⌕</kbd>}</label>
   <div className="top-actions"><button className="quiet demo-button" disabled={busy} onClick={()=>void load()}>{busy?<LoaderCircle className="spin" size={13}/>:<Box size={13}/>}Demo</button><button className="quiet" onClick={()=>input.current?.click()} disabled={busy}><Upload size={13}/>Upload ZIP</button><button className="export-button" disabled={!result} onClick={()=>result&&download(result.markdown,filename+'-docs.md')}><ArrowDownToLine size={13}/>Export docs</button><button className="help-button" aria-label="Analysis information" onClick={()=>setHelp(true)}><ShieldCheck size={17}/></button></div>
  </header>
  <div className="mobile-nav">{['Explorer','Code','Graph','Insights'].map(t=><button className={mobile===t?'active':''} key={t} onClick={()=>{setMobile(mobile===t&&t==='Insights'?'Graph':t);if(t==='Code')setInspector(true);}}>{t}</button>)}</div>
  {error&&<div className="error-banner" role="alert"><AlertTriangle size={15}/>{error}<button onClick={()=>setError('')} aria-label="Dismiss error"><X size={14}/></button></div>}
  <div className={'workspace '+(!inspector?'inspector-hidden':'')}>
   <aside className="explorer">
    <div className="pane-tabs">{['Explorer','Filters'].map(t=><button key={t} onClick={()=>setLeftTab(t)} className={leftTab===t?'active':''}>{t}</button>)}</div>
    <div className="explorer-body">{leftTab==='Explorer'?<>
     <div className="section-label"><FolderOpen size={12}/> REPOSITORY <span>{result?.stats.modules||0}</span></div>
     <div className="tree">{tree.map(m=><div key={m.id}><button className={'tree-module '+(module?.id===m.id?'active':'')} onClick={()=>select(m.id)} title={m.file}><ChevronRight size={10}/><FileCode2 size={13}/><span>{m.file.split('/').pop()}</span>{result?.cycles.some(c=>c.includes(m.id))&&<i className="issue-dot"/>}</button>{module?.id===m.id&&moduleSymbols.map(s=><button className={'tree-symbol '+(selected===s.id?'selected':'')} onClick={()=>select(s.id)} key={s.id} title={s.signature}>{s.kind==='class'?<Box size={10}/>:<Braces size={10}/>}<span>{s.name}</span></button>)}</div>)}</div>{!tree.length&&<p className="muted empty-small">{result?'No modules match.':'Load a repository to explore its source.'}</p>}
    </>:<><div className="section-label">NODE TYPES</div><p className="muted small">Choose what appears in the graph.</p>{['module','class','function'].map(t=><label className="filter-option" key={t}><span style={{color:colors[t]}}>{t==='module'?<FileCode2 size={13}/>:t==='class'?<Box size={13}/>:<Braces size={13}/>}</span><span>{t==='module'?'Module':t==='class'?'Class':'Function'}</span><input type="checkbox" checked={types.includes(t)} onChange={()=>setTypes(types.includes(t)?types.filter(v=>v!==t):[...types,t])}/></label>)}</>}
     <div className="filter-section"><div className="section-label">FOCUS DEPTH</div><p className="muted small">Connections around your selection</p><div className="depth-buttons">{[0,1,2].map(n=><button key={n} onClick={()=>setDepth(n)} className={depth===n?'active':''}>{n===0?'All':n+' hop'+(n>1?'s':'')}</button>)}</div></div>
     <div className="filter-section"><div className="section-label">GRAPH LEGEND</div>{Object.entries(colors).map(([kind,color])=><div className="legend" key={kind}><i style={{background:color}}/>{kind}<span>{items.filter(i=>i.kind===kind).length}</span></div>)}<div className="legend"><i className="cycle-dot"/>Import cycle<span>{result?.cycles.length||0}</span></div></div>
    </div>
    <div className="explorer-footer"><ShieldCheck size={13}/><span>Read only. Never executed.</span></div>
   </aside>
   {inspector&&<section className="inspector">
    <div className="pane-header"><Code2 size={14}/><b>Code inspector</b><button aria-label="Hide code inspector" onClick={()=>setInspector(false)}><PanelLeftClose size={14}/></button></div>
    <div className="source-info"><span className="file-tag">PYTHON</span><b>{module?.file.split('/').pop()||'No file selected'}</b><span>{module?.lines||0} lines</span></div>
    <div className="source-path" title={module?.file}>{module?.file||'Select a node to inspect its source'}</div>
    {symbol&&<><div className="symbol-focus"><Braces size={13}/><span>{symbol.signature}</span><small>L{symbol.line}</small></div><div className="symbol-actions"><button className="symbol-action primary" title="Trace statically detected callers and module dependencies" onClick={()=>runImpact(symbol)} disabled={impactStatus==='loading'}><Activity size={12}/>{impactStatus==='loading'?'Analyzing…':'Analyze Impact'}</button><button className="symbol-action" onClick={()=>{setCopyStatus('');setShowExplanation(true)}}><Sparkles size={12}/>{symbol.kind==='class'?'Explain This Class':'Explain This Function'}</button></div></>}
    <div className="code-scroll">{module?<Code source={module.source||'# Source unavailable. Reanalyze this repository to inspect its code.'} selectedLine={focusLine||symbol?.line}/>:<div className="empty-inspector"><Code2 size={27}/><p>Your source, in context.</p><small>Click any module or symbol in the graph.</small></div>}</div>
    <div className="inspector-summary"><div className="section-label">DECLARATION NOTES</div><p>{symbol?.docstring||module?.docstring||'No docstring provided for this declaration.'}</p><div><span>{moduleSymbols.filter(s=>s.kind==='function').length} functions</span><span>{moduleSymbols.filter(s=>s.kind==='class').length} classes</span></div></div>
   </section>}
   <section className="graph-panel">
    <div className="graph-toolbar"><div><Network size={15}/><span>Dependency universe</span><b>LIVE</b></div><button className="quiet" onClick={()=>setInspector(!inspector)} aria-label={inspector?'Hide inspector':'Show inspector'}>{inspector?<PanelLeftClose size={15}/>:<PanelLeftOpen size={15}/>}</button></div>
    <div className="graph-subtitle">{result?.name||'Your next codebase'} <span>/</span> {shown} nodes <span>/</span> {edges.length} connections</div>
    <div className="graph-canvas">
     <ReactFlow key={(result?.name||'empty')+types.join()+search+depth} nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{padding:.1}} minZoom={.15} maxZoom={2.5} nodesDraggable={false} nodesConnectable={false} onNodeClick={(_,node)=>{setSelected(node.id);}} colorMode="dark" proOptions={{hideAttribution:false}}><Background color="#1e1b2d" gap={30} size={.6}/><Controls showInteractive={false} position="bottom-right"/></ReactFlow>
     {!shown&&!busy&&<div className="graph-empty"><Network size={36}/><h2>{result?'No matching nodes':'A clearer view of your code.'}</h2><p>{result?'Adjust the search, node filters, or focus depth.':'Upload a Python ZIP or explore the demo repository.'}</p><button className="export-button" onClick={()=>result?(setSearch(''),setTypes(['module','class','function']),setDepth(0)):void load()}>{result?'Reset filters':'Load demo'}</button></div>}
     {busy&&<div className="loading-overlay"><LoaderCircle className="spin" size={27}/><strong>Mapping your codebase</strong><span>Parsing source · discovering connections</span></div>}
     <div className="graph-hint"><span className="pulse-dot"/> {total>150?'First 150 matches shown · narrow your search':'Select a node to inspect its source'}<small>Scroll to zoom · drag to pan</small></div>
    </div>
    <div className="graph-bottom"><span><i/>Imports</span><span><i className="purple"/>Contains / calls</span>{impactReport&&<span><i className="gold"/>Impact evidence</span>}<span>Static Python AST</span></div>
   </section>
   <aside className="insights">
    <div className="pane-header"><Sparkles size={14}/><b>AutoDoc intelligence</b><span className="local-tag">LOCAL</span></div>
    <div className="insight-tabs">{(['Insights','API','Impact','Security','Quality','Docs'] as View[]).map(v=><button key={v} onClick={()=>setView(v)} className={view===v?'active':''}>{v}{v==='Quality'&&result&&<span>{result.findings.length}</span>}{v==='Security'&&result&&<span>{securityFindings.length}</span>}</button>)}</div>
    <div className="insight-content">
    {view==='Insights'&&<>
     <div className="insight-eyebrow"><span/> REPOSITORY BRIEF</div><h1>Understand the architecture.<br/><em>Find your next move.</em></h1><p className="intro">A source-grounded overview of <b>{result?.name||'your repository'}</b>. Every connection leads back to the code.</p>
     <div className="metric-grid"><div><strong>{result?.stats.modules||0}</strong><span>modules</span></div><div><strong>{result?.stats.symbols||0}</strong><span>symbols</span></div><div><strong>{result?.stats.routes||0}</strong><span>endpoints</span></div></div>
     <div className="insight-section"><h2><Layers size={14}/> Architectural map</h2><p>Explore each module’s role and its declarations.</p><div className="architecture-table"><div className="table-header"><span>Module</span><span>Source evidence</span></div>{result?.modules.map(m=><button key={m.id} onClick={()=>select(m.id)} className={module?.id===m.id?'current':''}><span>{m.name.split('.').pop()}</span><span>{m.docstring||'No module description.'}<code>{m.file.split('/').pop()} <ArrowUpRight size={9}/></code></span></button>)}</div></div>
     <div className="coverage-card"><div><ShieldCheck size={15}/><b>Documentation coverage</b><strong>{result?.stats.coverage||0}%</strong></div><div className="coverage-track"><i style={{width:(result?.stats.coverage||0)+'%'}}/></div><p>{result?.stats.missing_docstrings||0} declarations need a docstring.<button onClick={()=>setView('Quality')}>Review findings <ArrowUpRight size={11}/></button></p></div>
     {!!result?.cycles.length&&<button className="cycle-alert" onClick={()=>setView('Quality')}><AlertTriangle size={16}/><span><b>{result.cycles.length} circular import group detected</b><small>Review coupling between modules</small></span><ChevronRight size={13}/></button>}
    </>}
    {view==='API'&&<><div className="insight-eyebrow">FASTAPI REFERENCE</div><h1>{result?.routes.length||0} endpoints discovered</h1><p className="intro">Literal paths and resolved router prefixes.</p>{result?.routes.map((r,i)=><details className="route" key={i}><summary><span className={'method '+r.method.toLowerCase()}>{r.method}</span><code>{r.path}</code><ChevronDown size={12}/></summary><div><p>{r.docstring||'No docstring provided.'}</p><pre>{r.signature}</pre><dl><dt>Response</dt><dd>{r.response_model||'Not declared'}</dd><dt>Status</dt><dd>{r.status_code}</dd><dt>Mounted</dt><dd>{r.mounted?'Resolved':'Unresolved'}</dd></dl><button className="source-link" onClick={()=>select(result.symbols.find(s=>s.file===r.file&&s.line===r.line)?.id||'')}>{r.file}:{r.line}<ArrowUpRight size={11}/></button></div></details>)}{!result?.routes.length&&<p className="empty-small">No FastAPI routes detected.</p>}</>}
    {view==='Impact'&&<>
      <div className="insight-eyebrow">CHANGE IMPACT · STATIC CALL GRAPH</div><h1>Analyze change impact</h1><p className="intro">Select a function or class, then choose Analyze Impact in the code inspector.</p>
      {impactStatus==='idle'&&<div className="feature-empty"><Activity size={22}/><b>Choose a symbol to begin</b><span>Impact tracing follows detected call edges. Module imports are shown separately and are not treated as calls.</span></div>}
      {impactStatus==='loading'&&<div className="feature-state"><LoaderCircle className="spin" size={18}/>Tracing detected relationships…</div>}
      {impactStatus==='error'&&<div className="feature-state error"><AlertTriangle size={16}/>{impactError}</div>}
      {impactStatus==='success'&&impactReport&&<>
       <div className="impact-target"><small>SELECTED SYMBOL</small><b>{impactReport.target.signature}</b><code>{impactReport.target.file}:{impactReport.target.line}</code></div>
       <p className="impact-limit">Static evidence only. Dynamic dispatch, reflection, and runtime registration may hide additional effects.</p>
       <div className="impact-counts"><span><b>{impactReport.direct.length}</b> direct relationships</span><span><b>{impactReport.transitive.length}</b> transitive callers</span><span><b>{impactReport.modules.length}</b> potentially affected modules</span></div>
       {impactReport.direct.length>0&&<section className="impact-section"><h2>Direct relationships</h2>{impactReport.direct.map((item,i)=><button className="impact-item" key={item.kind+item.id+i} onClick={()=>select(item.id)}><span className="impact-kind">{item.direction} · {item.kind}</span><b>{item.label}</b><code>{item.file}{item.line?':'+item.line:''}</code><small>{item.reason}</small></button>)}</section>}
       {impactReport.transitive.length>0&&<section className="impact-section"><h2>Transitive callers</h2>{impactReport.transitive.map((item,i)=><button className="impact-item transitive" key={item.id+i} onClick={()=>select(item.id)}><span className="impact-kind">{item.direction} · {item.depth} hops</span><b>{item.label}</b><code>{item.file}{item.line?':'+item.line:''}</code><small>{item.reason}</small></button>)}</section>}
       {impactReport.modules.length>0&&<section className="impact-section"><h2>Potentially affected modules</h2>{impactReport.modules.map(item=><button className="impact-item module-impact" key={item.id} onClick={()=>select(item.id)}><span className="impact-kind">{item.depth===1?'Direct evidence':'Transitive evidence'}</span><b>{item.name}</b><code>{item.file}</code><small>{item.reason}</small></button>)}</section>}
       {!impactReport.direct.length&&!impactReport.transitive.length&&!impactReport.modules.length&&<div className="feature-empty"><Check size={20}/><b>No relationships detected</b><span>No direct call or importing-module relationships were found for this symbol. Static analysis cannot rule out runtime dependencies.</span></div>}
      </>}
     </>}
     {view==='Security'&&<>
      <div className="insight-eyebrow">STATIC SECURITY CHECKS</div><h1>{securityFindings.length} potential findings</h1><p className="intro">Conservative source patterns with line links, remediation, and confidence labels.</p>
      <label className="security-search"><Search size={13}/><input aria-label="Search security findings" placeholder="Search filename, rule, or risk…" value={securityQuery} onChange={e=>setSecurityQuery(e.target.value)}/></label>
      <div className="severity-filters">{['All','Critical','High','Medium','Low'].map(level=><button key={level} className={securitySeverity===level?'active':''} onClick={()=>setSecuritySeverity(level)}>{level}<span>{level==='All'?securityFindings.length:securityFindings.filter(f=>f.severity===level).length}</span></button>)}</div>
      {filteredSecurity.map((item,i)=><article className="security-finding" key={item.rule_id+item.file+item.line+i}><div className="security-heading"><span className={'severity '+item.severity.toLowerCase()}>{item.severity}</span><span>{item.rule_id}</span><small>Confidence: {item.confidence}</small></div><h2>{item.title}</h2><p>{item.risk}</p><pre>{item.snippet||'No source snippet available.'}</pre><div className="security-fix"><b>Suggested remediation</b><p>{item.remediation}</p></div><button className="source-link" onClick={()=>openSecuritySource(item)}>{item.file}:{item.line}<ArrowUpRight size={11}/></button></article>)}
      {securityFindings.length===0&&<div className="feature-empty"><ShieldCheck size={22}/><b>No patterns detected</b><span>No findings does not mean the repository is secure. These static checks cover a limited set of patterns and cannot prove exploitability or absence of vulnerabilities.</span></div>}
      {securityFindings.length>0&&!filteredSecurity.length&&<p className="empty-small">No security findings match the selected severity and search.</p>}
      <p className="security-limit">Static heuristics only · findings require human review · source is never executed</p>
     </>}
     {view==='Quality'&&<><div className="insight-eyebrow">CODEBASE HEALTH</div><h1>Small fixes. Clearer code.</h1><p className="intro">{result?.findings.length||0} source-backed findings.</p>{result?.findings.map((f,i)=><button className="finding" key={i} onClick={()=>select(result.symbols.find(s=>s.file===f.file&&s.line===f.line)?.id||result.modules.find(m=>m.file===f.file)?.id||'')}><AlertTriangle size={14}/><span><small>{f.kind.replaceAll('_',' ')}</small><b>{f.message}</b><code>{f.file}:{f.line}</code></span><ArrowUpRight size={11}/></button>)}{!result?.findings.length&&<p className="empty-small">No findings in this analysis.</p>}</>}
    {view==='Docs'&&<><div className="insight-eyebrow">READY TO SHARE</div><h1>Your reference, generated.</h1><p className="intro">Deterministic Markdown from declarations and docstrings.</p><div className="download-actions"><button className="export-button" disabled={!result} onClick={()=>result&&download(result.markdown,filename+'-docs.md')}><FileText size={14}/>Markdown</button><button className="quiet outlined" disabled={!result} onClick={()=>result&&download(JSON.stringify(result,null,2),filename+'-analysis.json','application/json')}><Code2 size={14}/>JSON</button></div><pre className="markdown">{result?.markdown||'Load a repository to generate documentation.'}</pre></>}
    </div>
    <div className="ask-panel">{answer&&<div className="answer" role="status"><div><Sparkles size={12}/><b>From your source</b><button onClick={()=>setAnswer('')} aria-label="Clear answer"><X size={12}/></button></div><p>{answer}</p></div>}<div className="suggestions">{['API endpoints','Import cycles','Missing docs'].map(q=><button key={q} disabled={!result} onClick={()=>ask(q)}>{q}</button>)}</div><form onSubmit={e=>{e.preventDefault();ask()}}><input aria-label="Ask about the codebase" placeholder="Ask about the codebase…" value={question} onChange={e=>setQuestion(e.target.value)}/><button aria-label="Ask" disabled={!result||!question.trim()}><Send size={14}/></button></form><small><ShieldCheck size={9}/> AST facts only · no external AI provider</small></div>
   </aside>
  </div>
  <footer className="statusbar"><span><i className={busy?'working':''}/>{busy?'Analyzing':result?'Analysis ready':'Waiting for repository'}</span><span>{result?.stats.modules||0} files<span className="status-separator">·</span>{result?.stats.lines||0} lines<span className="status-separator">·</span>Python AST <span className="status-separator">·</span><ShieldCheck size={10}/> No execution</span></footer>
  {drag&&<div className="drop-overlay" onDragLeave={()=>setDrag(false)}><Upload size={38}/><h2>Drop your Python repository</h2><p>ZIP · up to 10 MB · analyzed locally</p></div>}
  {showExplanation&&symbol&&result&&<div className="modal-overlay" onClick={()=>setShowExplanation(false)}><section role="dialog" aria-modal="true" aria-labelledby="explanation-title" className="help-modal explanation-modal" onClick={e=>e.stopPropagation()}><button aria-label="Close explanation" className="close" onClick={()=>setShowExplanation(false)}><X size={18}/></button><Sparkles size={23}/><h2 id="explanation-title">{symbol.kind==='class'?'Explain This Class':'Explain This Function'}</h2><p>Built from this declaration’s AST metadata and detected call relationships. No language model is used.</p><pre className="explanation-text">{explainSymbol(symbol,result)}</pre><div className="explanation-actions"><button className="symbol-action primary" onClick={()=>void copyExplanation()}><Copy size={13}/>Copy Explanation</button><span role="status">{copyStatus}</span></div></section></div>}
  {help&&<div className="modal-overlay" onClick={()=>setHelp(false)}><section role="dialog" aria-modal="true" aria-labelledby="help-title" className="help-modal" onClick={e=>e.stopPropagation()}><button aria-label="Close information" className="close" onClick={()=>setHelp(false)}><X size={18}/></button><ShieldCheck size={27}/><h2 id="help-title">Your code never runs here.</h2><p>AutoDoc reads Python syntax in memory. Uploaded code is never imported, executed, or sent to an AI provider.</p><ul>{(result?.limitations||['ZIP limit: 10 MB; 300 Python files.','Static declarations only. Dynamic behavior may be unresolved.']).map(l=><li key={l}>{l}</li>)}</ul><p>Use this MVP locally. The parser is not isolated in an OS sandbox.</p></section></div>}
 </div>;
}
createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>);
