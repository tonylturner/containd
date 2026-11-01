import { expect, test, type Page } from '@playwright/test';
const token = (n:number) => `0123456789abcdef.${n}`;
async function auth(page: Page) { await page.addInitScript(() => { localStorage.setItem('containd.auth.token','test'); localStorage.setItem('containd.auth.role','admin'); }); }

test('routing Keep followed by two deletes does not resurrect the first gateway', async ({page}) => {
 await auth(page);
 let counter=1, hold=false;
 let routing:any={gateways:[{name:'one',address:'192.0.2.1'},{name:'two',address:'192.0.2.2'}],routes:[],rules:[]};
 const writes:any[]=[];
 let release!:()=>void; const held=new Promise<void>(r=>release=r);
 await page.route('**/api/v1/**',async route=>{
  const req=route.request(), path=new URL(req.url()).pathname.replace('/api/v1','');
  if(path==='/routing' && req.method()==='POST') {
   const body=req.postDataJSON(), rev=req.headers()['x-containd-if-revision']; writes.push({body,rev});
   if(rev!==token(counter)) return route.fulfill({status:412,json:{error:'changed',code:'config_revision_mismatch',currentRevision:token(counter)}});
   routing=body; counter++; hold=true;
   return route.fulfill({json:body,headers:{'X-Containd-Revision':token(counter),'X-Containd-Config':'staged'}});
  }
  if(path==='/routing' && hold) await held;
  const json=path.startsWith('/auth/')?{id:'admin',role:'admin'}:path==='/routing'?routing:path==='/config/diff'?{pendingConfirm:null,changed:false,changedSections:[],running:{},candidate:{}}:{};
  return route.fulfill({json,headers:{'X-Containd-Revision':token(counter)}});
 });
 try {
  await page.goto('/routing/');
  const row=(name:string)=>page.getByRole('row').filter({has:page.getByRole('cell',{name,exact:true})});
  await expect(row('one')).toBeVisible(); counter++;
  await row('one').getByRole('button',{name:'Delete',exact:true}).click();
  await page.getByRole('button',{name:'Keep my edits',exact:true}).click();
  await row('one').getByRole('button',{name:'Delete',exact:true}).click();
  await expect.poll(()=>counter).toBe(3);
  await expect(page.getByText('Routing staged — commit to apply.',{exact:true})).toBeVisible();
  await row('two').getByRole('button',{name:'Delete',exact:true}).click();
  await expect.poll(()=>counter).toBe(4);
  expect(routing.gateways).toEqual([]);
 } finally {release();}
});

test('reverse proxy Add clears fields after local transfer',async({page})=>{
 await auth(page);
 await page.route('**/api/v1/**',route=>{
  const p=new URL(route.request().url()).pathname.replace('/api/v1','');
  return route.fulfill({headers:{'X-Containd-Revision':token(1)},json:p.startsWith('/auth/')?{id:'admin',role:'admin'}:p==='/services/proxy/reverse'?{sites:[]}:p==='/config/diff'?{changed:false,changedSections:[],pendingConfirm:null,running:{},candidate:{}}:{}});
 });
 await page.goto('/proxies/');
 await page.getByPlaceholder('site name').fill('operator-console');
 await page.getByPlaceholder('backends host:port, host:port').fill('192.0.2.10:80');
 await page.getByRole('button',{name:'Add',exact:true}).click();
 await expect(page.getByText('operator-console',{exact:true})).toBeVisible();
 await expect(page.getByPlaceholder('site name')).toHaveValue('');
 await expect(page.getByPlaceholder('backends host:port, host:port')).toHaveValue('');
});

test('wizard adopts a successful publish before another deliberate publish',async({page})=>{
 await auth(page); let counter=1; const writes:string[]=[];
 await page.route('**/api/v1/**',async route=>{
  const req=route.request(),p=new URL(req.url()).pathname.replace('/api/v1','');
  if(p==='/firewall/port-forwards'&&req.method()==='POST') {
   const body=req.postDataJSON(),rev=req.headers()['x-containd-if-revision'];writes.push(rev);
   if(rev!==token(counter))return route.fulfill({status:412,json:{error:'changed',code:'config_revision_mismatch',currentRevision:token(counter)}});
   return route.fulfill({headers:{'X-Containd-Revision':token(++counter),'X-Containd-Config':'staged'},json:{forward:body.forward,placement:{reason:'generated',rule:{id:'pf-allow'},index:0}}});
  }
  return route.fulfill({headers:{'X-Containd-Revision':token(counter)},json:p.startsWith('/auth/')?{id:'admin',role:'admin'}:p==='/zones'?[{name:'lan'},{name:'wan'}]:p==='/firewall/nat'?{enabled:false}:p==='/config/diff'?{changed:false,changedSections:[],pendingConfirm:null,running:{},candidate:{}}:{}});
 });
 await page.goto('/wizard/');
 for(let i=0;i<2;i++){
  await page.getByRole('button',{name:/Publish Internal Service/}).click();
  await page.getByPlaceholder('e.g. 192.168.1.10').fill('192.0.2.5');
  await page.getByPlaceholder('e.g. 443').fill(String(502+i));
  await page.getByRole('button',{name:'Next',exact:true}).click();
  await page.getByRole('button',{name:'Next',exact:true}).click();
  await page.getByRole('combobox').selectOption('wan');
  await page.getByRole('button',{name:'Next',exact:true}).click();
  await page.getByRole('button',{name:'Stage',exact:true}).click();
  await expect.poll(()=>writes.length).toBe(i+1);
  if(i===0) {await expect(page.getByRole('heading',{name:'Success',exact:true})).toBeVisible();await page.getByRole('button',{name:'Run another wizard',exact:true}).click();}
 }
 expect(writes).toEqual([token(1),token(2)]);
});
