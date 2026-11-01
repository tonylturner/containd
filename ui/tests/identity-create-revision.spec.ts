import {expect,test} from '@playwright/test';
const token=(n:number)=>`0123456789abcdef.${n}`;
test('creation consent cannot rebase an unrelated dirty identity row',async({page})=>{
 let counter=1;let bindings=[{ip:'192.0.2.1',identities:['original']}];const writes:any[]=[];
 await page.addInitScript(()=>{localStorage.setItem('containd.auth.token','test');localStorage.setItem('containd.auth.role','admin');});
 await page.route('**/api/v1/**',async route=>{
  const req=route.request(),p=new URL(req.url()).pathname.replace('/api/v1','');
  if(p==='/identities'&&req.method()==='POST'){
   const body=req.postDataJSON(),rev=req.headers()['x-containd-if-revision'];writes.push({body,rev});
   if(rev!==token(counter))return route.fulfill({status:412,json:{error:'changed',code:'config_revision_mismatch',currentRevision:token(counter)}});
   bindings=[...bindings.filter(b=>b.ip!==body.ip),body];
   return route.fulfill({json:body,headers:{'X-Containd-Revision':token(++counter),'X-Containd-Config':'staged'}});
  }
  return route.fulfill({headers:{'X-Containd-Revision':token(counter)},json:p.startsWith('/auth/')?{id:'admin',role:'admin'}:p==='/identities'?{mappings:bindings}:p==='/firewall/rules'?[]:p==='/config/diff'?{changed:false,changedSections:[],pendingConfirm:null,running:{},candidate:{}}:{}});
 });
 await page.goto('/identities/');
 const row=page.getByRole('row').filter({has:page.getByRole('cell',{name:'192.0.2.1',exact:true})});
 await row.getByRole('button',{name:'Edit',exact:true}).click();
 await page.getByLabel('Identities of 192.0.2.1',{exact:true}).fill('original, local');
 await page.getByLabel('Address',{exact:true}).fill('192.0.2.2');
 await page.getByLabel('Identities',{exact:true}).fill('new-binding');
 bindings[0].identities=['original','theirs'];counter++;
 await page.getByRole('button',{name:'Bind',exact:true}).click();
 await page.getByRole('button',{name:'Keep my edits',exact:true}).click();
 await page.getByRole('button',{name:'Bind',exact:true}).click();
 await expect.poll(()=>counter).toBe(3);
 await expect(page.getByRole('button',{name:'Bind',exact:true})).toBeEnabled();
 await row.getByRole('button',{name:'Save',exact:true}).click();
 await expect.poll(()=>writes.length).toBe(3);
 expect(writes[2].rev).toBe(token(1));
 expect(bindings.find(b=>b.ip==='192.0.2.1')!.identities).toContain('theirs');
});
