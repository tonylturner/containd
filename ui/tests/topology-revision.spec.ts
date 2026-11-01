import { expect, test } from '@playwright/test';
const token=(n:number)=>`0123456789abcdef.${n}`;
test('two override writes merge the first acknowledged payload before the second',async({page})=>{
 await page.addInitScript(()=>{localStorage.setItem('containd.auth.token','test');localStorage.setItem('containd.auth.role','admin');});
 let counter=1,hold=false; const writes:any[]=[];
 const zones:any[]=[{name:'ot',slTarget:2},{name:'dmz',slTarget:1}];
 let release!:()=>void; const wait=new Promise<void>(r=>release=r);
 await page.route('**/api/v1/**',async route=>{
  const req=route.request(),path=new URL(req.url()).pathname.replace('/api/v1','');
  if(path.startsWith('/zones/')&&req.method()==='PATCH'){
   const body=req.postDataJSON(),rev=req.headers()['x-containd-if-revision'];writes.push({body,rev});
   if(rev!==token(counter))return route.fulfill({status:412,json:{error:'changed',code:'config_revision_mismatch',currentRevision:token(counter)}});
   Object.assign(zones.find(z=>path.endsWith(z.name)),body); counter++; hold=true;
   return route.fulfill({json:zones.find(z=>path.endsWith(z.name)),headers:{'X-Containd-Revision':token(counter),'X-Containd-Config':'staged'}});
  }
  if(path==='/zones'&&hold)await wait;
  const json=path.startsWith('/auth/')?{id:'admin',role:'admin'}:path==='/zones'?zones:path==='/security/conduits'?[{from:'ot',to:'dmz',state:'allow',ids:'none',proto:[],traffic:0,rules:[],gaps:[],mitre:[],defaultDeny:false,tlsEnforced:false,protoWhitelist:false,mfaRequired:false,auditLogged:true,avEnabled:false}]:path==='/config/diff'?{changed:false,changedSections:[],pendingConfirm:null,running:{},candidate:{}}:{};
  return route.fulfill({json,headers:{'X-Containd-Revision':token(counter)}});
 });
 try{
  await page.goto('/topology/');await page.getByRole('button',{name:'SECURITY',exact:true}).click();
  await page.getByText('ALLOW',{exact:true}).click();
  const buttons=page.getByRole('button',{name:'MARK PASS',exact:true});
  await buttons.nth(0).click(); await expect.poll(()=>counter).toBe(2);
  await expect(page.getByText('Zone override staged — commit to apply.',{exact:true})).toBeVisible();
  await buttons.nth(1).click();await expect.poll(()=>counter).toBe(3);
  expect(Object.keys(zones[0].slOverrides)).toHaveLength(2);
 }finally{release();}
});
