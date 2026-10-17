import {createHash} from "node:crypto";
import {mkdtemp,rm} from "node:fs/promises";
import {createServer} from "node:net";
import {tmpdir} from "node:os";
import path from "node:path";

import {Client,StreamableHTTPClientTransport} from "@modelcontextprotocol/client";
import {describe,expect,it} from "vitest";

import {V3_I01_MCP_TOOL_NAMES,type V3FinalFourMcpPorts} from
  "../../../src/v3/control-plane/final4-mcp-surface.js";
import {startV3ReadOnlyOAuthGateway} from "../../../src/v3/gateway/oauth-readonly.js";
import {testConfig} from "../../helpers/config.js";

async function availablePort():Promise<number>{
  const server=createServer();
  server.listen(0,"127.0.0.1");
  await new Promise<void>((resolve,reject)=>{
    server.once("listening",resolve);
    server.once("error",reject);
  });
  const address=server.address();
  if(!address||typeof address==="string")throw Error("TCP listener required");
  await new Promise<void>(resolve=>server.close(()=>resolve()));
  return address.port;
}

describe("I01-only V3 OAuth gateway discovery (never a physical execution)",()=>{
  it("advertises only I01 operations and refuses F01 OAuth scope",async()=>{
    const root=await mkdtemp(path.join(tmpdir(),"radlina-v3-i01-surface-"));
    const port=await availablePort(),origin="http://127.0.0.1:"+port;
    // Register-only port fixture: no real device, executable adapter, P03 key,
    // Keychain, owner-signing broker, consent grant or external S03 service.
    const i01Ports={
      authenticatedPlugin:{},
      execution:{},
      s02e:{},
    } as unknown as V3FinalFourMcpPorts;
    let gateway:Awaited<ReturnType<typeof startV3ReadOnlyOAuthGateway>>|undefined;
    let client:Client|undefined;
    try{
      gateway=await startV3ReadOnlyOAuthGateway({
        baseConfig:testConfig(root),stateDirectory:path.join(root,"v3-state"),
        publicUrl:"https://v3-mcp.radlina.com",port,finalFour:i01Ports,
      });
      const metadata=await fetch(origin+"/.well-known/oauth-authorization-server");
      expect(metadata.status).toBe(200);
      const scopes=(await metadata.json() as {scopes_supported:string[]}).scopes_supported;
      expect(scopes).toContain("device:execute");
      expect(scopes).not.toContain("fleet:control");

      const registration=await fetch(origin+"/register",{
        method:"POST",headers:{"content-type":"application/json"},
        body:JSON.stringify({
          redirect_uris:["http://127.0.0.1/callback"],
          client_name:"unit-only-no-executable-physical-i01",
        }),
      });
      expect(registration.status).toBe(201);
      const {client_id}=await registration.json() as {client_id:string};
      const verifier="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
      const params=new URLSearchParams({
        response_type:"code",client_id,
        redirect_uri:"http://127.0.0.1/callback",
        code_challenge:createHash("sha256").update(verifier).digest("base64url"),
        code_challenge_method:"S256",
        resource:gateway.auth.resourceUrl.href,
        scope:"device:read",state:"v3-i01-only-discovery",
      });
      const ask=await fetch(origin+"/authorize?"+params.toString());
      expect(ask.status).toBe(200);
      const html=await ask.text();
      const approvalId=/Request ID: <code>([0-9a-f-]+)<\/code>/u.exec(html)?.[1];
      expect(approvalId).toBeTruthy();
      expect(gateway.auth.approve(approvalId!,"v3-i01-test-owner")).toBe(true);
      const grant=await fetch(origin+"/authorize?request_id="+approvalId,{redirect:"manual"});
      expect(grant.status).toBe(302);
      const callback=new URL(grant.headers.get("location")!);
      const result=await fetch(origin+"/token",{
        method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},
        body:new URLSearchParams({
          grant_type:"authorization_code",
          code:callback.searchParams.get("code")!,
          client_id,redirect_uri:"http://127.0.0.1/callback",
          code_verifier:verifier,resource:gateway.auth.resourceUrl.href,
        }),
      });
      expect(result.status).toBe(200);
      const {access_token}=await result.json() as {access_token:string};
      client=new Client({name:"v3-i01-surface-test",version:"1.0.0"},
        {versionNegotiation:{mode:"auto"}});
      await client.connect(new StreamableHTTPClientTransport(new URL(gateway.url),{
        requestInit:{headers:{authorization:"Bearer "+access_token}},
      }));
      const actual=(await client.listTools()).tools.map(x=>x.name).sort();
      const expected=[
        "get_capabilities","get_device","list_devices","v3_admin_status",
        ...V3_I01_MCP_TOOL_NAMES,
      ].sort();
      expect(actual).toEqual(expected);
      expect(actual).not.toContain("v3_fleet_plan");
      expect(actual).not.toContain("v3_fleet_run");
      expect(actual).not.toContain("v3_fleet_reconcile");
      expect(actual).not.toContain("v3_release_acceptance_status");
      const state=await client.callTool({name:"v3_admin_status",arguments:{}});
      expect(state.structuredContent).toMatchObject({result:{
        productionReady:false,remoteExecutionEnabled:true,
        finalFourPortsBound:false,i01PortsBound:true,
      }});
      const capabilities=await client.callTool({name:"get_capabilities",arguments:{}});
      const advertised=(capabilities.structuredContent as {result:{tools:string[]}}).result.tools;
      expect([...advertised].sort()).toEqual(actual);
    }finally{
      if(client)await client.close();
      if(gateway)await gateway.shutdown();
      await rm(root,{recursive:true,force:true});
    }
  },45000);
});
