import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";

import { V3_FINAL4_MCP_TOOL_NAMES, type V3FinalFourMcpPorts } from "../../../src/v3/control-plane/final4-mcp-surface.js";
import { startV3ReadOnlyOAuthGateway } from "../../../src/v3/gateway/oauth-readonly.js";
import { testConfig } from "../../helpers/config.js";

async function availablePort():Promise<number>{
  const listener=createServer();
  listener.listen(0,"127.0.0.1");
  await new Promise<void>((resolve,reject)=>{
    listener.once("listening",resolve);
    listener.once("error",reject);
  });
  const address=listener.address();
  if(!address||typeof address==="string")throw Error("expected TCP listener");
  await new Promise<void>(resolve=>listener.close(()=>resolve()));
  return address.port;
}

describe("V3 standalone OAuth final-four MCP discovery (test-only ports)",()=>{
  it("matches discovered capabilities to all eight actual registered tools and guards privileged scopes",async()=>{
    const root=await mkdtemp(path.join(tmpdir(),"radlina-v3-final4-mcp-discovery-"));
    const cfg=testConfig(root),port=await availablePort();
    const origin="http://127.0.0.1:"+port;
    // Only a registration/discovery fixture, never executable physical
    // ports. No tool side effects, enrolled devices, signed receipt or
    // owner acceptance can result from this test.
    const finalFour={
      fleet:{},
      acceptance:{readiness:()=>({productionReady:false})},
    } as unknown as V3FinalFourMcpPorts;
    let gateway:Awaited<ReturnType<typeof startV3ReadOnlyOAuthGateway>>|undefined;
    let client:Client|undefined;
    try{
      gateway=await startV3ReadOnlyOAuthGateway({
        baseConfig:cfg,stateDirectory:path.join(root,"v3-state"),
        // Exercise the real exact V3 issuer scope policy on a loopback-only
        // test listener; OAuth traffic remains local and uses no live token.
        publicUrl:"https://v3-mcp.radlina.com",port,finalFour,
      });
      const oauthMetadataResponse=await fetch(origin+"/.well-known/oauth-authorization-server");
      expect(oauthMetadataResponse.status).toBe(200);
      const oauthMetadata=await oauthMetadataResponse.json() as {scopes_supported:string[]};
      expect(oauthMetadata.scopes_supported).toContain("device:execute");
      expect(oauthMetadata.scopes_supported).toContain("fleet:control");
      expect(oauthMetadata.scopes_supported).not.toContain("admin");

      const registration=await fetch(origin+"/register",{
        method:"POST",headers:{"content-type":"application/json"},
        body:JSON.stringify({
          redirect_uris:["http://127.0.0.1/callback"],
          client_name:"unit-only-no-physical-ports",
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
        resource:gateway.auth.resourceUrl.href,scope:"device:read",
        state:"v3-final4-discovery",
      });
      const ask=await fetch(origin+"/authorize?"+params.toString());
      expect(ask.status).toBe(200);
      const html=await ask.text();
      const approvalId=/Request ID: <code>([0-9a-f-]+)<\/code>/u.exec(html)?.[1];
      expect(approvalId).toBeTruthy();
      expect(gateway.auth.approve(approvalId!,"v3-unit-only-owner")).toBe(true);
      const grant=await fetch(origin+"/authorize?request_id="+approvalId,{redirect:"manual"});
      expect(grant.status).toBe(302);
      const callback=new URL(grant.headers.get("location")!);
      const response=await fetch(origin+"/token",{
        method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},
        body:new URLSearchParams({
          grant_type:"authorization_code",
          code:callback.searchParams.get("code")!,
          client_id,redirect_uri:"http://127.0.0.1/callback",
          code_verifier:verifier,resource:gateway.auth.resourceUrl.href,
        }),
      });
      expect(response.status).toBe(200);
      const token=await response.json() as {access_token:string};
      client=new Client({name:"v3-final4-discovery-test",version:"1.0.0"},
        {versionNegotiation:{mode:"auto"}});
      await client.connect(new StreamableHTTPClientTransport(new URL(gateway.url),{
        requestInit:{headers:{authorization:"Bearer "+token.access_token}},
      }));
      const actual=(await client.listTools()).tools.map(t=>t.name).sort();
      const expected=[
        "get_capabilities","get_device","list_devices","v3_admin_status",
        ...V3_FINAL4_MCP_TOOL_NAMES,
      ].sort();
      expect(actual).toEqual(expected);
      const capabilities=await client.callTool({name:"get_capabilities",arguments:{}});
      const metadata=capabilities.structuredContent as {result:{tools:string[]}};
      expect([...metadata.result.tools].sort()).toEqual(actual);
      expect(actual).toContain("v3_exact_device_reconcile");
      expect(actual).toContain("v3_fleet_reconcile");
    }finally{
      if(client)await client.close();
      if(gateway)await gateway.shutdown();
      await rm(root,{recursive:true,force:true});
    }
  },45000);
});
