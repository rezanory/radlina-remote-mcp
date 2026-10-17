import {readFileSync} from "node:fs";
import path from "node:path";
import {describe,expect,it} from "vitest";

import {resolveFinalFourProvisionMode} from "../../../src/v3/integration/final4-development-gating.js";
import {registeredV3PhysicalToolNames, V3_FINAL4_MCP_TOOL_NAMES,
  V3_I01_MCP_TOOL_NAMES, type V3FinalFourMcpPorts,
} from "../../../src/v3/control-plane/final4-mcp-surface.js";

const read=(file:string)=>readFileSync(path.resolve(file),"utf8");
const bootstrap=read("src/v3/integration/final4-physical-bootstrap.ts");
const factory=read("src/v3/control-plane/v3-environment-factory.ts");
const relay=read("src/v3/integration/i01-agent-relay-http.ts");
const gateway=read("src/v3/gateway/oauth-readonly.ts");
const policies=read("scripts/operations/v3-final4-owner-policies.ts");
const stage=read("scripts/operations/v3-final4-gateway-stage.ps1");
const migrations=read("src/v3/integration/final4-schema-migrations.ts");

describe("Production I01-only physical composition (no fake F01/AC01 ports)",()=>{
  it("allows ONLY explicit real I01 production mode, never a development-only binding",()=>{
    expect(resolveFinalFourProvisionMode("--prepare-i01")).toEqual({
      name:"i01",schema:"radlina.v3.i01-production-binding/v1",deployable:true,
    });
    expect(()=>resolveFinalFourProvisionMode("--prepare-i01","reviewer-public.pem"))
      .toThrow(/must not silently activate AC01/u);
    expect(resolveFinalFourProvisionMode("--prepare-development").deployable).toBe(false);
  });
  it("prepares I01 in a distinct real owner-pinned output directory",()=>{
    expect(policies).toContain('"i01-only-owner-policies"');
    expect(policies).toContain('const reviewer=mode.name==="production"');
    expect(policies).toContain("V3WindowsProtectedOwnerSigner.open()");
    expect(policies).toContain("trusted(registry,\"macbook-main\")");
    expect(policies).toContain('mode.name==="i01"?{i01Only:true as const}');
  });
  it("rejects unrecognized binding and requires exact real I01 schema",()=>{
    expect(bootstrap).toContain('schema:z.literal("radlina.v3.i01-production-binding/v1")');
    expect(bootstrap).toContain("i01Only:z.literal(true)");
    expect(bootstrap).toContain("configSchema.parse(JSON.parse(raw.toString");
    expect(bootstrap).toContain("sha256(raw)!==input.configFileSha256");
    expect(factory).toContain('approvedBinding.schema!=="radlina.v3.i01-production-binding/v1"');
  });
  it("still requires real P03, true owner, recipient-local S02E and S03 witness",()=>{
    for(const symbol of [
      "I01ActualP03SessionAuthority","V3PhysicalP03Reader",
      "PinnedNativeV3OwnerBinder","I01SqliteTargetLocalConsentMailbox",
      "I01S02EConsentController","I01ConsentAndAuditDispatcher",
      "V3OwnerProtectedSigningBroker","S03ExternalAuditClient",
      "HmacDistributedAuditSigner",
    ])expect(bootstrap).toContain(symbol);
  });
  it("does not construct fleet or AC01 acceptance ledger for I01-only",()=>{
    expect(bootstrap).toContain('const full=config.schema==="radlina.v3.final-four-production-binding/v1"');
    expect(bootstrap).toContain("const fleetTransport=full?");
    expect(bootstrap).toContain("const fleetApprovals=full?");
    expect(bootstrap).toContain("const fullPorts=full?");
    expect(bootstrap).toContain("else requireI01SchemaBaseline(state)");
    expect(migrations).toContain("export function requireI01SchemaBaseline");
    expect(migrations).toContain('"acceptance.sqlite3"');
  });
  it("exposes genuine I01 tools but no F01 or AC01 tools if ports are absent",()=>{
    const partial={
      authenticatedPlugin:{} as V3FinalFourMcpPorts["authenticatedPlugin"],
      execution:{} as V3FinalFourMcpPorts["execution"],
      s02e:{} as V3FinalFourMcpPorts["s02e"],
    };
    expect(registeredV3PhysicalToolNames(partial)).toEqual(V3_I01_MCP_TOOL_NAMES);
    expect(registeredV3PhysicalToolNames({
      ...partial,
      fleet:{} as NonNullable<V3FinalFourMcpPorts["fleet"]>,
      acceptance:{} as NonNullable<V3FinalFourMcpPorts["acceptance"]>,
    })).toEqual(V3_FINAL4_MCP_TOOL_NAMES);
  });
  it("physically omits unused F01 fleet HTTP routes and OAuth scopes",()=>{
    expect(relay).toContain("if(fleet && fleetApprovals)");
    expect(gateway).toContain('acceptedScopes.delete("fleet:control")');
    expect(gateway).toContain("registeredV3PhysicalToolNames(finalFour)");
    expect(gateway).toContain("finalFour?.acceptance?.readiness()");
    expect(gateway).toContain("i01PortsBound: Boolean(finalFour)");
  });
  it("requires explicit owner invocation for a pinned I01-only service candidate",()=>{
    expect(stage).toContain("[switch]$I01Only");
    expect(stage).toContain("radlina.v3.i01-production-binding/v1");
    expect(stage).toContain("$i01Tag.Value -ne $true");
    expect(stage).toContain("Explicit I01-only owner production schema");
    expect(stage).not.toContain("Stop-Service -Name 'RadlinaRemoteMCP'");
  });
});
