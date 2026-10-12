/**
 * Final-four V3 physical gateway dependency contracts.
 *
 * There is exactly ONE executable physical composition:
 *   src/v3/integration/final4-physical-bootstrap.ts
 * created by:
 *   src/v3/control-plane/v3-environment-factory.ts
 * and injected exclusively through the independent V3 OAuth gateway.
 *
 * This module deliberately exports types ONLY. The former experimental
 * composePhysicalV3FinalFour implementation had no call sites and conflicted
 * with the canonical bootstrap's S03 wire protocol / registry ownership.
 * Its original source remains preserved in Git history (14f429f).
 *
 * This refactoring neither loads physical ports nor changes V2.
 */
import type { AppConfig } from "../../config/schema.js";
import type { Store } from "../../persistence/store.js";
import type { AuthService } from "../../auth/service.js";
import type { SqliteDeviceRegistry } from "../device/registry.js";
import type { V3FinalFourMcpPorts } from "./final4-mcp-surface.js";
import type { I01PhysicalRelayPorts } from "../integration/i01-agent-relay-http.js";

export type V3FinalFourFactoryContext = {
  registry: SqliteDeviceRegistry;
  store: Store;
  config: AppConfig;
  auth: AuthService;
  stateRoot: string;
};

export type V3ComposedPhysicalFinalFour = {
  finalFour: V3FinalFourMcpPorts;
  physicalRelay: I01PhysicalRelayPorts;
  close(): Promise<void>;
};
