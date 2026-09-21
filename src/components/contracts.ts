import type { AuthInfo } from "@modelcontextprotocol/server";

import type { Risk } from "../policy/engine.js";

export type CapabilityExecutionContext = {
  subject: string;
  profile: string;
  auth: AuthInfo | undefined;
  isCancelled: () => boolean;
};

export type CapabilityProvider = {
  id: string;
  version: string;
  description: string;
  requiredScope: string;
  risk: Risk;
  readOnly: boolean;
  idempotent: boolean;
  execute: (context: CapabilityExecutionContext, input: unknown) => Promise<unknown>;
};

export type RadlinaComponent = {
  id: string;
  version: string;
  description: string;
  capabilities: readonly CapabilityProvider[];
};

export type CapabilityDescriptor = Omit<CapabilityProvider, "execute"> & {
  componentId: string;
};

export type ComponentDescriptor = {
  id: string;
  version: string;
  description: string;
  capabilities: string[];
};
