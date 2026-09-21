import { AppError } from "../errors.js";
import type {
  CapabilityDescriptor,
  CapabilityProvider,
  ComponentDescriptor,
  RadlinaComponent,
} from "./contracts.js";

const ID_PATTERN = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/u;

export class CapabilityRegistry {
  private readonly components = new Map<string, RadlinaComponent>();
  private readonly providers = new Map<
    string,
    { componentId: string; provider: CapabilityProvider }
  >();

  register(component: RadlinaComponent): void {
    this.assertId(component.id, "component");
    if (this.components.has(component.id)) {
      throw new AppError("CONFLICT", `component ${component.id} is already registered`);
    }
    const local = new Set<string>();
    for (const capability of component.capabilities) {
      this.assertId(capability.id, "capability");
      if (local.has(capability.id) || this.providers.has(capability.id)) {
        throw new AppError("CONFLICT", `capability ${capability.id} already has a provider`);
      }
      local.add(capability.id);
    }
    this.components.set(component.id, component);
    for (const capability of component.capabilities) {
      this.providers.set(capability.id, { componentId: component.id, provider: capability });
    }
  }

  unregister(componentId: string): boolean {
    const component = this.components.get(componentId);
    if (!component) return false;
    for (const capability of component.capabilities) this.providers.delete(capability.id);
    this.components.delete(componentId);
    return true;
  }

  resolve(capabilityId: string): CapabilityProvider {
    const found = this.providers.get(capabilityId);
    if (!found) throw new AppError("NOT_FOUND", `capability ${capabilityId} is not available`);
    return found.provider;
  }

  listComponents(): ComponentDescriptor[] {
    return [...this.components.values()]
      .map((component) => ({
        id: component.id,
        version: component.version,
        description: component.description,
        capabilities: component.capabilities.map((capability) => capability.id).sort(),
      }))
      .sort((left, right) => left.id.localeCompare(right.id));
  }

  listCapabilities(): CapabilityDescriptor[] {
    return [...this.providers.entries()]
      .map(([id, entry]) => ({
        id,
        componentId: entry.componentId,
        version: entry.provider.version,
        description: entry.provider.description,
        requiredScope: entry.provider.requiredScope,
        risk: entry.provider.risk,
        readOnly: entry.provider.readOnly,
        idempotent: entry.provider.idempotent,
      }))
      .sort((left, right) => left.id.localeCompare(right.id));
  }

  private assertId(value: string, kind: string): void {
    if (!ID_PATTERN.test(value) || value.length > 100) {
      throw new AppError("INVALID_INPUT", `${kind} id is invalid`);
    }
  }
}
