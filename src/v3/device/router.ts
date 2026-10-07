import type { DeviceDescriptor } from "./identity.js";
import type { DeviceTarget } from "../workflow/contracts.js";

export interface DeviceRegistryReader {
  get(deviceId: string): DeviceDescriptor | undefined;
  list(): DeviceDescriptor[];
}

export interface AgentVersionMatcher {
  matches(version: string, range: string): boolean;
}

export type DeviceRoute = {
  device: DeviceDescriptor;
  selector: DeviceTarget;
  exact: boolean;
};

export class DeviceRoutingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeviceRoutingError";
  }
}

export class DeviceRouter {
  constructor(
    private readonly registry: DeviceRegistryReader,
    private readonly versions: AgentVersionMatcher = {
      matches: (version, range) => version === range,
    },
  ) {}

  route(target: DeviceTarget, capability: string): DeviceRoute {
    if (target.deviceId !== undefined) {
      const exact = this.registry.get(target.deviceId);
      if (!exact) throw new DeviceRoutingError(`exact device not found: ${target.deviceId}`);
      const reason = this.ineligibleReason(exact, target, capability);
      if (reason) {
        throw new DeviceRoutingError(
          `exact device ${target.deviceId} is not eligible and will not fail over: ${reason}`,
        );
      }
      return { device: exact, selector: target, exact: true };
    }

    const candidates = this.eligible(target, capability);
    const selected = candidates[0];
    if (!selected) throw new DeviceRoutingError("no eligible device matched the selector");
    return { device: selected, selector: target, exact: false };
  }

  reroute(
    target: DeviceTarget,
    capability: string,
    previousDeviceId: string,
    allowDynamicReroute: boolean,
  ): DeviceRoute {
    if (target.deviceId !== undefined) {
      throw new DeviceRoutingError("exact-device routing never permits failover");
    }
    if (!allowDynamicReroute) {
      throw new DeviceRoutingError("dynamic reroute is disabled by execution policy");
    }
    const selected = this.eligible(target, capability).find(
      (device) => device.deviceId !== previousDeviceId,
    );
    if (!selected) throw new DeviceRoutingError("no alternate eligible device is available");
    return { device: selected, selector: target, exact: false };
  }

  private eligible(target: DeviceTarget, capability: string): DeviceDescriptor[] {
    return this.registry
      .list()
      .filter((device) => this.ineligibleReason(device, target, capability) === undefined)
      .sort((a, b) => this.rank(a) - this.rank(b) || a.deviceId.localeCompare(b.deviceId));
  }

  private ineligibleReason(
    device: DeviceDescriptor,
    target: DeviceTarget,
    capability: string,
  ): string | undefined {
    if (device.trustState !== "trusted") return `trust=${device.trustState}`;
    if (device.status !== "online" && device.status !== "degraded")
      return `status=${device.status}`;
    if (device.health !== "healthy" && device.health !== "degraded")
      return `health=${device.health}`;
    if (!device.capabilities.includes(capability)) return `missing capability=${capability}`;
    if (target.capability !== undefined && !device.capabilities.includes(target.capability))
      return `selector capability mismatch=${target.capability}`;
    if (target.platform !== undefined && device.platform !== target.platform)
      return `platform=${device.platform}`;
    if (target.approvedTag !== undefined && !device.tags.includes(target.approvedTag))
      return `missing approved tag=${target.approvedTag}`;
    if (target.architecture !== undefined && device.architecture !== target.architecture)
      return `architecture=${device.architecture}`;
    if (
      target.agentVersionRange !== undefined &&
      !this.versions.matches(device.agentVersion, target.agentVersionRange)
    )
      return `agentVersion=${device.agentVersion}`;
    if (target.health !== undefined && device.health !== target.health)
      return `health constraint=${target.health}`;
    return undefined;
  }

  private rank(device: DeviceDescriptor): number {
    const health = device.health === "healthy" ? 0 : 10;
    const status = device.status === "online" ? 0 : 5;
    return health + status;
  }
}
