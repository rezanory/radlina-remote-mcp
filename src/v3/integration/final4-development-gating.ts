/**
 * Development is allowed to prepare genuine owner/P03/S03 public policies
 * before a final reviewer signing identity is available. This has NO effect
 * on tool authorization, live remote execution, Mac-local consent or the
 * independently verified production acceptance ledger.
 */
export type FinalFourProvisionMode =
  | { name: "production"; schema: "radlina.v3.final-four-production-binding/v1"; deployable: true }
  | { name: "i01"; schema: "radlina.v3.i01-production-binding/v1"; deployable: true }
  | { name: "development"; schema: "radlina.v3.final-four-development-binding/v1"; deployable: false };

export function resolveFinalFourProvisionMode(
  flag: string,
  independentReviewerPublicKeyFile?: string,
): FinalFourProvisionMode {
  if (flag === "--prepare") {
    if (!independentReviewerPublicKeyFile?.trim())
      throw new Error("production requires a genuine reviewer public-key file");
    return {
      name: "production",
      schema: "radlina.v3.final-four-production-binding/v1",
      deployable: true,
    };
  }
  if (flag === "--prepare-i01") {
    if (independentReviewerPublicKeyFile)
      throw new Error("I01-only owner binding must not silently activate AC01 reviewer policy");
    return {
      name: "i01",
      schema: "radlina.v3.i01-production-binding/v1",
      deployable: true,
    };
  }
  if (flag === "--prepare-development") {
    // Do not silently ignore or downgrade a production reviewer input.
    if (independentReviewerPublicKeyFile)
      throw new Error("development-only provisioning cannot accept production reviewer input");
    return {
      name: "development",
      schema: "radlina.v3.final-four-development-binding/v1",
      deployable: false,
    };
  }
  throw new Error("explicit --prepare, --prepare-i01 or --prepare-development operation required");
}
