import type { DeploymentProfile } from "./api";

export function factoryResetLoginGuidance(profile?: DeploymentProfile, labMode?: boolean): string {
  if (profile === "strict") {
    return "Log in afterwards with the new one-time password printed to the container log and written to bootstrap/admin-password in the data directory (next to users.db); a password change is required at first login.";
  }
  if (profile === "training") {
    return `Log in afterwards with the default credentials.${labMode === true ? " Lab web/API tokens remain valid." : ""}`;
  }
  return "After reset, follow the sign-in instructions for this deployment.";
}
