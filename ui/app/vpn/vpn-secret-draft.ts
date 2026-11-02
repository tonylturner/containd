import type { NormalizedVPNConfig } from "./vpn-shared";

/** A successful write clears only the secret values it submitted. Other edits,
 * including newer secret replacements, remain a draft against the saved view.
 */
export function scrubSubmittedVPNSecrets(current: NormalizedVPNConfig, submitted: NormalizedVPNConfig): NormalizedVPNConfig {
  const wireguard = { ...current.wireguard };
  if (submitted.wireguard.privateKey) {
    wireguard.privateKeyConfigured = true;
    if (wireguard.privateKey === submitted.wireguard.privateKey) wireguard.privateKey = "";
  }
  let managed = current.openvpn.managed;
  if (managed && submitted.openvpn.managed) {
    managed = { ...managed };
    for (const field of ["ca", "cert", "key", "password"] as const) {
      if (submitted.openvpn.managed[field]) {
        managed[`${field}Configured`] = true;
        if (managed[field] === submitted.openvpn.managed[field]) managed[field] = "";
      }
    }
  }
  return { ...current, wireguard, openvpn: { ...current.openvpn, managed } };
}
