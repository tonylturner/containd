export async function generateWireGuardKeyPair() {
  const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  if (!jwk.d || !jwk.x) throw new Error("This browser cannot export X25519 keys.");
  const base64 = (value: string) => btoa(atob(value.replace(/-/g, "+").replace(/_/g, "/")));
  return { privateKey: base64(jwk.d), publicKey: base64(jwk.x) };
}
