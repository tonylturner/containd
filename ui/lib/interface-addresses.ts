import type { Interface, InterfaceState } from "./api";

export type InterfaceAddresses = {
  addrs: string[];
  source: "config" | "dhcp" | "os" | "none";
};

export const OS_ADDRESS_HINT =
  "From the OS/Docker network. containd does not manage this address.";

export function runtimeFor(
  iface: Interface,
  state: InterfaceState[],
): InterfaceState | null {
  return state.find((s) => s.name === (iface.device || iface.name)) ?? null;
}

// Display only: never use these addresses in a configuration update.
// Keep the original arrays intact for configuration and full-list tooltips.
export function interfaceAddresses(
  iface: Interface,
  state: InterfaceState[],
): InterfaceAddresses {
  const runtime = runtimeFor(iface, state);
  const configured = (iface.addresses?.length ?? 0) > 0;
  const dhcp = iface.addressMode?.toLowerCase() === "dhcp";
  const source = configured
    ? "config"
    : dhcp
      ? "dhcp"
      : runtime?.addrs?.length
        ? "os"
        : "none";
  const addrs = (configured ? iface.addresses : runtime?.addrs) ?? [];
  return {
    source,
    addrs: addrs
      .filter((addr) => !/^fe[89ab][0-9a-f]:/i.test(addr))
      .sort((a, b) => Number(a.includes(":")) - Number(b.includes(":"))),
  };
}
