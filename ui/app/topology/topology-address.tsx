import Image from "next/image";
import { OS_ADDRESS_HINT, type InterfaceAddresses } from "../../lib/interface-addresses";
import { staticAssetURL } from "../../lib/api-core";

export function TopologyAddress({
  address,
  fullAddrs,
}: {
  address?: InterfaceAddresses;
  fullAddrs?: string[];
}) {
  return (
    <span title={fullAddrs?.join(", ")}>
      {address?.source === "os" && (
        <span title={OS_ADDRESS_HINT}>
          <Image
            src={staticAssetURL("/icons/docker.svg")}
            alt="Detected address"
            width={14}
            height={14}
            className="mr-1 inline-block"
          />
        </span>
      )}
      {address?.addrs[0] || (address?.source === "dhcp" ? "dhcp" : "—")}
    </span>
  );
}
