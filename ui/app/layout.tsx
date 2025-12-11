import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "containd",
  description: "ICS/OT-native next-generation firewall",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
