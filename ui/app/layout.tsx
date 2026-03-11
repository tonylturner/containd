import type { Metadata } from "next";
import { Inter, Rajdhani, Orbitron, Share_Tech_Mono } from "next/font/google";
import "./globals.css";
import { ToastProvider } from "../components/ToastProvider";

const inter = Inter({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-inter",
});

const rajdhani = Rajdhani({
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700"],
  display: "swap",
  variable: "--font-rajdhani",
});

const orbitron = Orbitron({
  subsets: ["latin"],
  weight: ["400", "700", "900"],
  display: "swap",
  variable: "--font-orbitron",
});

const shareTechMono = Share_Tech_Mono({
  subsets: ["latin"],
  weight: "400",
  display: "swap",
  variable: "--font-share-tech-mono",
});

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
    <html lang="en" className={`antialiased ${inter.variable} ${rajdhani.variable} ${orbitron.variable} ${shareTechMono.variable}`}>
      <body>
        <ToastProvider>{children}</ToastProvider>
      </body>
    </html>
  );
}
