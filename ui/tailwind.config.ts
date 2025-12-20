import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx}",
    "./components/**/*.{js,ts,jsx,tsx}",
    "./pages/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        ink: "#0f172a",
        mint: "#10b981",
        amber: "#fbbf24",
      },
      backgroundImage: {
        grid: "radial-gradient(circle at 1px 1px, rgba(6,182,212,0.2) 1px, transparent 0)",
      },
    },
  },
  plugins: [],
};

export default config;
