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
        mint: "#3dd6d0",
        amber: "#f59e0b",
      },
      backgroundImage: {
        grid: "radial-gradient(circle at 1px 1px, rgba(61,214,208,0.2) 1px, transparent 0)",
      },
    },
  },
  plugins: [],
};

export default config;
