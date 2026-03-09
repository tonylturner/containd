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
        ink: "#0c0e14",
        surface: "#151821",
        "surface-raised": "#1a1e2a",
        mint: "#10b981",
        amber: "#f59e0b",
        danger: "#ef4444",
      },
      borderColor: {
        DEFAULT: "rgba(255, 255, 255, 0.08)",
      },
      boxShadow: {
        card: "0 1px 3px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.04)",
        "card-lg": "0 4px 16px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(255, 255, 255, 0.04)",
        "focus-ring": "0 0 0 2px #0c0e14, 0 0 0 4px #3b82f6",
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
      transitionDuration: {
        "150": "150ms",
      },
      animation: {
        "fade-in": "fadeIn 200ms ease",
        "slide-down": "slideDown 200ms ease",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        slideDown: {
          "0%": { opacity: "0", transform: "translateY(-4px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
