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
        ink: "#080a08",
        surface: "#0d110d",
        "surface-raised": "#111611",
        mint: "#22c55e",
        amber: "#f59e0b",
        danger: "#ef4444",
        cyan: "#06b6d4",
      },
      borderColor: {
        DEFAULT: "rgba(245, 158, 11, 0.15)",
      },
      boxShadow: {
        card: "0 1px 3px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(245, 158, 11, 0.08)",
        "card-lg": "0 4px 16px rgba(0, 0, 0, 0.6), 0 0 0 1px rgba(245, 158, 11, 0.1)",
        "focus-ring": "0 0 0 2px #080a08, 0 0 0 4px #f59e0b",
        "amber-glow": "0 0 12px rgba(245, 158, 11, 0.15), inset 0 0 8px rgba(245, 158, 11, 0.1)",
      },
      fontFamily: {
        display: ["'Orbitron'", "monospace"],
        ui: ["'Rajdhani'", "sans-serif"],
        mono: ["'Share Tech Mono'", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
      transitionDuration: {
        "150": "150ms",
      },
      animation: {
        "fade-in": "fadeIn 200ms ease",
        "fade-in-up": "fadeInUp 400ms ease both",
        "slide-down": "slideDown 200ms ease",
        "pulse-ring": "pulseRing 3s ease-in-out infinite",
        blink: "blink 1.5s ease-in-out infinite",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        fadeInUp: {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        slideDown: {
          "0%": { opacity: "0", transform: "translateY(-4px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        pulseRing: {
          "0%, 100%": { boxShadow: "0 0 8px rgba(245,158,11,0.15), inset 0 0 6px rgba(245,158,11,0.1)" },
          "50%": { boxShadow: "0 0 20px rgba(245,158,11,0.4), inset 0 0 12px rgba(245,158,11,0.3)" },
        },
        blink: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.2" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
