/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        display: ["Space Grotesk", "sans-serif"],
        mono: ["IBM Plex Mono", "monospace"]
      },
      colors: {
        panel: "#101622",
        panelSoft: "#161d2b",
        accent: "#21d4a7",
        danger: "#ff4d6d",
        glow: "#38bdf8"
      },
      boxShadow: {
        neon: "0 0 30px rgba(33, 212, 167, 0.18)",
        alert: "0 0 28px rgba(255, 77, 109, 0.28)"
      },
      keyframes: {
        pipelineFlow: {
          "0%": { transform: "translateX(-8%)", opacity: "0" },
          "10%": { opacity: "1" },
          "90%": { opacity: "1" },
          "100%": { transform: "translateX(108%)", opacity: "0" }
        },
        pulseAlert: {
          "0%, 100%": { boxShadow: "0 0 0 0 rgba(255, 77, 109, 0.55)" },
          "70%": { boxShadow: "0 0 0 16px rgba(255, 77, 109, 0)" }
        }
      },
      animation: {
        pipelineFlow: "pipelineFlow 3.5s linear infinite",
        pulseAlert: "pulseAlert 1.3s infinite"
      }
    }
  },
  plugins: []
};
