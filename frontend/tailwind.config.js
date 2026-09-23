/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        sentinel: {
          bg: '#0A0E17',         // deep dark navy/near-black background
          surface: '#111827',    // card and panel surface
          elevated: '#172236',   // hovered/elevated surface
          subtle: '#1F2E47',     // soft highlight/active state
          border: '#1E293B',     // borders
          'border-light': '#334155',
          text: '#F1F5F9',       // primary text
          muted: '#94A3B8',      // secondary text
          dim: '#64748B',        // tertiary / placeholder text
          cyan: '#06B6D4',       // primary cyber accent (sparingly)
          'cyan-hover': '#22D3EE',
          'cyan-subtle': 'rgba(6, 182, 212, 0.1)',
          purple: '#8B5CF6',     // secondary accent (sparingly)
          'purple-hover': '#A78BFA',
          'purple-subtle': 'rgba(139, 92, 246, 0.1)',
        },
        severity: {
          critical: {
            bg: '#450A0A',
            border: '#991B1B',
            text: '#FCA5A5',
            badge: '#EF4444',
          },
          high: {
            bg: '#431407',
            border: '#9A3412',
            text: '#FDBA74',
            badge: '#F97316',
          },
          medium: {
            bg: '#422006',
            border: '#854D0E',
            text: '#FDE047',
            badge: '#EAB308',
          },
          low: {
            bg: '#082F49',
            border: '#075985',
            text: '#7DD3FC',
            badge: '#38BDF8',
          },
          info: {
            bg: '#1E1B4B',
            border: '#3730A3',
            text: '#C7D2FE',
            badge: '#818CF8',
          },
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
