/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#F4F7FB',       // Platinum / Cool-White foundation
        surface: {
          DEFAULT: '#FFFFFF',        // Pure white surface
          elevated: '#FFFFFF',       // Elevated surface
          muted: '#EEF3F8',          // Surface muted / subtle cool gray
          border: '#D8E1EB',         // Thin cool-gray border
        },
        primary: {
          DEFAULT: '#0B1220',        // Primary Headings
          navy: '#0B1F3A',           // Brand Primary Deep Navy
          sapphire: '#1D4ED8',       // Sapphire Primary Accent
          'sapphire-hover': '#1E40AF',
          indigo: '#4F46E5',         // Supporting Indigo
        },
        brand: {
          navy: '#0B1F3A',
          sapphire: '#1D4ED8',
          'sapphire-hover': '#1E40AF',
          indigo: '#4F46E5',
        },
        text: {
          primary: '#0B1220',        // Primary headings / titles
          secondary: '#475569',      // Body text
          muted: '#64748B',          // Metadata / subtle text
        },
        threat: {
          critical: '#DC2626',       // Semantic Critical
          warning: '#D97706',        // Semantic High / Amber
          success: '#059669',        // Semantic Low / Green
          medium: '#CA8A04',         // Semantic Medium / Yellow
        },
        // Sentinel compatibility tokens mapped to unified architecture
        sentinel: {
          bg: '#F4F7FB',
          surface: '#FFFFFF',
          elevated: '#EEF3F8',
          subtle: '#EEF3F8',
          border: '#D8E1EB',
          'border-light': '#E2E8F0',
          text: '#0B1220',
          muted: '#475569',
          dim: '#64748B',
          cyan: '#1D4ED8',           // Mapped to Sapphire
          'cyan-hover': '#1E40AF',
          'cyan-subtle': 'rgba(29, 78, 216, 0.08)',
          purple: '#4F46E5',         // Mapped to Indigo
          'purple-hover': '#4338CA',
          'purple-subtle': 'rgba(79, 70, 229, 0.08)',
          navy: '#0B1F3A',
          sapphire: '#1D4ED8',
        },
        severity: {
          critical: {
            bg: '#FEF2F2',
            border: '#FECACA',
            text: '#B91C1C',
            badge: '#DC2626',
          },
          high: {
            bg: '#FFF7ED',
            border: '#FED7AA',
            text: '#C2410C',
            badge: '#D97706',
          },
          medium: {
            bg: '#FEFCE8',
            border: '#FEF08A',
            text: '#A16207',
            badge: '#CA8A04',
          },
          low: {
            bg: '#F0FDF4',
            border: '#BBF7D0',
            text: '#15803D',
            badge: '#059669',
          },
          info: {
            bg: '#F8FAFC',
            border: '#E2E8F0',
            text: '#475569',
            badge: '#64748B',
          },
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', 'monospace'],
      },
      boxShadow: {
        'card': '0 1px 3px 0 rgba(11, 18, 32, 0.04), 0 1px 2px -1px rgba(11, 18, 32, 0.04)',
        'card-hover': '0 10px 15px -3px rgba(11, 18, 32, 0.06), 0 4px 6px -4px rgba(11, 18, 32, 0.04)',
      },
    },
  },
  plugins: [],
}
