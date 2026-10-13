/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#09090B',       // Login page dark foundation
        surface: {
          DEFAULT: '#121214',        // Login page card surface
          elevated: '#18181B',       // Login page nested panels / inputs
          muted: '#18181B',          // Surface muted / subtle zinc
          border: '#27272A',         // Zinc-800 border
        },
        sidebar: {
          DEFAULT: '#09090B',
          foreground: '#FAFAFA',
          primary: '#FAFAFA',
          'primary-foreground': '#09090B',
          accent: '#27272A',
          'accent-foreground': '#FAFAFA',
          border: '#27272A',
          ring: '#52525B',
        },
        primary: {
          DEFAULT: '#FAFAFA',        // Primary Headings
          navy: '#09090B',           // Brand Primary Dark
          sapphire: '#FAFAFA',       // High contrast white / zinc accent
          'sapphire-hover': '#E4E4E7',
          indigo: '#A1A1AA',         // Supporting secondary
        },
        brand: {
          navy: '#09090B',
          sapphire: '#FAFAFA',
          'sapphire-hover': '#E4E4E7',
          indigo: '#A1A1AA',
        },
        text: {
          primary: '#FAFAFA',        // Primary headings / titles
          secondary: '#A1A1AA',      // Body text
          muted: '#71717A',          // Metadata / subtle text
        },
        threat: {
          critical: '#EF4444',       // Semantic Critical
          warning: '#F59E0B',        // Semantic High / Amber
          success: '#10B981',        // Semantic Low / Green
          medium: '#EAB308',         // Semantic Medium / Yellow
        },
        // Sentinel compatibility tokens mapped to unified dark architecture
        sentinel: {
          bg: '#09090B',
          surface: '#121214',
          elevated: '#18181B',
          subtle: '#18181B',
          border: '#27272A',
          'border-light': '#3F3F46',
          text: '#FAFAFA',
          muted: '#A1A1AA',
          dim: '#71717A',
          cyan: '#FAFAFA',
          'cyan-hover': '#E4E4E7',
          'cyan-subtle': 'rgba(255, 255, 255, 0.05)',
          purple: '#A1A1AA',
          'purple-hover': '#D4D4D8',
          'purple-subtle': 'rgba(255, 255, 255, 0.05)',
          navy: '#09090B',
          sapphire: '#FAFAFA',
        },
        severity: {
          critical: {
            bg: 'rgba(127, 29, 29, 0.35)',
            border: 'rgba(185, 28, 28, 0.6)',
            text: '#F87171',
            badge: '#EF4444',
          },
          high: {
            bg: 'rgba(120, 53, 15, 0.35)',
            border: 'rgba(180, 83, 9, 0.6)',
            text: '#FBBF24',
            badge: '#F59E0B',
          },
          medium: {
            bg: 'rgba(113, 63, 18, 0.35)',
            border: 'rgba(161, 98, 7, 0.6)',
            text: '#FDE047',
            badge: '#EAB308',
          },
          low: {
            bg: 'rgba(6, 78, 59, 0.35)',
            border: 'rgba(4, 120, 87, 0.6)',
            text: '#34D399',
            badge: '#10B981',
          },
          info: {
            bg: 'rgba(39, 39, 42, 0.6)',
            border: 'rgba(63, 63, 70, 0.8)',
            text: '#D4D4D8',
            badge: '#A1A1AA',
          },
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', 'monospace'],
      },
      screens: {
        xs: '480px',
      },
      boxShadow: {
        'card': '0 1px 3px 0 rgba(11, 18, 32, 0.04), 0 1px 2px -1px rgba(11, 18, 32, 0.04)',
        'card-hover': '0 10px 15px -3px rgba(11, 18, 32, 0.06), 0 4px 6px -4px rgba(11, 18, 32, 0.04)',
      },
    },
  },
  plugins: [],
}
