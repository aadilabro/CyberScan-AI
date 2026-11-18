import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./app/**/*.{js,ts,jsx,tsx,mdx}', './components/**/*.{js,ts,jsx,tsx,mdx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#f0fdf4',
          100: '#dcfce7',
          500: '#22c55e',
          600: '#16a34a',
          900: '#052e16',
        },
        slate: {
          950: '#020817',
        },
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(34,197,94,0.35), 0 10px 30px rgba(15,23,42,0.45)',
      },
    },
  },
  plugins: [],
};

export default config;
