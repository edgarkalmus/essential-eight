module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: "#1e40af",
        secondary: "#3b82f6",
        accent: "#4f46e5",
        'maturity-0': "#ef4444",
        'maturity-1': "#f97316",
        'maturity-2': "#3b82f6",
        'maturity-3': "#10b981",
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      }
    },
  },
  plugins: [],
}