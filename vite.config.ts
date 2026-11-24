import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  // Project site: https://charry99.github.io/payshield-check/
  base: '/payshield-check/',
  plugins: [react()],
})
