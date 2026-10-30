import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The browser talks to http://localhost:5174 only. Vite forwards /api/* to the backend,
// so the session cookie is a normal same-origin cookie (no cross-site cookie tricks needed).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    strictPort: true,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8001', changeOrigin: false },
    },
  },
})
