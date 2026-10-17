import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  base: '/static/',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/findings': 'http://localhost:8000',
      '/graph': 'http://localhost:8000',
      '/trace': 'http://localhost:8000',
      '/tools': 'http://localhost:8000',
      '/decisions': 'http://localhost:8000',
      '/approve': 'http://localhost:8000',
      '/reject': 'http://localhost:8000',
      '/eval': 'http://localhost:8000',
      '/tickets': 'http://localhost:8000',
      '/baseline': 'http://localhost:8000',
      '/triage': 'http://localhost:8000',
      '/report': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
    },
  },
  build: {
    outDir: '../static',
    emptyOutDir: false,
    sourcemap: true,
  },
});
