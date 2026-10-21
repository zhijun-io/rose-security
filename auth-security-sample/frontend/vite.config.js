import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export default defineConfig(({ mode }) => {
  const projectRoot = fileURLToPath(new URL('..', import.meta.url))
  const frontendRoot = fileURLToPath(new URL('.', import.meta.url))
  const env = loadEnv(mode, projectRoot, '')
  const vitePort = Number(env.VITE_PORT ?? 5173)
  const backendPort = Number(env.SERVER_PORT ?? 8080)

  return {
    plugins: [react()],
    resolve: {
      alias: { '@': path.resolve(frontendRoot, 'src') },
    },
    server: {
      port: vitePort,
      strictPort: true,
      proxy: {
        '/api': {
          target: `http://localhost:${backendPort}`,
          changeOrigin: true,
        },
      },
    },
    build: {
      outDir: '../src/main/resources/static',
      emptyOutDir: true,
      assetsDir: 'assets',
      sourcemap: false,
    },
  }
})
