import { fileURLToPath, URL } from 'node:url'
import UnoCSS from 'unocss/vite'
import Inspect from 'vite-plugin-inspect'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    vue(),
    UnoCSS(),
    Inspect()
  ],
  base: '/',
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  }
})
