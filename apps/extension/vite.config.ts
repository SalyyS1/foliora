import { defineConfig } from 'vite';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  build: {
    outDir: 'dist/shared',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: fileURLToPath(new URL('./popup.html', import.meta.url)),
        background: fileURLToPath(new URL('./src/background.ts', import.meta.url)),
        content: fileURLToPath(new URL('./src/content.ts', import.meta.url)),
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
});
