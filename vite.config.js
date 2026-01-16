import { defineConfig } from 'vite';

// This project is intentionally a single HTML file with inline JS.
// Vite is used only as a dev server and static builder.
export default defineConfig({
  server: { port: 5174 },
  esbuild: {
    // Keep the shipped single-file inscription clean.
    drop: ['console', 'debugger'],
  },
  build: {
    minify: 'esbuild',
    modulePreload: {
      polyfill: false,
    },
    // Ensure the build output stays simple.
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        manualChunks: undefined,
      },
    },
  },
});
