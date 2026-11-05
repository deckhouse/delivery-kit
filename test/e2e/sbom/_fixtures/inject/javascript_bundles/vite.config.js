import { defineConfig } from "vite";

export default defineConfig({
  build: {
    minify: false,
    modulePreload: false,
    rollupOptions: {
      input: { main: "src/main.js" },
      output: {
        entryFileNames: "[name].js",
        chunkFileNames: "[name].js",
      },
    },
  },
});
