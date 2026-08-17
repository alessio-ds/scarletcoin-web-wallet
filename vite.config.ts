import { defineConfig } from "vite";

// A relative base works from any path, including GitHub Pages project sites
// (https://<user>.github.io/<repo>/). All asset URLs in the build are relative.
export default defineConfig({
  base: "./",
  build: {
    target: "es2022",
    sourcemap: false,
  },
});
