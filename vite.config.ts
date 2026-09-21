import { defineConfig } from "vitest/config";

// A relative base works from any path, including GitHub Pages project sites
// (https://<user>.github.io/<repo>/). All asset URLs in the build are relative.
export default defineConfig({
  base: "./",
  build: {
    target: "es2022",
    sourcemap: false,
  },
  test: {
    // The keystore tests run scrypt (n=65536, r=8) several times; a single
    // derivation takes seconds in CI, so the 5s default is too tight.
    testTimeout: 30_000,
  },
});
