import { defineConfig } from "vitest/config";

export default defineConfig({
  root: ".",
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{js,jsx,ts,tsx}"],
    exclude: ["**/node_modules/**", "**/dist/**", "**/.git/**"],
  },
});
