import { defineConfig } from "vite";
import path from "node:path";

export default defineConfig({
  server: {
    fs: {
      allow: [
        path.resolve(__dirname),
        path.resolve(__dirname, "../../library/target/pkg-web"),
        path.resolve(__dirname, "../.."),
      ],
    },
  },
});
