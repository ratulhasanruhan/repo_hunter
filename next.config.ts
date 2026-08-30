import type { NextConfig } from "next";

const config: NextConfig = {
  // The scan shells out to git and holds results in memory; never bundle it for edge.
  serverExternalPackages: [],
  // Standalone output is what the Dockerfile copies. Gated on an env var so the
  // default build is untouched for hosts that do their own packaging.
  ...(process.env.DOCKER_BUILD ? { output: "standalone" as const } : {}),
};

export default config;
