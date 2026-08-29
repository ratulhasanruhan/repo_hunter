import type { NextConfig } from "next";

const config: NextConfig = {
  // The scan shells out to git and holds results in memory; never bundle it for edge.
  serverExternalPackages: [],
};

export default config;
