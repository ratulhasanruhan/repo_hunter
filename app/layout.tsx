import type { Metadata } from "next";
import { IBM_Plex_Mono, Inter } from "next/font/google";
import "./globals.css";

// Evidence — hashes, dates, paths, masked values — is set in mono so it reads
// as machine-recorded rather than authored.
const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["300", "400", "500", "600"],
  variable: "--font-plex-mono",
  display: "swap",
});

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

export const metadata: Metadata = {
  title: "RepoHunter",
  description:
    "Find every credential ever committed to a repository's history, check which ones are still live, and see how long each has been exposed.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${plexMono.variable} ${inter.variable}`}>
      <body>{children}</body>
    </html>
  );
}
