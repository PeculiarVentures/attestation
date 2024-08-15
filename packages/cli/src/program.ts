import fs from 'node:fs';
import path from 'node:path';
import { Command } from 'commander';

/**
 * Get the version of the package
 * @returns The version of the package
 */
export function getVersion(): string {
  // Determine the base directory
  const baseDir = __dirname.endsWith('src')
    ? path.resolve(__dirname, '../') // Running from source when running via ts-node
    : path.resolve(__dirname, '../../'); // Running from build when running via node
  const packageJsonPath = path.join(baseDir, 'package.json');

  // Read and parse the package.json file
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
  return packageJson.version;
}

export const program = new Command()
  .name('attest')
  .description('Utility for verifying attestation data in various formats')
  .version(getVersion());
