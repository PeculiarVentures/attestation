import { Command } from 'commander';

export const program = new Command()
  .name('attest')
  .description('Utility for verifying attestation data in various formats');
