import { Command } from 'commander';

export const rulesCommand = new Command('rules')
  .description('Manage Opengrep security rules')
  .option('--add <url>', 'Add rules from a registry URL')
  .option('--list', 'List available rules loaded')
  .action((options) => {
    console.log('Rule management will be implemented in a future phase.');
    if (options.add) {
      console.log(`Will add ${options.add} to .securox.yml`);
    } else if (options.list) {
      console.log('Available default rules: ...');
    }
  });
