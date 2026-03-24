#!/usr/bin/env node

import { Command } from 'commander';
import { scanCommand } from './commands/scan';
import { rulesCommand } from './commands/rules';

const program = new Command();

program
  .name('securox')
  .description('Open-Source Developer Security Scanner (SAST, SCA, Secrets)')
  .version('1.0.0');

program.addCommand(scanCommand);
program.addCommand(rulesCommand);

program.parse(process.argv);