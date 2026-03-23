#!/usr/bin/env node
import '@abraham/reflection';
import { program } from './program';

import './cmd_yubico';
import './cmd_marvell';

program.parse(process.argv);
