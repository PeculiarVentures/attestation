#!/usr/bin/env node
// eslint-disable-next-line import/no-unassigned-import -- Reflect metadata polyfill for x509, loaded before any other module.
import "@abraham/reflection";
import { program } from "./program";

/* eslint-disable import/no-unassigned-import -- Each command module registers its subcommands on `program`. */
import "./cmd_yubico";
import "./cmd_marvell";
/* eslint-enable import/no-unassigned-import */

program.parse(process.argv);
