#!/usr/bin/env node

/**
 * Development runner for testing scripts locally
 */

import yargs from 'yargs';
import script from '../src/script.mjs';
import { hideBin } from 'yargs/helpers';

const argv = yargs(hideBin(process.argv))
  .option('params', {
    type: 'string',
    describe: 'JSON string of parameters to pass to the script',
    demandOption: false
  })
  .option('secrets', {
    type: 'string',
    describe: 'JSON string of secrets to pass to the script',
    demandOption: false
  })
  .help()
  .argv;

// Parse params and secrets FIRST before building context
let params = {
  userPrincipalName: 'test@example.com',
  roleId: '12345678-1234-1234-1234-123456789abc',
  directoryScopeId: '/',
  justification: 'Approved by SGNL.ai'
};

let secrets = {
  OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET: 'test-client-secret',
  OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID: 'test-client-id',
  OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL: 'https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token',
  OAUTH2_CLIENT_CREDENTIALS_SCOPE: 'https://graph.microsoft.com/.default'
};

if (argv.params) {
  try {
    params = { ...params, ...JSON.parse(argv.params) };
  } catch (e) {
    console.error('Failed to parse --params as JSON:', e.message);
    process.exit(1);
  }
}

if (argv.secrets) {
  try {
    secrets = { ...secrets, ...JSON.parse(argv.secrets) };
  } catch (e) {
    console.error('Failed to parse --secrets as JSON:', e.message);
    process.exit(1);
  }
}

// Build context AFTER secrets and params are fully resolved
const context = {
  environment: {
    ADDRESS: params.address || 'https://graph.microsoft.com',
    OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL: secrets.OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL,
    OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID: secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID,
    OAUTH2_CLIENT_CREDENTIALS_SCOPE: secrets.OAUTH2_CLIENT_CREDENTIALS_SCOPE
  },
  secrets,
  outputs: {},
  partial_results: {},
  current_step: 'start'
};

async function runDev() {
  console.log('🚀 Running AAD Assign Role to User script in development mode...\n');
  console.log('📋 Parameters:', JSON.stringify(params, null, 2));
  console.log('🔧 Context:', JSON.stringify(context, null, 2));
  console.log('\n' + '='.repeat(50) + '\n');

  // Set environment variables for credential flow
  Object.entries(secrets).forEach(([key, value]) => { process.env[key] = value; });
  Object.entries(context.environment).forEach(([key, value]) => { process.env[key] = value; });

  try {
    const result = await script.invoke(params, context);
    console.log('\n' + '='.repeat(50));
    console.log('✅ Job completed successfully!');
    console.log('📤 Result:', JSON.stringify(result, null, 2));
  } catch (error) {
    console.log('\n' + '='.repeat(50));
    console.error('❌ Job failed:', error.message);

    if (script.error) {
      console.log('\n🔄 Attempting error recovery...');
      try {
        const recovery = await script.error({ ...params, error }, context);
        console.log('✅ Recovery successful!');
        console.log('📤 Recovery result:', JSON.stringify(recovery, null, 2));
      } catch (recoveryError) {
        console.error('❌ Recovery failed:', recoveryError.message);
      }
    }
  }
}

runDev().catch(console.error);