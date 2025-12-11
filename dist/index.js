// SGNL Job Script - Auto-generated bundle
'use strict';

/**
 * SGNL Actions - Authentication Utilities
 *
 * Shared authentication utilities for SGNL actions.
 * Supports: Bearer Token, Basic Auth, OAuth2 Client Credentials, OAuth2 Authorization Code
 */

/**
 * Get OAuth2 access token using client credentials flow
 * @param {Object} config - OAuth2 configuration
 * @param {string} config.tokenUrl - Token endpoint URL
 * @param {string} config.clientId - Client ID
 * @param {string} config.clientSecret - Client secret
 * @param {string} [config.scope] - OAuth2 scope
 * @param {string} [config.audience] - OAuth2 audience
 * @param {string} [config.authStyle] - Auth style: 'InParams' or 'InHeader' (default)
 * @returns {Promise<string>} Access token
 */
async function getClientCredentialsToken(config) {
  const { tokenUrl, clientId, clientSecret, scope, audience, authStyle } = config;

  if (!tokenUrl || !clientId || !clientSecret) {
    throw new Error('OAuth2 Client Credentials flow requires tokenUrl, clientId, and clientSecret');
  }

  const params = new URLSearchParams();
  params.append('grant_type', 'client_credentials');

  if (scope) {
    params.append('scope', scope);
  }

  if (audience) {
    params.append('audience', audience);
  }

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'
  };

  if (authStyle === 'InParams') {
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret);
  } else {
    const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    headers['Authorization'] = `Basic ${credentials}`;
  }

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers,
    body: params.toString()
  });

  if (!response.ok) {
    let errorText;
    try {
      const errorData = await response.json();
      errorText = JSON.stringify(errorData);
    } catch {
      errorText = await response.text();
    }
    throw new Error(
      `OAuth2 token request failed: ${response.status} ${response.statusText} - ${errorText}`
    );
  }

  const data = await response.json();

  if (!data.access_token) {
    throw new Error('No access_token in OAuth2 response');
  }

  return data.access_token;
}

/**
 * Get the Authorization header value from context using available auth method.
 * Supports: Bearer Token, Basic Auth, OAuth2 Authorization Code, OAuth2 Client Credentials
 *
 * @param {Object} context - Execution context with environment and secrets
 * @param {Object} context.environment - Environment variables
 * @param {Object} context.secrets - Secret values
 * @returns {Promise<string>} Authorization header value (e.g., "Bearer xxx" or "Basic xxx")
 */
async function getAuthorizationHeader(context) {
  const env = context.environment || {};
  const secrets = context.secrets || {};

  // Method 1: Simple Bearer Token
  if (secrets.BEARER_AUTH_TOKEN) {
    const token = secrets.BEARER_AUTH_TOKEN;
    return token.startsWith('Bearer ') ? token : `Bearer ${token}`;
  }

  // Method 2: Basic Auth (username + password)
  if (secrets.BASIC_PASSWORD && secrets.BASIC_USERNAME) {
    const credentials = Buffer.from(`${secrets.BASIC_USERNAME}:${secrets.BASIC_PASSWORD}`).toString('base64');
    return `Basic ${credentials}`;
  }

  // Method 3: OAuth2 Authorization Code - use pre-existing access token
  if (secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN) {
    const token = secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN;
    return token.startsWith('Bearer ') ? token : `Bearer ${token}`;
  }

  // Method 4: OAuth2 Client Credentials - fetch new token
  if (secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET) {
    const tokenUrl = env.OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL;
    const clientId = env.OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID;
    const clientSecret = secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET;

    if (!tokenUrl || !clientId) {
      throw new Error('OAuth2 Client Credentials flow requires TOKEN_URL and CLIENT_ID in env');
    }

    const token = await getClientCredentialsToken({
      tokenUrl,
      clientId,
      clientSecret,
      scope: env.OAUTH2_CLIENT_CREDENTIALS_SCOPE,
      audience: env.OAUTH2_CLIENT_CREDENTIALS_AUDIENCE,
      authStyle: env.OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE
    });

    return `Bearer ${token}`;
  }

  throw new Error(
    'No authentication configured. Provide one of: ' +
    'BEARER_AUTH_TOKEN, BASIC_USERNAME/BASIC_PASSWORD, ' +
    'OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN, or OAUTH2_CLIENT_CREDENTIALS_*'
  );
}

/**
 * Get the base URL/address for API calls
 * @param {Object} params - Request parameters
 * @param {string} [params.address] - Address from params
 * @param {Object} context - Execution context
 * @returns {string} Base URL
 */
function getBaseURL(params, context) {
  const env = context.environment || {};
  const address = params?.address || env.ADDRESS;

  if (!address) {
    throw new Error('No URL specified. Provide address parameter or ADDRESS environment variable');
  }

  // Remove trailing slash if present
  return address.endsWith('/') ? address.slice(0, -1) : address;
}

/**
 * Create full headers object with Authorization and common headers
 * @param {Object} context - Execution context with env and secrets
 * @returns {Promise<Object>} Headers object with Authorization, Accept, Content-Type
 */
async function createAuthHeaders(context) {
  const authHeader = await getAuthorizationHeader(context);
  return {
    'Authorization': authHeader,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
  };
}

/**
 * SGNL Actions - Template Utilities
 *
 * Provides JSONPath-based template resolution for SGNL actions.
 */

/**
 * Simple path getter that traverses an object using dot/bracket notation.
 * Does not use eval or Function constructor, safe for sandbox execution.
 *
 * Supports: dot notation (a.b.c), bracket notation with numbers (items[0]) or
 * strings (items['key'] or items["key"]), nested paths (items[0].name)
 *
 * @param {Object} obj - The object to traverse
 * @param {string} path - The path string (e.g., "user.name" or "items[0].id")
 * @returns {any} The value at the path, or undefined if not found
 */
function get(obj, path) {
  if (!path || obj == null) {
    return undefined;
  }

  // Split path into segments, handling both dot and bracket notation
  // "items[0].name" -> ["items", "0", "name"]
  // "x['store']['book']" -> ["x", "store", "book"]
  const segments = path
    .replace(/\[(\d+)\]/g, '.$1')           // Convert [0] to .0
    .replace(/\['([^']+)'\]/g, '.$1')       // Convert ['key'] to .key
    .replace(/\["([^"]+)"\]/g, '.$1')       // Convert ["key"] to .key
    .split('.')
    .filter(Boolean);

  let current = obj;
  for (const segment of segments) {
    if (current == null) {
      return undefined;
    }
    current = current[segment];
  }

  return current;
}

/**
 * Regex pattern to match JSONPath templates: {$.path.to.value}
 * Matches patterns starting with {$ and ending with }
 */
const TEMPLATE_PATTERN = /\{(\$[^}]+)\}/g;

/**
 * Regex pattern to match an exact JSONPath template (entire string is a single template)
 */
const EXACT_TEMPLATE_PATTERN = /^\{(\$[^}]+)\}$/;

/**
 * Placeholder for values that cannot be resolved
 */
const NO_VALUE_PLACEHOLDER = '{No Value}';

/**
 * Formats a date to RFC3339 format (without milliseconds) to match Go's time.RFC3339.
 * @param {Date} date - The date to format
 * @returns {string} RFC3339 formatted string (e.g., "2025-12-04T17:30:00Z")
 */
function formatRFC3339(date) {
  // toISOString() returns "2025-12-04T17:30:00.123Z", we need "2025-12-04T17:30:00Z"
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Injects SGNL namespace values into the job context.
 * These are runtime values that should be fresh on each execution.
 *
 * @param {Object} jobContext - The job context object
 * @returns {Object} Job context with sgnl namespace injected
 */
function injectSGNLNamespace(jobContext) {
  const now = new Date();

  return {
    ...jobContext,
    sgnl: {
      ...jobContext?.sgnl,
      time: {
        now: formatRFC3339(now),
        ...jobContext?.sgnl?.time
      },
      random: {
        uuid: crypto.randomUUID(),
        ...jobContext?.sgnl?.random
      }
    }
  };
}

/**
 * Extracts a value from JSON using path traversal.
 *
 * Supported: dot notation (a.b.c), bracket notation (items[0]),
 * nested paths (items[0].name), deep nesting (a.b.c.d.e).
 *
 * TODO: Advanced JSONPath features not supported: wildcard [*], filters [?()],
 * recursive descent (..), slices [start:end], scripts [()].
 *
 * @param {Object} json - The JSON object to extract from
 * @param {string} jsonPath - The JSONPath expression (e.g., "$.user.email")
 * @returns {{ value: any, found: boolean }} The extracted value and whether it was found
 */
function extractJSONPathValue(json, jsonPath) {
  try {
    // Convert JSONPath to path by removing leading $. or $
    let path = jsonPath;
    if (path.startsWith('$.')) {
      path = path.slice(2);
    } else if (path.startsWith('$')) {
      path = path.slice(1);
    }

    // Handle root reference ($)
    if (!path) {
      return { value: json, found: true };
    }

    const results = get(json, path);

    // Check if value was found
    if (results === undefined || results === null) {
      return { value: null, found: false };
    }

    return { value: results, found: true };
  } catch {
    return { value: null, found: false };
  }
}

/**
 * Converts a value to string representation.
 *
 * @param {any} value - The value to convert
 * @returns {string} String representation of the value
 */
function valueToString(value) {
  if (value === null || value === undefined) {
    return '';
  }

  if (typeof value === 'string') {
    return value;
  }

  return JSON.stringify(value);
}

/**
 * Resolves a single template string by replacing all {$.path} patterns with values.
 *
 * @param {string} templateString - The string containing templates
 * @param {Object} jobContext - The job context to resolve templates from
 * @param {Object} [options] - Resolution options
 * @param {boolean} [options.omitNoValueForExactTemplates=false] - If true, exact templates that can't be resolved return empty string
 * @returns {{ result: string, errors: string[] }} The resolved string and any errors
 */
function resolveTemplateString(templateString, jobContext, options = {}) {
  const { omitNoValueForExactTemplates = false } = options;
  const errors = [];

  // Check if the entire string is a single exact template
  const isExactTemplate = EXACT_TEMPLATE_PATTERN.test(templateString);

  const result = templateString.replace(TEMPLATE_PATTERN, (_, jsonPath) => {
    const { value, found } = extractJSONPathValue(jobContext, jsonPath);

    if (!found) {
      errors.push(`failed to extract field '${jsonPath}': field not found`);

      // For exact templates with omitNoValue, return empty string
      if (isExactTemplate && omitNoValueForExactTemplates) {
        return '';
      }

      return NO_VALUE_PLACEHOLDER;
    }

    const strValue = valueToString(value);

    if (strValue === '') {
      errors.push(`failed to extract field '${jsonPath}': field is empty`);
      return '';
    }

    return strValue;
  });

  return { result, errors };
}

/**
 * Resolves JSONPath templates in the input object/string using job context.
 *
 * Template syntax: {$.path.to.value}
 * - {$.user.email} - Extracts user.email from jobContext
 * - {$.sgnl.time.now} - Current RFC3339 timestamp (injected at runtime)
 * - {$.sgnl.random.uuid} - Random UUID (injected at runtime)
 *
 * @param {Object|string} input - The input containing templates to resolve
 * @param {Object} jobContext - The job context (from context.data) to resolve templates from
 * @param {Object} [options] - Resolution options
 * @param {boolean} [options.omitNoValueForExactTemplates=false] - If true, removes keys where exact templates can't be resolved
 * @param {boolean} [options.injectSGNLNamespace=true] - If true, injects sgnl.time.now and sgnl.random.uuid
 * @returns {{ result: Object|string, errors: string[] }} The resolved input and any errors encountered
 *
 * @example
 * // Basic usage
 * const jobContext = { user: { email: 'john@example.com' } };
 * const input = { login: '{$.user.email}' };
 * const { result } = resolveJSONPathTemplates(input, jobContext);
 * // result = { login: 'john@example.com' }
 *
 * @example
 * // With runtime values
 * const { result } = resolveJSONPathTemplates(
 *   { timestamp: '{$.sgnl.time.now}', requestId: '{$.sgnl.random.uuid}' },
 *   {}
 * );
 * // result = { timestamp: '2025-12-04T10:30:00Z', requestId: '550e8400-...' }
 */
function resolveJSONPathTemplates(input, jobContext, options = {}) {
  const {
    omitNoValueForExactTemplates = false,
    injectSGNLNamespace: shouldInjectSgnl = true
  } = options;

  // Inject SGNL namespace if enabled
  const resolvedJobContext = shouldInjectSgnl ? injectSGNLNamespace(jobContext || {}) : (jobContext || {});

  const allErrors = [];

  /**
   * Recursively resolve templates in a value
   */
  function resolveValue(value) {
    if (typeof value === 'string') {
      const { result, errors } = resolveTemplateString(value, resolvedJobContext, { omitNoValueForExactTemplates });
      allErrors.push(...errors);
      return result;
    }

    if (Array.isArray(value)) {
      const resolved = value.map(item => resolveValue(item));
      if (omitNoValueForExactTemplates) {
        return resolved.filter(item => item !== '');
      }
      return resolved;
    }

    if (value !== null && typeof value === 'object') {
      const resolved = {};
      for (const [key, val] of Object.entries(value)) {
        const resolvedVal = resolveValue(val);

        // If omitNoValueForExactTemplates is enabled, skip keys with empty exact template values
        if (omitNoValueForExactTemplates && resolvedVal === '') {
          continue;
        }

        resolved[key] = resolvedVal;
      }
      return resolved;
    }

    // Return non-string primitives as-is
    return value;
  }

  const result = resolveValue(input);

  return { result, errors: allErrors };
}

/**
 * Azure AD Assign Role to User Action
 *
 * Assigns a directory role to a user in Azure Active Directory using a two-step process:
 * 1. Get user's directory object ID by user principal name
 * 2. Create role assignment schedule request for permanent role assignment
 */


/**
 * Helper function to get user by UPN and assign role
 * @param {string} userPrincipalName - User principal name
 * @param {string} roleId - Role definition ID
 * @param {string} directoryScopeId - Directory scope ID
 * @param {string} justification - Justification for assignment
 * @param {string} baseUrl - Azure AD base URL
 * @param {Object} headers - Request headers with Authorization
 * @returns {Promise<Object>} API response
 */
async function assignRoleToUser(userPrincipalName, roleId, directoryScopeId, justification, baseUrl, headers) {
  // Step 1: Get user by UPN to retrieve their directory object ID
  const encodedUPN = encodeURIComponent(userPrincipalName);
  const getUserUrl = `${baseUrl}/v1.0/users/${encodedUPN}`;

  const getUserResponse = await fetch(getUserUrl, {
    method: 'GET',
    headers
  });

  if (!getUserResponse.ok) {
    throw new Error(`Failed to get user ${userPrincipalName}: ${getUserResponse.status} ${getUserResponse.statusText}`);
  }

  const userData = await getUserResponse.json();
  const userId = userData.id;

  // Step 2: Create role assignment schedule request
  const assignRoleUrl = `${baseUrl}/v1.0/roleManagement/directory/roleAssignmentScheduleRequests`;

  const roleAssignmentRequest = {
    action: 'adminAssign',
    justification: justification,
    roleDefinitionId: roleId,
    directoryScopeId: directoryScopeId,
    principalId: userId,
    scheduleInfo: {
      startDateTime: new Date().toISOString(),
      expiration: {
        type: 'NoExpiration'
      }
    }
  };

  const assignRoleResponse = await fetch(assignRoleUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify(roleAssignmentRequest)
  });

  if (!assignRoleResponse.ok) {
    throw new Error(`Failed to assign role ${roleId} to user ${userPrincipalName}: ${assignRoleResponse.status} ${assignRoleResponse.statusText}`);
  }

  const assignmentData = await assignRoleResponse.json();

  return {
    userId,
    requestId: assignmentData.id,
    assignmentData
  };
}

var script = {
  /**
   * Main execution handler - assigns role to user
   * @param {Object} params - Job input parameters
   * @param {string} params.userPrincipalName - User principal name
   * @param {string} params.roleId - Role definition ID
   * @param {string} params.directoryScopeId - Directory scope ID (default: "/")
   * @param {string} params.justification - Justification for assignment (default: "Approved by SGNL.ai")
   * @param {Object} context - Execution context with env, secrets, outputs
   * @param {string} context.environment.ADDRESS - Azure AD API base URL
   *
   * The configured auth type will determine which of the following environment variables and secrets are available
   * @param {string} context.secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_AUDIENCE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_SCOPE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL
   *
   * @param {string} context.secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN
   *
   * @returns {Object} Assignment results
   */
  invoke: async (params, context) => {
    console.log('Starting Azure AD role assignment');

    const jobContext = context.data || {};

    // Resolve JSONPath templates in params
    const { result: resolvedParams, errors } = resolveJSONPathTemplates(params, jobContext);
    if (errors.length > 0) {
      console.warn('Template resolution errors:', errors);
    }

    // Validate required parameters
    if (!resolvedParams.userPrincipalName) {
      throw new Error('userPrincipalName is required');
    }

    if (!resolvedParams.roleId) {
      throw new Error('roleId is required');
    }

    // Extract parameters with defaults
    const {
      userPrincipalName,
      roleId,
      directoryScopeId = '/',
      justification = 'Approved by SGNL.ai'
    } = resolvedParams;

    // Get base URL and authentication headers using utilities
    const baseUrl = getBaseURL(resolvedParams, context);
    const headers = await createAuthHeaders(context);

    console.log(`Assigning role ${roleId} to user ${userPrincipalName} with scope ${directoryScopeId}`);

    try {
      const result = await assignRoleToUser(
        userPrincipalName,
        roleId,
        directoryScopeId,
        justification,
        baseUrl,
        headers
      );

      console.log(`Successfully assigned role to user. Request ID: ${result.requestId}`);

      return {
        status: 'success',
        userPrincipalName,
        roleId,
        userId: result.userId,
        requestId: result.requestId
      };
    } catch (error) {
      console.error(`Failed to assign role: ${error.message}`);
      throw error;
    }
  },

  /**
   * Error recovery handler - framework handles retries by default
   * Only implement if custom recovery logic is needed
   * @param {Object} params - Original params plus error information
   * @param {Object} context - Execution context
   * @returns {Object} Recovery results
   */
  error: async (params, _context) => {
    const { error, userPrincipalName, roleId } = params;
    console.error(`Role assignment failed for user ${userPrincipalName} with role ${roleId}: ${error.message}`);

    // Framework handles retries for transient errors (429, 502, 503, 504)
    // Just re-throw the error to let the framework handle it
    throw error;
  },

  /**
   * Graceful shutdown handler - performs cleanup
   * @param {Object} params - Original params plus halt reason
   * @param {Object} context - Execution context
   * @returns {Object} Cleanup results
   */
  halt: async (params, _context) => {
    const { reason } = params;
    console.log(`Role assignment is being halted: ${reason}`);

    return {
      status: 'halted',
      reason: reason,
      halted_at: new Date().toISOString()
    };
  }
};

module.exports = script;
