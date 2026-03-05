/**
 * Azure AD Assign Role to User Action
 *
 * Assigns a directory role to a user in Azure Active Directory using a two-step process:
 * 1. Get user's directory object ID by user principal name
 * 2. Create role assignment schedule request for permanent role assignment
 */

import { getBaseURL, createHeaders } from '@sgnl-actions/utils';

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

  // Step 2: Check if role assignment already exists (for idempotency)
  const baseURL = `${baseUrl}/v1.0/roleManagement/directory/roleAssignments`;
  const url = new URL(baseURL);
  url.searchParams.set('$filter', `principalId eq '${userId}' and roleDefinitionId eq '${roleId}' and directoryScopeId eq '${directoryScopeId}'`);
  const checkAssignmentUrl = url.toString();

  const checkResponse = await fetch(checkAssignmentUrl, {
    method: 'GET',
    headers
  });

  if (!checkResponse.ok) {
    throw new Error(`Failed to check existing role assignments for user ${userPrincipalName}: ${checkResponse.status} ${checkResponse.statusText}`);
  }

  const existingAssignments = await checkResponse.json();

  // If assignment already exists, return success without creating duplicate
  if (existingAssignments.value && existingAssignments.value.length > 0) {
    return {
      userId,
      requestId: null,
      assignmentData: null,
      alreadyAssigned: true,
      existingAssignmentId: existingAssignments.value[0].id
    };
  }

  // Step 3: Create role assignment schedule request (only if it doesn't exist)
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
    assignmentData,
    alreadyAssigned: false
  };
}

export default {
  /**
   * Main execution handler - assigns role to user
   * @param {Object} params - Job input parameters
   * @param {string} params.userPrincipalName - User principal name
   * @param {string} params.roleId - Role definition ID
   * @param {string} params.directoryScopeId - Directory scope ID (default: "/")
   * @param {string} params.justification - Justification for assignment (default: "Approved by SGNL.ai")
   * @param {string} params.address - The Azure AD API base URL (e.g., https://graph.microsoft.com)
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

    // Extract parameters with defaults
    const {
      userPrincipalName,
      roleId,
      directoryScopeId = '/',
      justification = 'Approved by SGNL.ai'
    } = params;

    // Get base URL and authentication headers using utilities
    const baseUrl = getBaseURL(params, context);
    const headers = await createHeaders(context);

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

      if (result.alreadyAssigned) {
        console.log(`Role assignment already exists for user. Existing assignment ID: ${result.existingAssignmentId}`);
        return {
          status: 'success',
          userPrincipalName,
          roleId,
          userId: result.userId,
          requestId: result.existingAssignmentId,
          address: baseUrl
        };
      } else {
        console.log(`Successfully assigned role to user. Request ID: ${result.requestId}`);
        return {
          status: 'success',
          userPrincipalName,
          roleId,
          userId: result.userId,
          requestId: result.requestId,
          address: baseUrl
        };
      }
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
