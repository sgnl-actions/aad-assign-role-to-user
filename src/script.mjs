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
 * @param {string} tenantUrl - Azure AD tenant URL
 * @param {string} authToken - Azure AD access token
 * @returns {Promise<Object>} API response
 */
async function assignRoleToUser(userPrincipalName, roleId, directoryScopeId, justification, tenantUrl, authToken) {
  // Step 1: Get user by UPN to retrieve their directory object ID
  const encodedUPN = encodeURIComponent(userPrincipalName);
  const getUserUrl = new URL(`/v1.0/users/${encodedUPN}`, tenantUrl);

  const getUserResponse = await fetch(getUserUrl.toString(), {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${authToken}`,
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    }
  });

  if (!getUserResponse.ok) {
    throw new Error(`Failed to get user ${userPrincipalName}: ${getUserResponse.status} ${getUserResponse.statusText}`);
  }

  const userData = await getUserResponse.json();
  const userId = userData.id;

  // Step 2: Create role assignment schedule request
  const assignRoleUrl = new URL('/v1.0/roleManagement/directory/roleAssignmentScheduleRequests', tenantUrl);

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

  const assignRoleResponse = await fetch(assignRoleUrl.toString(), {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${authToken}`,
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
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

export default {
  /**
   * Main execution handler - assigns role to user
   * @param {Object} params - Job input parameters
   * @param {string} params.userPrincipalName - User principal name
   * @param {string} params.roleId - Role definition ID
   * @param {string} params.directoryScopeId - Directory scope ID (default: "/")
   * @param {string} params.justification - Justification for assignment (default: "Approved by SGNL.ai")
   * @param {Object} context - Execution context with env, secrets, outputs
   * @param {string} context.secrets.BEARER_AUTH_TOKEN - Bearer token for Azure AD API authentication
   * @returns {Object} Assignment results
   */
  invoke: async (params, context) => {
    console.log('Starting Azure AD role assignment');

    // Validate required parameters
    if (!params.userPrincipalName) {
      throw new Error('userPrincipalName is required');
    }

    if (!params.roleId) {
      throw new Error('roleId is required');
    }

    // Extract parameters with defaults
    const {
      userPrincipalName,
      roleId,
      directoryScopeId = '/',
      justification = 'Approved by SGNL.ai'
    } = params;

    // Validate required environment and secrets
    if (!context.environment.AZURE_AD_TENANT_URL) {
      throw new Error('AZURE_AD_TENANT_URL environment variable is required');
    }

    if (!context.secrets.BEARER_AUTH_TOKEN) {
      throw new Error('BEARER_AUTH_TOKEN secret is required');
    }

    const tenantUrl = context.environment.AZURE_AD_TENANT_URL;
    const authToken = context.secrets.BEARER_AUTH_TOKEN;

    console.log(`Assigning role ${roleId} to user ${userPrincipalName} with scope ${directoryScopeId}`);

    try {
      const result = await assignRoleToUser(
        userPrincipalName,
        roleId,
        directoryScopeId,
        justification,
        tenantUrl,
        authToken
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
   * Error recovery handler - handles retryable errors
   * @param {Object} params - Original params plus error information
   * @param {Object} context - Execution context
   * @returns {Object} Recovery results
   */
  error: async (params, _context) => {
    const { error } = params;
    console.error(`Role assignment encountered error: ${error.message}`);

    // Check if error is retryable
    if (error.message.includes('429') || // Rate limited
        error.message.includes('502') || // Bad gateway
        error.message.includes('503') || // Service unavailable
        error.message.includes('504')) { // Gateway timeout
      console.log('Detected retryable error, waiting before retry...');
      await new Promise(resolve => setTimeout(resolve, 5000));
      return { status: 'retry_requested' };
    }

    // Mark authentication/authorization errors as fatal
    if (error.message.includes('401') || error.message.includes('403')) {
      console.error('Authentication/authorization error - not retrying');
      throw error;
    }

    // Default: let framework handle retry
    return { status: 'retry_requested' };
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