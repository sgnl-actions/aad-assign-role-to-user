# Azure AD Assign Role to User

Assigns a directory role to a user in Azure Active Directory using the Microsoft Graph API. This action uses a two-step process to permanently assign roles to users through the role assignment schedule API.

## Overview

This action performs the following steps:

1. **User Lookup**: Retrieves the user's directory object ID by their User Principal Name (UPN)
2. **Role Assignment**: Creates a permanent role assignment schedule request using the Microsoft Graph API

The action uses Azure AD's Privileged Identity Management (PIM) role assignment schedule API to create permanent role assignments with proper audit trails and compliance tracking.

## Prerequisites

- Azure AD tenant with appropriate permissions
- Application registration or service principal with required permissions
- Valid access token with Directory.ReadWrite.All permissions

### Required Permissions

The Azure AD application or service principal must have:
- `Directory.ReadWrite.All` - Required to read user information and create role assignments
- `RoleManagement.ReadWrite.Directory` - Required to manage directory role assignments

## Configuration

### Authentication

This action supports two OAuth2 authentication methods:

#### OAuth2 Authorization Code Flow

**Required Secrets:**
- **`OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN`**: OAuth2 access token

**Required Environment Variables:**
- **`OAUTH2_AUTHORIZATION_CODE_CLIENT_ID`**: OAuth2 client ID
- **`OAUTH2_AUTHORIZATION_CODE_TOKEN_URL`**: Token endpoint URL

**Optional Environment Variables:**
- **`OAUTH2_AUTHORIZATION_CODE_AUTH_STYLE`**: Authentication style (`InHeader`, `InParams`, or `AutoDetect`)
- **`OAUTH2_AUTHORIZATION_CODE_AUTH_URL`**: Authorization endpoint URL
- **`OAUTH2_AUTHORIZATION_CODE_SCOPE`**: OAuth2 scope
- **`OAUTH2_AUTHORIZATION_CODE_REDIRECT_URI`**: OAuth2 redirect URI

#### OAuth2 Client Credentials Flow

**Required Secrets:**
- **`OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET`**: OAuth2 client secret

**Required Environment Variables:**
- **`OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL`**: Token endpoint URL
- **`OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID`**: OAuth2 client ID

**Optional Environment Variables:**
- **`OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE`**: Authentication style (`InHeader`, `InParams`, or `AutoDetect`)
- **`OAUTH2_CLIENT_CREDENTIALS_SCOPE`**: OAuth2 scope
- **`OAUTH2_CLIENT_CREDENTIALS_AUDIENCE`**: OAuth2 audience

### Required Environment Variables

- **`ADDRESS`**: Azure AD API base URL (e.g., `https://graph.microsoft.com`)

### Input Parameters

| Name | Type | Description | Required | Default |
|------|------|-------------|----------|---------|
| `userPrincipalName` | string | User Principal Name (UPN) of the user to assign the role to | Yes | None |
| `roleId` | string | Directory role definition ID to assign | Yes | None |
| `directoryScopeId` | string | Directory scope ID for the role assignment | No | "/" |
| `justification` | string | Justification for the role assignment | No | "Approved by SGNL.ai" |

### Output Values

| Name | Type | Description |
|------|------|-------------|
| `status` | string | Operation result (success, failed, recovered, etc.) |
| `userPrincipalName` | string | User Principal Name that was processed |
| `roleId` | string | Role ID that was assigned |
| `userId` | string | User's directory object ID |
| `requestId` | string | Role assignment request ID |

## Usage Examples

### Basic Role Assignment

```json
{
  "userPrincipalName": "john.doe@example.com",
  "roleId": "729827e3-9c14-49f7-bb1b-9608f156bbb8"
}
```

### Role Assignment with Custom Scope

```json
{
  "userPrincipalName": "admin@example.com",
  "roleId": "62e90394-69f5-4237-9190-012177145e10",
  "directoryScopeId": "/administrativeUnits/12345678-1234-1234-1234-123456789abc",
  "justification": "Temporary administrative access for project deployment"
}
```

### Common Directory Role IDs

| Role Name | Role ID |
|-----------|---------|
| Global Administrator | 62e90394-69f5-4237-9190-012177145e10 |
| User Administrator | fe930be7-5e62-47db-91af-98c3a49a38b1 |
| Application Administrator | 9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3 |
| Directory Readers | 88d8e3e3-8f55-4a1e-953a-9b9898b8876b |
| Directory Writers | 9360feb5-f418-4baa-8175-e2a00bac4301 |

Note: Role IDs may vary between Azure AD tenants. Use the Microsoft Graph API or Azure Portal to find the correct role IDs for your tenant.

## Error Handling

The action implements comprehensive error handling with automatic retry logic:

### Retryable Errors (Automatic Retry)
- `429` - Rate limited (will wait 5 seconds before retry)
- `502` - Bad gateway
- `503` - Service unavailable  
- `504` - Gateway timeout

### Fatal Errors (No Retry)
- `401` - Unauthorized (invalid or expired token)
- `403` - Forbidden (insufficient permissions)
- `400` - Bad request (invalid parameters)
- `404` - Not found (user or role doesn't exist)

### Error Recovery

The action includes an error handler that:
1. Identifies retryable vs. fatal errors
2. Implements exponential backoff for rate limits
3. Provides clear error messages for troubleshooting

## Development

### Local Testing

```bash
# Install dependencies
npm install

# Run tests
npm test

# Check test coverage (80% minimum required)
npm run test:coverage

# Run locally with test parameters
npm run dev -- --params '{"userPrincipalName": "test@example.com", "roleId": "12345678-1234-1234-1234-123456789abc"}'

# Lint code
npm run lint

# Build distribution
npm run build
```

### Testing with Real Azure AD

For integration testing with a real Azure AD tenant:

1. Create an application registration in Azure AD
2. Grant necessary permissions and admin consent
3. Generate an access token
4. Set environment variables and run tests

```bash
export ADDRESS="https://graph.microsoft.com"
export OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN="your-access-token"
npm run dev
```

## Security Considerations

- **Token Security**: Never log or expose access tokens in plaintext
- **Principle of Least Privilege**: Only grant necessary permissions to the service principal
- **Audit Logging**: All role assignments are logged in Azure AD audit logs
- **Token Expiration**: Monitor token expiration and implement refresh logic
- **Input Validation**: All user inputs are validated and URL-encoded to prevent injection attacks

## API Reference

### Microsoft Graph Endpoints Used

1. **Get User by UPN**
   - `GET /v1.0/users/{userPrincipalName}`
   - Returns user's directory object ID

2. **Create Role Assignment Schedule Request**
   - `POST /v1.0/roleManagement/directory/roleAssignmentScheduleRequests`
   - Creates permanent role assignment

### Request Structure

The role assignment request body follows this structure:

```json
{
  "action": "adminAssign",
  "justification": "Approved by SGNL.ai",
  "roleDefinitionId": "role-id",
  "directoryScopeId": "/",
  "principalId": "user-object-id",
  "scheduleInfo": {
    "startDateTime": "2024-01-15T10:30:00.000Z",
    "expiration": {
      "type": "NoExpiration"
    }
  }
}
```

## Troubleshooting

### Common Issues

1. **401 Unauthorized**
   - Check if access token is valid and not expired
   - Verify token has required permissions

2. **403 Forbidden**  
   - Ensure service principal has Directory.ReadWrite.All permissions
   - Verify admin consent has been granted

3. **404 User Not Found**
   - Check if User Principal Name is correct and exists
   - Verify user is not deleted or in recycle bin

4. **400 Bad Request - Role Assignment**
   - Verify role ID exists in the tenant
   - Check if user already has the role assigned
   - Ensure directory scope ID is valid

### Debug Tips

- Enable verbose logging to see detailed API requests/responses
- Check Azure AD audit logs for role assignment activity
- Use Graph Explorer to test API calls manually
- Verify permissions using the Microsoft Graph API

## Compliance and Audit

- All role assignments are logged in Azure AD audit logs
- Assignment requests include justification for compliance tracking
- Permanent assignments follow your organization's access review policies
- Role assignments can be tracked and managed through Azure AD PIM

## Support

- [Microsoft Graph API Documentation](https://docs.microsoft.com/en-us/graph/)
- [Azure AD Role Management](https://docs.microsoft.com/en-us/graph/api/resources/unifiedroleassignment)
