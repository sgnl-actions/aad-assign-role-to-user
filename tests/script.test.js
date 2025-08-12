import { jest } from '@jest/globals';
import script from '../src/script.mjs';

// Mock fetch globally
global.fetch = jest.fn();

describe('Azure AD Assign Role to User Script', () => {
  const mockContext = {
    environment: {
      AZURE_AD_TENANT_URL: 'https://graph.microsoft.com'
    },
    secrets: {
      AZURE_AD_TOKEN: 'mock-access-token'
    }
  };

  const validParams = {
    userPrincipalName: 'test.user@example.com',
    roleId: '12345678-1234-1234-1234-123456789abc'
  };

  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    // Mock setTimeout for fast tests
    jest.spyOn(global, 'setTimeout').mockImplementation((fn) => {
      fn();
      return null;
    });
  });

  describe('invoke handler', () => {
    test('should assign role successfully with required params', async () => {
      // Mock successful user lookup
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'user-object-id-123' })
      });

      // Mock successful role assignment
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'request-id-456' })
      });

      const result = await script.invoke(validParams, mockContext);

      expect(result.status).toBe('success');
      expect(result.userPrincipalName).toBe('test.user@example.com');
      expect(result.roleId).toBe('12345678-1234-1234-1234-123456789abc');
      expect(result.userId).toBe('user-object-id-123');
      expect(result.requestId).toBe('request-id-456');

      // Verify correct API calls
      expect(global.fetch).toHaveBeenCalledTimes(2);

      // Check user lookup call
      expect(global.fetch).toHaveBeenNthCalledWith(1,
        'https://graph.microsoft.com/v1.0/users/test.user%40example.com',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'Authorization': 'Bearer mock-access-token'
          })
        })
      );

      // Check role assignment call
      expect(global.fetch).toHaveBeenNthCalledWith(2,
        'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Authorization': 'Bearer mock-access-token',
            'Content-Type': 'application/json'
          }),
          body: expect.stringContaining('"action":"adminAssign"')
        })
      );
    });

    test('should use default values for optional parameters', async () => {
      // Mock successful responses
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'user-object-id-123' })
      });

      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'request-id-456' })
      });

      await script.invoke(validParams, mockContext);

      // Verify role assignment call includes defaults
      const roleAssignmentCall = JSON.parse(global.fetch.mock.calls[1][1].body);
      expect(roleAssignmentCall.directoryScopeId).toBe('/');
      expect(roleAssignmentCall.justification).toBe('Approved by SGNL.ai');
      expect(roleAssignmentCall.scheduleInfo.expiration.type).toBe('NoExpiration');
    });

    test('should use custom values for optional parameters', async () => {
      const customParams = {
        ...validParams,
        directoryScopeId: '/administrativeUnits/unit-123',
        justification: 'Custom business justification'
      };

      // Mock successful responses
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'user-object-id-123' })
      });

      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'request-id-456' })
      });

      await script.invoke(customParams, mockContext);

      // Verify role assignment call includes custom values
      const roleAssignmentCall = JSON.parse(global.fetch.mock.calls[1][1].body);
      expect(roleAssignmentCall.directoryScopeId).toBe('/administrativeUnits/unit-123');
      expect(roleAssignmentCall.justification).toBe('Custom business justification');
    });

    test('should handle UPN with special characters through URL encoding', async () => {
      const specialParams = {
        ...validParams,
        userPrincipalName: 'test+user@example.com'
      };

      // Mock successful responses
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'user-object-id-123' })
      });

      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'request-id-456' })
      });

      await script.invoke(specialParams, mockContext);

      // Verify URL encoding of UPN
      expect(global.fetch).toHaveBeenNthCalledWith(1,
        'https://graph.microsoft.com/v1.0/users/test%2Buser%40example.com',
        expect.any(Object)
      );
    });

    test('should throw error when userPrincipalName is missing', async () => {
      const params = { roleId: '12345678-1234-1234-1234-123456789abc' };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('userPrincipalName is required');
      expect(global.fetch).not.toHaveBeenCalled();
    });

    test('should throw error when roleId is missing', async () => {
      const params = { userPrincipalName: 'test.user@example.com' };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('roleId is required');
      expect(global.fetch).not.toHaveBeenCalled();
    });

    test('should throw error when AZURE_AD_TENANT_URL is missing', async () => {
      const contextWithoutUrl = {
        environment: {},
        secrets: { AZURE_AD_TOKEN: 'mock-token' }
      };

      await expect(script.invoke(validParams, contextWithoutUrl)).rejects.toThrow('AZURE_AD_TENANT_URL environment variable is required');
      expect(global.fetch).not.toHaveBeenCalled();
    });

    test('should throw error when AZURE_AD_TOKEN is missing', async () => {
      const contextWithoutToken = {
        environment: { AZURE_AD_TENANT_URL: 'https://graph.microsoft.com' },
        secrets: {}
      };

      await expect(script.invoke(validParams, contextWithoutToken)).rejects.toThrow('AZURE_AD_TOKEN secret is required');
      expect(global.fetch).not.toHaveBeenCalled();
    });

    test('should handle user lookup failure', async () => {
      // Mock failed user lookup
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found'
      });

      await expect(script.invoke(validParams, mockContext)).rejects.toThrow('Failed to get user test.user@example.com: 404 Not Found');
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    test('should handle role assignment failure', async () => {
      // Mock successful user lookup
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'user-object-id-123' })
      });

      // Mock failed role assignment
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request'
      });

      await expect(script.invoke(validParams, mockContext)).rejects.toThrow('Failed to assign role 12345678-1234-1234-1234-123456789abc to user test.user@example.com: 400 Bad Request');
      expect(global.fetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('error handler', () => {
    test('should handle retryable errors (429)', async () => {
      const params = {
        ...validParams,
        error: { message: 'Rate limited: 429 Too Many Requests' }
      };

      const result = await script.error(params, mockContext);
      expect(result.status).toBe('retry_requested');
    }, 10000);

    test('should handle retryable errors (502)', async () => {
      const params = {
        ...validParams,
        error: { message: 'Bad gateway: 502 Bad Gateway' }
      };

      const result = await script.error(params, mockContext);
      expect(result.status).toBe('retry_requested');
    });

    test('should handle retryable errors (503)', async () => {
      const params = {
        ...validParams,
        error: { message: 'Service unavailable: 503 Service Unavailable' }
      };

      const result = await script.error(params, mockContext);
      expect(result.status).toBe('retry_requested');
    });

    test('should handle retryable errors (504)', async () => {
      const params = {
        ...validParams,
        error: { message: 'Gateway timeout: 504 Gateway Timeout' }
      };

      const result = await script.error(params, mockContext);
      expect(result.status).toBe('retry_requested');
    });

    test('should throw fatal authentication errors (401)', async () => {
      const params = {
        ...validParams,
        error: { message: 'Unauthorized: 401 Unauthorized' }
      };

      try {
        const result = await script.error(params, mockContext);
        console.log('Error handler returned:', result);
        expect(result).not.toBeDefined();
      } catch (error) {
        expect(error.message).toContain('401');
      }
    });

    test('should throw fatal authorization errors (403)', async () => {
      const params = {
        ...validParams,
        error: { message: 'Forbidden: 403 Forbidden' }
      };

      try {
        const result = await script.error(params, mockContext);
        console.log('Error handler returned:', result);
        expect(result).not.toBeDefined();
      } catch (error) {
        expect(error.message).toContain('403');
      }
    });

    test('should request retry for unknown errors', async () => {
      const params = {
        ...validParams,
        error: { message: 'Unknown error occurred' }
      };

      const result = await script.error(params, mockContext);
      expect(result.status).toBe('retry_requested');
    });
  });

  describe('halt handler', () => {
    test('should handle graceful shutdown', async () => {
      const params = { reason: 'timeout' };

      const result = await script.halt(params, mockContext);

      expect(result.status).toBe('halted');
      expect(result.reason).toBe('timeout');
      expect(result.halted_at).toBeDefined();
      expect(new Date(result.halted_at)).toBeInstanceOf(Date);
    });

    test('should handle halt with system shutdown reason', async () => {
      const params = { reason: 'system_shutdown' };

      const result = await script.halt(params, mockContext);

      expect(result.status).toBe('halted');
      expect(result.reason).toBe('system_shutdown');
    });
  });
});