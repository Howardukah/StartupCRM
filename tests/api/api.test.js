import request from 'supertest';
import { app, httpServer } from '../../server.js';

describe('API Tests', () => {
  // Removed afterAll to prevent "Server is not running" error since we don't listen() during tests.

  it('GET /api/asset-buckets/all without auth should fail or return 401/403', async () => {
    const response = await request(app).get('/api/asset-buckets/all');
    // Expecting 401 Unauthorized or similar since no session cookie is sent
    expect(response.status).toBeGreaterThanOrEqual(400);
  });
});
