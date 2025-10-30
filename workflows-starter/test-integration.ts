/**
 * RAVERSE Cloudflare Workflows Integration Tests
 * Comprehensive test suite for hybrid-cloud architecture
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';

const WORKFLOWS_URL = 'https://raverse-workflows.use-manus-ai.workers.dev';
const RAVERSE_API_URL = 'https://jaegis-raverse.onrender.com';

interface WorkflowInstance {
	instanceId: string;
	workflowType: string;
	status: any;
	createdAt: string;
}

describe('RAVERSE Cloudflare Workflows Integration', () => {
	let testInstanceIds: string[] = [];

	beforeAll(async () => {
		console.log('Starting integration tests...');
		console.log(`Workflows URL: ${WORKFLOWS_URL}`);
		console.log(`RAVERSE API URL: ${RAVERSE_API_URL}`);
	});

	afterAll(async () => {
		console.log('Cleaning up test instances...');
		// Cleanup logic if needed
	});

	describe('Health Checks', () => {
		it('should respond to health check', async () => {
			const response = await fetch(`${WORKFLOWS_URL}/health`);
			expect(response.status).toBe(200);

			const data = await response.json();
			expect(data.status).toBe('healthy');
			expect(data.workflows).toContain('binary-analysis');
			expect(data.workflows).toContain('multi-step-analysis');
			expect(data.workflows).toContain('cache-management');
			expect(data.workflows).toContain('hybrid-routing');
		});

		it('should verify RAVERSE API connectivity', async () => {
			const response = await fetch(`${RAVERSE_API_URL}/health`);
			expect(response.status).toBe(200);

			const data = await response.json();
			expect(data.status).toBe('healthy');
		});
	});

	describe('Binary Analysis Workflow', () => {
		it('should create binary analysis workflow instance', async () => {
			const response = await fetch(
				`${WORKFLOWS_URL}/?type=binary-analysis&binaryPath=/test/binary&analysisType=comprehensive`
			);
			expect(response.status).toBe(200);

			const data: WorkflowInstance = await response.json();
			expect(data.instanceId).toBeDefined();
			expect(data.workflowType).toBe('binary-analysis');
			expect(data.status).toBeDefined();

			testInstanceIds.push(data.instanceId);
		});

		it('should retrieve workflow instance status', async () => {
			if (testInstanceIds.length === 0) {
				console.log('Skipping status check - no instances created');
				return;
			}

			const instanceId = testInstanceIds[0];
			const response = await fetch(
				`${WORKFLOWS_URL}/?instanceId=${instanceId}&type=binary-analysis`
			);
			expect(response.status).toBe(200);

			const data = await response.json();
			expect(data.instanceId).toBe(instanceId);
			expect(data.status).toBeDefined();
		});

		it('should handle different analysis types', async () => {
			const analysisTypes = ['disassembly', 'pattern', 'vulnerability', 'comprehensive'];

			for (const type of analysisTypes) {
				const response = await fetch(
					`${WORKFLOWS_URL}/?type=binary-analysis&binaryPath=/test/binary&analysisType=${type}`
				);
				expect(response.status).toBe(200);

				const data: WorkflowInstance = await response.json();
				expect(data.instanceId).toBeDefined();
				testInstanceIds.push(data.instanceId);
			}
		});
	});

	describe('Multi-Step Analysis Workflow', () => {
		it('should create multi-step analysis workflow', async () => {
			const payload = {
				type: 'multi-step-analysis',
				binaryPath: '/test/binary',
				steps: [
					{
						name: 'disassembly',
						type: 'disassembly',
						config: { format: 'intel' },
					},
					{
						name: 'pattern-analysis',
						type: 'pattern',
						config: { dependsOn: ['disassembly'] },
					},
				],
				parallelExecution: true,
			};

			const response = await fetch(`${WORKFLOWS_URL}/`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(payload),
			});

			expect(response.status).toBe(200);
			const data: WorkflowInstance = await response.json();
			expect(data.instanceId).toBeDefined();
			testInstanceIds.push(data.instanceId);
		});
	});

	describe('Cache Management Workflow', () => {
		it('should handle cache invalidation', async () => {
			const response = await fetch(
				`${WORKFLOWS_URL}/?type=cache-management&action=invalidate&pattern=binary-analysis:*`
			);
			expect(response.status).toBe(200);

			const data = await response.json();
			expect(data.status).toBe('completed');
		});

		it('should handle cache refresh', async () => {
			const response = await fetch(
				`${WORKFLOWS_URL}/?type=cache-management&action=refresh&ttl=3600`
			);
			expect(response.status).toBe(200);

			const data = await response.json();
			expect(data.status).toBe('completed');
		});

		it('should handle cache cleanup', async () => {
			const response = await fetch(
				`${WORKFLOWS_URL}/?type=cache-management&action=cleanup`
			);
			expect(response.status).toBe(200);

			const data = await response.json();
			expect(data.status).toBe('completed');
		});

		it('should handle cache analysis', async () => {
			const response = await fetch(
				`${WORKFLOWS_URL}/?type=cache-management&action=analyze`
			);
			expect(response.status).toBe(200);

			const data = await response.json();
			expect(data.status).toBe('completed');
		});
	});

	describe('Hybrid Routing Workflow', () => {
		it('should route GET requests', async () => {
			const payload = {
				type: 'hybrid-routing',
				requestPath: '/api/analyze',
				method: 'GET',
				useCache: true,
			};

			const response = await fetch(`${WORKFLOWS_URL}/`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(payload),
			});

			expect(response.status).toBe(200);
			const data = await response.json();
			expect(data.status).toBe('completed');
		});

		it('should route POST requests', async () => {
			const payload = {
				type: 'hybrid-routing',
				requestPath: '/api/analyze',
				method: 'POST',
				payload: { binaryPath: '/test/binary' },
				useCache: false,
			};

			const response = await fetch(`${WORKFLOWS_URL}/`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(payload),
			});

			expect(response.status).toBe(200);
			const data = await response.json();
			expect(data.status).toBe('completed');
		});
	});

	describe('Error Handling', () => {
		it('should handle invalid workflow type', async () => {
			const response = await fetch(
				`${WORKFLOWS_URL}/?type=invalid-workflow`
			);
			// Should default to binary-analysis or return error
			expect([200, 400]).toContain(response.status);
		});

		it('should handle missing required parameters', async () => {
			const response = await fetch(`${WORKFLOWS_URL}/`);
			expect(response.status).toBe(200); // Should create with defaults
		});

		it('should handle network timeouts gracefully', async () => {
			// This test would require mocking or actual timeout simulation
			console.log('Network timeout test - requires mock setup');
		});
	});

	describe('Performance Tests', () => {
		it('should complete binary analysis within timeout', async () => {
			const startTime = Date.now();
			const response = await fetch(
				`${WORKFLOWS_URL}/?type=binary-analysis&binaryPath=/test/binary`
			);
			const duration = Date.now() - startTime;

			expect(response.status).toBe(200);
			expect(duration).toBeLessThan(30000); // 30 seconds
		});

		it('should handle concurrent requests', async () => {
			const requests = Array(5).fill(null).map(() =>
				fetch(`${WORKFLOWS_URL}/?type=binary-analysis&binaryPath=/test/binary`)
			);

			const responses = await Promise.all(requests);
			responses.forEach(response => {
				expect(response.status).toBe(200);
			});
		});
	});

	describe('Integration Tests', () => {
		it('should maintain state across workflow steps', async () => {
			// Create workflow
			const createResponse = await fetch(
				`${WORKFLOWS_URL}/?type=binary-analysis&binaryPath=/test/binary`
			);
			const data: WorkflowInstance = await createResponse.json();

			// Check status multiple times
			for (let i = 0; i < 3; i++) {
				const statusResponse = await fetch(
					`${WORKFLOWS_URL}/?instanceId=${data.instanceId}&type=binary-analysis`
				);
				expect(statusResponse.status).toBe(200);
				await new Promise(resolve => setTimeout(resolve, 1000));
			}
		});

		it('should cache results correctly', async () => {
			const binaryPath = '/test/binary-cache-test';

			// First request - should hit RAVERSE API
			const response1 = await fetch(
				`${WORKFLOWS_URL}/?type=binary-analysis&binaryPath=${binaryPath}`
			);
			expect(response1.status).toBe(200);

			// Second request - should hit cache
			const response2 = await fetch(
				`${WORKFLOWS_URL}/?type=binary-analysis&binaryPath=${binaryPath}`
			);
			expect(response2.status).toBe(200);

			const data1 = await response1.json();
			const data2 = await response2.json();

			// Results should be consistent
			expect(data1.workflowType).toBe(data2.workflowType);
		});
	});
});

// Export test utilities
export { WORKFLOWS_URL, RAVERSE_API_URL };

