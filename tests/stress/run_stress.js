const autocannon = require('autocannon');

const PORT = process.env.PORT || 8787;
const SERVER_URL = `http://localhost:${PORT}`;

// Example token from user's logs
const TEST_TOKEN = '1fad76d046b1ed309762ef2e21ead175ef78fbd5111626f69835eb4de48a8a8c';

console.log(`Starting stress test against ${SERVER_URL}...`);
console.log('Ensure your CRM server is running (npm run dev) before running this script.');

const instance = autocannon({
  url: SERVER_URL,
  connections: 50, // Concurrent connections
  pipelining: 1,
  duration: 15, // Test for 15 seconds
  requests: [
    {
      method: 'GET',
      path: `/api/asset-bucket/validate/${TEST_TOKEN}`
    },
    {
      method: 'GET',
      path: `/api/storage/bucket/${TEST_TOKEN}/files`
    }
  ]
}, console.log);

autocannon.track(instance, { renderProgressBar: true });

instance.on('done', (result) => {
  console.log('\\nStress Test Completed!');
  console.log('----------------------------------------------------');
  console.log(`Total Requests: ${result.requests.total}`);
  console.log(`Errors: ${result.errors}`);
  console.log(`Timeouts: ${result.timeouts}`);
  console.log(`Average Latency: ${result.latency.average} ms`);
  console.log(`Requests/sec (Avg): ${result.requests.average}`);
  console.log('----------------------------------------------------');
  console.log('If the egress fix worked, you should NOT see thousands of Supabase logs on your console, even though thousands of requests were served!');
});
