process.env.HOST = '0.0.0.0';
process.env.PORT = '4321';

import('./dist/server/entry.mjs').then(() => {
  console.log('QuantumTrust App running at http://localhost:4321');
}).catch(err => {
  console.error('Server error:', err);
});
