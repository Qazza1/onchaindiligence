/**
 * index.ts
 * --------
 * Local/Node entrypoint. `server.ts` exports the bare Hono `app` so it
 * can also be deployed to edge runtimes (Cloudflare Workers, etc.) that
 * provide their own listener. This file is specifically for running it
 * with plain Node — `npm run dev` / `npm start` point here.
 *
 * Loads .env BEFORE importing server.ts, since config.ts reads
 * process.env at module-load time.
 */

import 'dotenv/config'
import { serve } from '@hono/node-server'

const { default: app } = await import('./server.js')

const port = Number(process.env.PORT ?? 3000)

serve({ fetch: app.fetch, port }, (info) => {
  console.log(`Compliance Diligence Suite listening on http://localhost:${info.port}`)
  console.log(`  GET /                          — service info`)
  console.log(`  GET /screen/:address            — sanctions check`)
  console.log(`  GET /company/:companyNumber     — UK company check`)
  console.log(`  GET /diligence?wallet=&company= — combined check`)
  console.log(`  GET /openapi.json               — machine-readable discovery`)
})
