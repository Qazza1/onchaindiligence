/**
 * api/index.ts — Vercel serverless entrypoint.
 *
 * Vercel runs each file under /api as a serverless function. Unlike
 * src/index.ts (which starts a long-running Node listener for
 * VPS/Railway-style hosts), Vercel needs a Node request listener.
 * getRequestListener adapts the same Hono app from server.ts into one.
 *
 * Vercel injects environment variables itself, so we do NOT import
 * 'dotenv/config' here (that's only for local runs).
 */

import { getRequestListener } from '@hono/node-server'
import app from '../src/server.js'

export default getRequestListener(app.fetch)
