#!/usr/bin/env node
// Validates an Agent Plugins 1.0.0 package against the official, vendored
// plugin.schema.json / mcp.schema.json (schemas/1.0.0 in
// https://github.com/agentplugins/agent-plugins-spec), plus the Agent Skills
// SKILL.md frontmatter rules the spec defers to. No custom plugin-format
// rules are invented here beyond what those two specs already state.
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv from 'ajv'
import { parse as parseYaml } from 'yaml'

const here = dirname(fileURLToPath(import.meta.url))
const pluginDir = process.argv[2]
if (!pluginDir) {
  console.error('usage: node validate-plugin.mjs <plugin-dir>')
  process.exit(2)
}

const errors = []
const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'))

// validateSchema: false — the official schemas set their own top-level
// "$schema" to their own $id (a plain identifying field per the spec text,
// not a meta-schema pointer), which would otherwise make Ajv try to
// self-validate the schema document as if it were a plugin.json/mcp.json
// instance.
const ajv = new Ajv({ strict: true, validateSchema: false })
const pluginSchema = readJson(join(here, '1.0.0', 'plugin.schema.json'))
const mcpSchema = readJson(join(here, '1.0.0', 'mcp.schema.json'))

// plugin.json
const pluginJsonPath = join(pluginDir, 'plugin.json')
if (!existsSync(pluginJsonPath)) {
  errors.push('plugin.json is missing at the plugin root (required by spec).')
} else {
  const plugin = readJson(pluginJsonPath)
  const validate = ajv.compile(pluginSchema)
  if (!validate(plugin)) {
    for (const e of validate.errors ?? []) errors.push(`plugin.json: ${e.instancePath || '(root)'} ${e.message}`)
  }
}

// mcp.json
const mcpJsonPath = join(pluginDir, 'mcp.json')
if (existsSync(mcpJsonPath)) {
  const mcp = readJson(mcpJsonPath)
  const validate = ajv.compile(mcpSchema)
  if (!validate(mcp)) {
    for (const e of validate.errors ?? []) errors.push(`mcp.json: ${e.instancePath || '(root)'} ${e.message}`)
  }
  for (const [id, server] of Object.entries(mcp.mcpServers ?? {})) {
    if (server.type === 'streamable-http' || server.type === 'sse') {
      let url
      try { url = new URL(server.url) } catch { errors.push(`mcp.json: mcpServers.${id}.url is not a valid URL`); continue }
      const isLoopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '::1'
      if (url.protocol !== 'https:' && !isLoopback) errors.push(`mcp.json: mcpServers.${id}.url must use https for a non-loopback host`)
      if (url.username || url.password) errors.push(`mcp.json: mcpServers.${id}.url must not contain user info`)
      if (url.hash) errors.push(`mcp.json: mcpServers.${id}.url must not contain a fragment`)
    }
  }
} else {
  errors.push('mcp.json is missing at the plugin root.')
}

// skills/*/SKILL.md — Agent Skills frontmatter: required name + description,
// name must match the containing directory.
const skillsDir = join(pluginDir, 'skills')
if (existsSync(skillsDir) && statSync(skillsDir).isDirectory()) {
  for (const entry of readdirSync(skillsDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const skillMdPath = join(skillsDir, entry.name, 'SKILL.md')
    if (!existsSync(skillMdPath) || !statSync(skillMdPath).isFile()) continue
    const raw = readFileSync(skillMdPath, 'utf8')
    const match = raw.match(/^---\n([\s\S]*?)\n---/)
    if (!match) { errors.push(`skills/${entry.name}/SKILL.md: missing YAML frontmatter`); continue }
    const front = parseYaml(match[1])
    if (!front.name) errors.push(`skills/${entry.name}/SKILL.md: frontmatter missing required 'name'`)
    else if (front.name !== entry.name) errors.push(`skills/${entry.name}/SKILL.md: frontmatter name '${front.name}' must match directory name '${entry.name}'`)
    if (!front.description) errors.push(`skills/${entry.name}/SKILL.md: frontmatter missing required 'description'`)
    else if (front.description.length > 1024) errors.push(`skills/${entry.name}/SKILL.md: description exceeds 1024 characters`)
  }
}

if (errors.length > 0) {
  console.error(`FAIL — ${errors.length} issue(s):`)
  for (const e of errors) console.error(`  - ${e}`)
  process.exit(1)
}
console.log('OK — plugin.json, mcp.json, and skills/*/SKILL.md all pass Agent Plugins 1.0.0 checks.')
