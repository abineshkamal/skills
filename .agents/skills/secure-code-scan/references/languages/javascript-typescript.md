# JavaScript / TypeScript (Node, Express, Next.js, NestJS, Koa, Fastify, React, Vue, Angular, Svelte, Electron)

## Sources
- Express/Koa/Fastify: `req.query`, `req.body`, `req.params`, `req.cookies`, `req.headers`, `req.get()`, `req.files`, `req.hostname`, `req.originalUrl`, `ctx.request.body`, `ctx.query`, `ctx.params`, `request.query` (Fastify)
- Next.js: `searchParams`/`params` props, `request.nextUrl.searchParams`, `await request.json()`, `request.formData()`, `cookies()`, `headers()`, Server Action arguments (**every exported `'use server'` function is a public endpoint**), `getServerSideProps({ query })`, API route `req.query`/`req.body`
- NestJS: `@Body() @Query() @Param() @Headers() @Req()`
- GraphQL resolver `args`; WebSocket `socket.on('msg', data)`; queue consumers (`message.content`)
- Browser: `location.*`, `document.URL/referrer/cookie`, `window.name`, `postMessage` `event.data`, `localStorage`, `URLSearchParams`, router params (`useParams`, `useSearchParams`, `$route.query`, `ActivatedRoute`)
- `process.argv`, uploaded file `originalname`/`mimetype` (both attacker-controlled)

## Sinks
| Class | Sinks |
|---|---|
| SQL | `db.query/execute/raw` with template literals or `+`; `sequelize.query`, `sequelize.literal`; `knex.raw`, `whereRaw`, `orderByRaw`; Prisma `$queryRawUnsafe`/`$executeRawUnsafe` and `Prisma.raw()`; TypeORM `query()`, `createQueryBuilder().where(\`...${x}\`)`; `mysql2` `query` with concat; better-sqlite3 `prepare(\`...${x}\`)` |
| NoSQL | Mongoose/Mongo `find(req.body)`, `findOne({user: req.body.user})` (object injection), `$where`, `mapReduce`, `aggregate` with user stages |
| Command | `child_process.exec/execSync`, `spawn(..., {shell:true})`, `execa` with `shell:true`, `shelljs.exec` |
| Code | `eval`, `new Function`, `setTimeout(string)`, `vm.runIn*` (not a sandbox), `vm2` (deprecated, escapable), `require(userPath)`, dynamic `import(user)` |
| XSS | `innerHTML/outerHTML`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `[innerHTML]` + `bypassSecurityTrust*`, jQuery `.html()/.append()/$(userHtml)`, `href={user}` / `src={user}` (javascript: URLs), `res.send(\`<p>${x}\`)`, SSR `<script>window.__DATA__ = ${JSON.stringify(x)}</script>` without escaping `<` |
| Path | `fs.*(userPath)`, `res.sendFile`, `res.download`, `express.static` with user root, `path.join(base, user)` without a prefix check, archive extraction (`adm-zip`, `unzipper`, `tar`) |
| SSRF | `fetch`, `axios`, `got`, `node-fetch`, `http.request`, `needle`, `superagent` with user URL; headless browser `page.goto(user)` (Puppeteer/Playwright); image/PDF libs fetching URLs |
| Redirect | `res.redirect(user)`, `NextResponse.redirect(user)`, `redirect(user)` (next/navigation), `window.location = user` |
| SSTI | `ejs.render(userTemplate)`, `pug.compile(user)`, `Handlebars.compile(user)`, `_.template(user)`, `nunjucks.renderString(user)`; `res.render(req.query.view)` (template path); EJS `res.render('x', req.query)` (options pollution: outputFunctionName/escapeFunction) |
| Deserialization | `node-serialize.unserialize`, `serialize-javascript` round-trip with eval, `js-yaml.load` in v<4 (v4 `load` is safe), `funcster`, `cryo` |
| Prototype pollution | `_.merge/defaultsDeep/set/zipObjectDeep` with user objects, hand-written deep merge, `obj[k1][k2] = v` with user keys, `qs` with deep nesting (old versions) |
| ReDoS | `new RegExp(user)`; nested-quantifier regex applied to input |
| JWT | `jwt.decode` used for auth, `jwt.verify` without `algorithms`, `jsonwebtoken` < 9 with `none`, hard-coded secrets |
| Electron | `nodeIntegration:true`, `contextIsolation:false`, `webSecurity:false`, `shell.openExternal(user)`, exposing `ipcRenderer` wholesale via `contextBridge` |

## Sanitizers / safe APIs
- SQL: placeholders `?`/`$1` with a values array; knex/Sequelize builders with values; Prisma tagged `` $queryRaw`... ${x}` `` (parameterized; still check `Prisma.raw`); identifiers via allow-list.
- Mongo: `mongo-sanitize`/`express-mongo-sanitize`, explicit casts `String(x)`, schema validation (zod/joi/class-validator with `whitelist:true, forbidNonWhitelisted:true`).
- Command: `execFile`/`spawn` with an args array and no shell + allow-list.
- HTML: React/Vue/Angular/Svelte interpolation (auto-escaped), `textContent`, `DOMPurify.sanitize`, `sanitize-html`, `escape-html`; URL scheme check for `href`.
- Path: `path.resolve(base, p)` then `.startsWith(base + path.sep)`; `path.basename`.
- SSRF: `ssrf-req-filter`, `request-filtering-agent`, allow-list + DNS check.
- Proto pollution: `Object.create(null)`, `Map`, key filtering, `Object.freeze(Object.prototype)`.
- Validation libs (zod, joi, yup, class-validator, ajv) **are** sanitizers when the schema restricts the type or format for that sink, e.g. `z.number()` or `z.enum([...])`. Plain `z.string()` is not.

## Framework notes
- Express has no CSRF protection by default; `csurf` is deprecated. Look for `csrf-csrf`/`lusca` or SameSite cookies + token.
- Express: `helmet()` missing → missing-headers finding (Low, once). `app.disable('x-powered-by')`.
- `express-session` default `secret: 'keyboard cat'` and missing `cookie.secure`.
- Next.js: middleware-only auth is fragile (path matcher gaps, CVE-2025-29927 `x-middleware-subrequest` bypass in < 15.2.3 / 14.2.25). Server Actions need their own auth checks. Also check `NEXT_PUBLIC_*` env vars: they are shipped to the browser, so no secrets there.
- NestJS: `ValidationPipe` without `whitelist` → mass assignment; guards via `@UseGuards`.
- `cors({origin: true, credentials: true})` reflects any origin with cookies = High.
- TypeScript types are **not** runtime validation; `req.body as UserDto` is still tainted.
