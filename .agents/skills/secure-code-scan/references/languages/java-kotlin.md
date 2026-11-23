# Java / Kotlin / Scala / Groovy (Spring, Spring Boot, Jakarta EE/Servlets, Struts, JAX-RS, Android)

## Sources
- Servlet: `getParameter*`, `getHeader*`, `getCookies`, `getQueryString`, `getPathInfo`, `getRequestURI/URL`, `getInputStream/getReader`, `getPart(s)` (+ `getSubmittedFileName`)
- Spring MVC/WebFlux: `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, `@ModelAttribute`, `@MatrixVariable`, `MultipartFile.getOriginalFilename()`, `ServerHttpRequest`
- JAX-RS: `@QueryParam`, `@PathParam`, `@FormParam`, `@HeaderParam`, `@CookieParam`, entity params
- Struts action fields, JSF beans, message listeners (`@KafkaListener`, `@JmsListener`, `@RabbitListener`), Android `Intent.getExtras()`, `getIntent().getData()`, content providers, WebView JS interfaces

## Sinks
| Class | Sinks |
|---|---|
| SQL | `Statement.execute*/addBatch` with concat; `prepareStatement(sql + x)` (prepared but concatenated = still SQLi); JPA/Hibernate `createQuery("... " + x)`, `createNativeQuery`, `@Query(... nativeQuery)` with SpEL `?#{}` misuse; `JdbcTemplate.query/update/queryForObject(sql + x)`; MyBatis `${}` in mappers (`#{}` is safe); jOOQ `DSL.sql/field/condition(String)` plain-SQL APIs; Criteria `cb.literal` misuse; `ORDER BY` + user column |
| Command | `Runtime.exec(String)`, `ProcessBuilder` (esp. `"sh","-c", cmd`), Apache Commons Exec |
| Path | `new File/FileInputStream/FileOutputStream/FileReader/RandomAccessFile(user)`, `Paths.get/Path.of/resolve(user)`, `Files.*`, `ZipEntry.getName()` in extraction (zip slip), Spring `ResourceLoader.getResource(user)`, `ClassPathResource(user)`, `ServletContext.getResourceAsStream(user)` |
| SSRF | `new URL(user).openConnection/openStream`, `RestTemplate.*`, `WebClient.*.uri(user)`, `HttpClient.send(HttpRequest(URI.create(user)))`, Apache `HttpGet(user)`, OkHttp `Request.Builder().url(user)`, Feign with dynamic URL, `ImageIO.read(URL)` |
| XSS | `response.getWriter().print(user)`, JSP `<%= user %>` / `${user}` without `<c:out>`/`fn:escapeXml`, `escapeXml="false"`, Thymeleaf `th:utext`, Freemarker `?no_esc`, `@ResponseBody String` returned with `text/html` |
| Deserialization | `ObjectInputStream.readObject/readUnshared`, `XMLDecoder`, XStream `fromXML` (< 1.4.18 default), Jackson `enableDefaultTyping/activateDefaultTyping` or `@JsonTypeInfo(use=CLASS)`, SnakeYAML `new Yaml().load` (< 2.0 default constructor), Kryo without registration, Hessian/Burlap, `SerializationUtils.deserialize`, JNDI `lookup(user)` (Log4Shell class) |
| XXE | `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`, `Validator`, `SAXReader` (dom4j), `SAXBuilder` (JDOM), `Unmarshaller` (JAXB) without secure features. **Java parsers are insecure by default** |
| EL/SSTI | `SpelExpressionParser.parseExpression(user)` with `StandardEvaluationContext`, OGNL (Struts), `ScriptEngine.eval`, `GroovyShell.evaluate`, Velocity `evaluate(user)`, Freemarker `new Template(name, new StringReader(user))`, Thymeleaf view name from input (`return "user/" + lang;` → fragment expression injection) |
| LDAP | `DirContext.search(base, "(uid=" + u + ")", ...)` |
| Redirect | `sendRedirect(user)`, `"redirect:" + user`, `RedirectView(user)` |
| Reflection | `Class.forName(user)`, `getMethod(user).invoke`, `newInstance` |
| Logging | Log4j 2 < 2.17.1 with user data (Log4Shell, check deps), CRLF in logs |

## Sanitizers / safe APIs
- SQL: `PreparedStatement` with `?` placeholders and `setX()`; JPA named/positional parameters (`:id`, `?1`); Spring Data derived queries; MyBatis `#{}`; jOOQ typed DSL.
- XML: `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`, `XMLConstants.FEATURE_SECURE_PROCESSING`, `setExpandEntityReferences(false)`, `XMLInputFactory.SUPPORT_DTD=false`.
- Deserialization: `ObjectInputFilter` allow-list, Jackson without default typing, SnakeYAML `SafeConstructor`.
- Path: `getCanonicalPath().startsWith(base.getCanonicalPath() + File.separator)`, `Path.normalize()` + `startsWith(base)`.
- HTML: `<c:out>`, Thymeleaf `th:text`, OWASP Java Encoder `Encode.forHtml`, OWASP Java HTML Sanitizer.
- SpEL: `SimpleEvaluationContext`.
- Bean Validation (`@Valid` + `@Pattern`/`@Min`/`@Email`) constrains format: a sanitizer only for matching sinks.

## Framework notes
- Spring Security: `csrf().disable()` on a cookie/session app (OK for pure stateless bearer-token APIs; say so); `permitAll()` on sensitive matchers; matcher order (a broad `permitAll` placed before a specific `authenticated`); `@PreAuthorize` missing on service methods; `mvcMatchers` vs `antMatchers` path-normalization bypasses; actuator endpoints exposed (`management.endpoints.web.exposure.include=*`) = High.
- `application.properties/yml`: hard-coded `spring.datasource.password`, `server.ssl.enabled=false`, `debug=true`, H2 console enabled (`spring.h2.console.enabled=true`).
- Mass assignment: binding entities directly with `@ModelAttribute`/`@RequestBody User user` → use DTOs or `@InitBinder setAllowedFields`.
- `MessageDigest MD5/SHA-1` for passwords → `BCryptPasswordEncoder`/`Argon2PasswordEncoder`; `new Random()` for tokens → `SecureRandom`; `Cipher.getInstance("AES")` defaults to **ECB**.
- Android: `WebView.setJavaScriptEnabled(true)` + `addJavascriptInterface`, `MODE_WORLD_READABLE`, exported components without permissions (`android:exported="true"`), `allowBackup="true"`, cleartext traffic allowed, logging PII with `Log.d`.
