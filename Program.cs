// DevOidc: an OpenID Connect provider for LOCAL TESTING ONLY.
//
// It signs in anyone as anyone, with no password, so that a developer or a test script can get
// tokens for a local API and a local single-page application without a real identity provider.
// It listens on this computer's loopback addresses only, refuses any caller that is not on this
// computer, and has no deployment script on purpose. README.md has the rest.

using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

const string ScriptGrant = "urn:devoidc:user";

// ---- command line ------------------------------------------------------------------------------
var configPaths = new List<string>();
var port = 5443;
string? certPem = null, keyPem = null;
try
{
    for (var i = 0; i < args.Length; i++)
    {
        var name = args[i];
        string Value() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"{name} needs a value.");
        switch (name)
        {
            case "--config": configPaths.Add(Path.GetFullPath(Value())); break;
            case "--port": port = int.Parse(Value()); break;
            case "--cert-pem": certPem = Path.GetFullPath(Value()); break;
            case "--key-pem": keyPem = Path.GetFullPath(Value()); break;
            default: throw new ArgumentException($"Unknown argument {name}.");
        }
    }
    if (configPaths.Count == 0) throw new ArgumentException("No --config file was given.");
    if ((certPem is null) != (keyPem is null)) throw new ArgumentException("--cert-pem and --key-pem go together.");
}
catch (Exception e) when (e is ArgumentException or FormatException)
{
    Console.Error.WriteLine(e.Message);
    Console.Error.WriteLine("Usage: DevOidc --config <file.json> [--config <another.json>] [--port 5443] [--cert-pem <file> --key-pem <file>]");
    return 2;
}

var issuer = $"https://localhost:{port}";
Registry registry;
try
{
    registry = new Registry(configPaths);
}
catch (Exception e)
{
    Console.Error.WriteLine($"The configuration could not be read: {e.Message}");
    return 2;
}
var signer = Signer.LoadOrCreate();

// What has been handed out. All of it lives in memory: a restart signs everyone out.
var codes = new ConcurrentDictionary<string, Grant>();
var refreshTokens = new ConcurrentDictionary<string, Grant>();
var lastAuthTime = new ConcurrentDictionary<string, long>(StringComparer.OrdinalIgnoreCase);

// ---- the web host: loopback only ---------------------------------------------------------------
var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = [] });
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(o => o.SingleLine = true);
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.WebHost.ConfigureKestrel(kestrel => kestrel.ListenLocalhost(port, listen =>
{
    if (certPem is null)
    {
        listen.UseHttps(); // the ASP.NET Core development certificate (dotnet dev-certs https --trust)
    }
    else
    {
        // Windows cannot serve TLS from a key that only lives in memory, hence the round trip.
        using var pem = X509Certificate2.CreateFromPemFile(certPem, keyPem);
        listen.UseHttps(X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null));
    }
}));
var app = builder.Build();

app.Use(async (ctx, next) =>
{
    // The second guard behind the loopback listener: nobody off this computer gets an answer.
    if (ctx.Connection.RemoteIpAddress is { } remote && !IPAddress.IsLoopback(remote))
    {
        ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
        await ctx.Response.WriteAsync("DevOidc answers this computer only.");
        return;
    }

    // A single-page application calls discovery and /token from the browser, so its origin must be
    // allowed. The origins are those of the registered redirect addresses, nothing wider.
    var origin = ctx.Request.Headers.Origin.ToString();
    if (origin.Length > 0 && registry.Current.Origins.Contains(origin))
    {
        var headers = ctx.Response.Headers;
        headers.AccessControlAllowOrigin = origin;
        headers.Vary = "Origin";
        if (HttpMethods.IsOptions(ctx.Request.Method))
        {
            var asked = ctx.Request.Headers.AccessControlRequestHeaders.ToString();
            headers.AccessControlAllowMethods = "GET, POST, OPTIONS";
            headers.AccessControlAllowHeaders = asked.Length > 0 ? asked : "*";
            headers.AccessControlMaxAge = "600";
            headers["Access-Control-Allow-Private-Network"] = "true";
            ctx.Response.StatusCode = StatusCodes.Status204NoContent;
            return;
        }
    }
    await next();
});

// ---- discovery and keys ------------------------------------------------------------------------
app.MapGet("/.well-known/openid-configuration", () => Results.Json(new JsonObject
{
    ["issuer"] = issuer,
    ["authorization_endpoint"] = $"{issuer}/authorize",
    ["token_endpoint"] = $"{issuer}/token",
    ["userinfo_endpoint"] = $"{issuer}/userinfo",
    ["jwks_uri"] = $"{issuer}/jwks",
    ["end_session_endpoint"] = $"{issuer}/logout",
    ["response_types_supported"] = Strings("code"),
    ["response_modes_supported"] = Strings("query", "fragment"),
    ["grant_types_supported"] = Strings("authorization_code", "refresh_token", ScriptGrant),
    ["subject_types_supported"] = Strings("public"),
    ["id_token_signing_alg_values_supported"] = Strings("RS256"),
    ["scopes_supported"] = Strings("openid", "profile", "email", "offline_access"),
    ["token_endpoint_auth_methods_supported"] = Strings("none"),
    ["code_challenge_methods_supported"] = Strings("S256"),
    ["claims_supported"] = Strings("iss", "aud", "sub", "email", "emails", "name", "given_name", "family_name", "auth_time", "iat", "nbf", "exp", "nonce"),
}));

app.MapGet("/jwks", () => Results.Json(new JsonObject { ["keys"] = new JsonArray(signer.PublicJwk()) }));

// ---- sign-in: the page that lists the test users, and the answer to its buttons -----------------
// The cast matters: without it this lambda also fits RequestDelegate, which discards what it returns.
app.MapGet("/authorize", (Func<HttpContext, Task<IResult>>)(ctx => Authorize(ctx, key => ctx.Request.Query[key].FirstOrDefault())));
app.MapPost("/authorize", async (HttpContext ctx) =>
{
    var form = await ctx.Request.ReadFormAsync();
    return await Authorize(ctx, key => form[key].FirstOrDefault());
});

async Task<IResult> Authorize(HttpContext ctx, Func<string, string?> read)
{
    string? P(string key) => read(key) is { Length: > 0 } value ? value : null;
    var config = registry.Current;

    // Until the client and its redirect address are known to be registered, nothing is sent
    // anywhere: the mistake is shown here, with what was asked and what is registered.
    var clientId = P("client_id");
    if (clientId is null || !config.Clients.TryGetValue(clientId, out var client))
    {
        return Page.Problem("This application is not registered with DevOidc.",
            $"client_id: {clientId ?? "(none)"}", "Registered: " + string.Join(", ", config.Clients.Keys));
    }
    var redirectUri = P("redirect_uri");
    if (redirectUri is null || !client.RedirectUris.Contains(redirectUri, StringComparer.Ordinal))
    {
        return Page.Problem($"That redirect address is not registered for {client.Name}.",
            $"redirect_uri: {redirectUri ?? "(none)"}", "Registered: " + string.Join(", ", client.RedirectUris));
    }

    var state = P("state");
    var asFragment = P("response_mode") == "fragment";
    IResult Back(params (string Key, string? Value)[] answer)
    {
        var pairs = answer.Append((Key: "state", Value: state)).Where(p => p.Value is not null)
            .Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value!)}");
        var separator = asFragment ? "#" : redirectUri.Contains('?') ? "&" : "?";
        return Results.Redirect(redirectUri + separator + string.Join("&", pairs));
    }

    if (P("response_type") != "code")
        return Back(("error", "unsupported_response_type"), ("error_description", "DevOidc issues authorization codes only (response_type=code)."));
    if (P("code_challenge") is not { } challenge || P("code_challenge_method") != "S256")
        return Back(("error", "invalid_request"), ("error_description", "PKCE is required: send code_challenge with code_challenge_method=S256."));
    if (P("prompt") == "none")
        return Back(("error", "login_required"), ("error_description", "DevOidc keeps no browser session, so every sign-in shows its page."));

    var email = P("email")?.Trim();
    if (!HttpMethods.IsPost(ctx.Request.Method) || email is null)
    {
        var carried = new[] { "client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "nonce", "code_challenge", "code_challenge_method" }
            .Select(key => (key, P(key))).Where(p => p.Item2 is not null).Select(p => (p.key, p.Item2!));
        return Page.SignIn(client, config.Users, carried);
    }

    var authTime = await NextAuthTime(email);
    var code = Token.Random();
    Prune(codes);
    codes[code] = new Grant(client.ClientId, email, authTime, P("nonce"), P("scope") ?? "openid", redirectUri, challenge, DateTimeOffset.UtcNow.AddSeconds(60));
    Log($"sign-in   {email}  ->  {client.Name}");
    return Back(("code", code));
}

// ---- tokens ------------------------------------------------------------------------------------
app.MapPost("/token", async (HttpContext ctx) =>
{
    var form = await ctx.Request.ReadFormAsync();
    string? P(string key) => form[key].FirstOrDefault() is { Length: > 0 } value ? value : null;
    ctx.Response.Headers.CacheControl = "no-store";
    var config = registry.Current;

    if (P("client_id") is not { } clientId || !config.Clients.TryGetValue(clientId, out var client))
        return Refuse("invalid_client", "client_id is missing or not registered with DevOidc.");

    switch (P("grant_type"))
    {
        case "authorization_code":
        {
            if (P("code") is not { } code || !codes.TryRemove(code, out var grant) || grant.Expires < DateTimeOffset.UtcNow)
                return Refuse("invalid_grant", "The code is unknown, already used, or older than a minute.");
            if (grant.ClientId != client.ClientId || grant.RedirectUri != P("redirect_uri"))
                return Refuse("invalid_grant", "The code was issued to another client or redirect address.");
            if (P("code_verifier") is not { } verifier || Token.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))) != grant.CodeChallenge)
                return Refuse("invalid_grant", "code_verifier does not match the code_challenge of the sign-in request.");
            return Issue(client, grant, config, withRefreshToken: true, clientInfo: P("client_info") == "1");
        }
        case "refresh_token":
        {
            if (P("refresh_token") is not { } refresh || !refreshTokens.TryGetValue(refresh, out var grant) || grant.ClientId != client.ClientId)
                return Refuse("invalid_grant", "The refresh token is unknown (DevOidc forgets them when it restarts) or was revoked by a sign-out.");
            // A renewed token keeps the moment of the original sign-in, as a real provider's does.
            return Issue(client, grant with { Nonce = null }, config, withRefreshToken: false, refreshToken: refresh, clientInfo: P("client_info") == "1");
        }
        case ScriptGrant:
        {
            if (P("email")?.Trim() is not { Length: > 0 } email)
                return Refuse("invalid_request", "email is required.");
            int? lifetime = null;
            long? authTime = null;
            if (P("lifetime_seconds") is { } l) { if (int.TryParse(l, out var n)) lifetime = n; else return Refuse("invalid_request", "lifetime_seconds must be a whole number."); }
            if (P("auth_time") is { } a) { if (long.TryParse(a, out var n)) authTime = n; else return Refuse("invalid_request", "auth_time must be seconds since 1970."); }
            var grant = new Grant(client.ClientId, email, authTime ?? await NextAuthTime(email), P("nonce"), P("scope") ?? "openid profile offline_access", null, null, DateTimeOffset.MaxValue);
            Log($"script    {email}  ->  {client.Name}{(lifetime is null ? "" : $"  lifetime {lifetime}s")}{(authTime is null ? "" : $"  auth_time {authTime}")}{(P("aud") is { } aud ? $"  aud {aud}" : "")}");
            return Issue(client, grant, config, withRefreshToken: false, lifetime: lifetime, audience: P("aud"), alwaysAccessToken: true, clientInfo: P("client_info") == "1");
        }
        default:
            return Refuse("unsupported_grant_type", $"grant_type must be authorization_code, refresh_token or {ScriptGrant}.");
    }
});

IResult Issue(Client client, Grant grant, Snapshot config, bool withRefreshToken, string? refreshToken = null,
              int? lifetime = null, string? audience = null, bool alwaysAccessToken = false, bool clientInfo = false)
{
    var seconds = lifetime ?? client.TokenLifetimeSeconds;
    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    // A token asked to be expired already (a negative lifetime) was also issued before it expired.
    var issuedAt = seconds > 0 ? now : now + seconds - 60;
    var user = config.Find(grant.Email);
    var claims = new JsonObject
    {
        ["iss"] = issuer,
        ["aud"] = audience ?? client.ClientId,
        ["sub"] = Token.Subject(grant.Email),
        ["email"] = user.Email,
        ["emails"] = Strings(user.Email),
        ["name"] = user.Name,
        ["given_name"] = user.GivenName,
        ["family_name"] = user.FamilyName,
        ["auth_time"] = grant.AuthTime,
        ["iat"] = issuedAt,
        ["nbf"] = issuedAt,
        ["exp"] = now + seconds,
    };
    if (grant.Nonce is not null) claims["nonce"] = grant.Nonce;
    var jwt = signer.Sign(claims);

    var answer = new JsonObject
    {
        ["token_type"] = "Bearer",
        ["expires_in"] = Math.Max(seconds, 0),
        ["id_token"] = jwt,
        ["id_token_expires_in"] = Math.Max(seconds, 0),
        ["scope"] = grant.Scope,
    };
    // The access token is the same signed token: the API reads the same claims from either.
    if (client.AccessToken || alwaysAccessToken) answer["access_token"] = jwt;
    if (withRefreshToken)
    {
        refreshToken = Token.Random();
        refreshTokens[refreshToken] = grant;
    }
    if (refreshToken is not null) answer["refresh_token"] = refreshToken;
    // Microsoft's libraries (MSAL) ask for client_info=1 and build the account's id from the answer,
    // as they do with Azure AD B2C. Without it they fall back to sub and warn on every token.
    if (clientInfo)
    {
        var info = new JsonObject { ["uid"] = Token.Subject(grant.Email), ["utid"] = "devoidc" };
        answer["client_info"] = Token.Base64Url(Encoding.UTF8.GetBytes(info.ToJsonString()));
    }
    return Results.Json(answer);
}

app.MapMethods("/userinfo", ["GET", "POST"], (HttpContext ctx) =>
{
    var header = ctx.Request.Headers.Authorization.ToString();
    var claims = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? signer.Read(header[7..].Trim(), mustBeCurrent: true) : null;
    if (claims is null)
    {
        ctx.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
        return Results.StatusCode(StatusCodes.Status401Unauthorized);
    }
    var info = new JsonObject();
    foreach (var name in new[] { "sub", "email", "emails", "name", "given_name", "family_name" })
        if (claims[name] is { } value) info[name] = value.DeepClone();
    return Results.Json(info);
});

// ---- sign-out ----------------------------------------------------------------------------------
app.MapMethods("/logout", ["GET", "POST"], async (HttpContext ctx) =>
{
    var form = ctx.Request.HasFormContentType ? await ctx.Request.ReadFormAsync() : null;
    string? P(string key) => (ctx.Request.Query[key].FirstOrDefault() ?? form?[key].FirstOrDefault()) is { Length: > 0 } value ? value : null;
    var config = registry.Current;

    // There is no browser session to end. What a sign-out can end is the renewal of tokens.
    Client? hinted = null;
    if (P("id_token_hint") is { } hint && signer.Read(hint, mustBeCurrent: false) is { } claims
        && claims["aud"]?.GetValue<string>() is { } aud && claims["email"]?.GetValue<string>() is { } email)
    {
        config.Clients.TryGetValue(aud, out hinted);
        foreach (var entry in refreshTokens.Where(t => t.Value.ClientId == aud && string.Equals(t.Value.Email, email, StringComparison.OrdinalIgnoreCase)))
            refreshTokens.TryRemove(entry.Key, out _);
        Log($"sign-out  {email}");
    }

    if (P("post_logout_redirect_uri") is not { } target)
        return Page.Message("You are signed out.", "DevOidc keeps no browser session, so there was nothing else to end.");

    // The address may carry a query (the application's own, such as ?reason=...); the part that
    // must be registered is everything before it.
    var withoutQuery = target.Split('?', '#')[0];
    var candidates = hinted is not null ? [hinted] : config.Clients.Values;
    if (!candidates.Any(c => c.PostLogoutRedirectUris.Contains(withoutQuery, StringComparer.Ordinal)))
    {
        return Page.Problem("That address is not registered as a place to return to after sign-out.",
            $"post_logout_redirect_uri: {target}", "Registered: " + string.Join(", ", candidates.SelectMany(c => c.PostLogoutRedirectUris)));
    }
    if (P("state") is { } state) target += (target.Contains('?') ? "&" : "?") + "state=" + Uri.EscapeDataString(state);
    return Results.Redirect(target);
});

app.MapGet("/", () => Page.Home(issuer, registry.Current, registry.Paths));

// ---- start -------------------------------------------------------------------------------------
var line = new string('=', 78);
Console.WriteLine(line);
Console.WriteLine(" DevOidc: a sign-in provider for LOCAL TESTING ONLY.");
Console.WriteLine(" It asks no password: whoever reaches it signs in as anyone. It answers this");
Console.WriteLine(" computer only. Never deploy it, and never let a real environment trust it.");
Console.WriteLine(line);
Console.WriteLine($" Issuer    {issuer}");
foreach (var path in registry.Paths) Console.WriteLine($" Config    {path}");
foreach (var client in registry.Current.Clients.Values) Console.WriteLine($" Client    {client.ClientId}  {client.Name}");
Console.WriteLine($" Users     {registry.Current.Users.Count} listed on the sign-in page (any other e-mail can be typed)");
Console.WriteLine($" Key       {signer.Path}");
Console.WriteLine(line);

try
{
    app.Run();
}
catch (IOException e) when (e.InnerException is System.Net.Sockets.SocketException)
{
    Console.Error.WriteLine($"Port {port} is taken: {e.InnerException.Message}");
    return 1;
}
return 0;

// ---- helpers -----------------------------------------------------------------------------------
static JsonArray Strings(params string[] values) => new(values.Select(v => (JsonNode)v).ToArray());

static IResult Refuse(string error, string description) =>
    Results.Json(new JsonObject { ["error"] = error, ["error_description"] = description }, statusCode: StatusCodes.Status400BadRequest);

static void Log(string message) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {message}");

static void Prune(ConcurrentDictionary<string, Grant> grants)
{
    foreach (var stale in grants.Where(g => g.Value.Expires < DateTimeOffset.UtcNow)) grants.TryRemove(stale.Key, out _);
}

// The moment of a sign-in, in whole seconds, and never the same second twice for one person.
// An API that revokes a session by remembering the auth_time of the token that signed out (and
// then refuses every token that is not newer) would otherwise refuse a sign-in made in the same
// second as the one before it, which only a provider with no password to type can produce.
async Task<long> NextAuthTime(string email)
{
    while (true)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var last = lastAuthTime.GetOrAdd(email, 0);
        if (now > last && lastAuthTime.TryUpdate(email, now, last)) return now;
        await Task.Delay(100);
    }
}

// ---- types -------------------------------------------------------------------------------------
sealed record Client(string ClientId, string Name, string[] RedirectUris, string[] PostLogoutRedirectUris, bool AccessToken, int TokenLifetimeSeconds);

sealed record User(string Email, string Name, string GivenName, string FamilyName, string Note);

sealed record Grant(string ClientId, string Email, long AuthTime, string? Nonce, string Scope, string? RedirectUri, string? CodeChallenge, DateTimeOffset Expires);

sealed record Snapshot(IReadOnlyDictionary<string, Client> Clients, IReadOnlyList<User> Users, IReadOnlySet<string> Origins)
{
    /// <summary>The listed user with this e-mail, or a person made up from the address itself.</summary>
    public User Find(string email)
    {
        if (Users.FirstOrDefault(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase)) is { } listed) return listed;
        var words = email.Split('@')[0].Split(['.', '_', '-', '+'], StringSplitOptions.RemoveEmptyEntries)
            .Select(w => char.ToUpperInvariant(w[0]) + w[1..]).ToArray();
        var given = words.Length > 0 ? words[0] : email;
        return new User(email, words.Length > 0 ? string.Join(' ', words) : email, given, string.Join(' ', words.Skip(1)), "");
    }
}

/// <summary>
/// The clients and users, read from the --config files. Every project that tests against DevOidc
/// keeps its own file and one DevOidc serves them all. A saved file is re-read on the next request.
/// </summary>
sealed class Registry
{
    private static readonly JsonDocumentOptions Lenient = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };
    private readonly Lock _gate = new();
    private Snapshot _snapshot;
    private DateTime[] _stamps;

    public IReadOnlyList<string> Paths { get; }

    public Registry(IReadOnlyList<string> paths)
    {
        Paths = paths;
        _stamps = Stamps();
        _snapshot = Read();
    }

    public Snapshot Current
    {
        get
        {
            lock (_gate)
            {
                var stamps = Stamps();
                if (!stamps.SequenceEqual(_stamps))
                {
                    try
                    {
                        _snapshot = Read();
                        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] configuration re-read");
                    }
                    catch (Exception e)
                    {
                        Console.Error.WriteLine($"[{DateTime.Now:HH:mm:ss}] the changed configuration is not usable, the last good one stays: {e.Message}");
                    }
                    _stamps = stamps;
                }
                return _snapshot;
            }
        }
    }

    private DateTime[] Stamps() => Paths.Select(File.GetLastWriteTimeUtc).ToArray();

    private Snapshot Read()
    {
        var clients = new Dictionary<string, Client>(StringComparer.OrdinalIgnoreCase);
        var users = new List<User>();
        foreach (var path in Paths)
        {
            var root = JsonNode.Parse(File.ReadAllText(path), documentOptions: Lenient) as JsonObject
                       ?? throw new InvalidDataException($"{path} is not a JSON object.");
            foreach (var node in root["clients"] as JsonArray ?? [])
            {
                var id = Text(node, "client_id") ?? throw new InvalidDataException($"{path}: a client has no client_id.");
                var redirects = List(node, "redirect_uris");
                if (redirects.Length == 0) throw new InvalidDataException($"{path}: client {id} has no redirect_uris.");
                if (!clients.TryAdd(id, new Client(id, Text(node, "name") ?? id, redirects, List(node, "post_logout_redirect_uris"),
                        node?["access_token"]?.GetValue<bool>() ?? true,
                        node?["token_lifetime_seconds"]?.GetValue<int>() ?? 3600)))
                    throw new InvalidDataException($"{path}: client {id} is defined twice.");
            }
            foreach (var node in root["users"] as JsonArray ?? [])
            {
                var email = Text(node, "email") ?? throw new InvalidDataException($"{path}: a user has no email.");
                if (users.Any(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase))) continue;
                var name = Text(node, "name") ?? email;
                users.Add(new User(email, name, Text(node, "given_name") ?? name.Split(' ')[0],
                    Text(node, "family_name") ?? string.Join(' ', name.Split(' ').Skip(1)), Text(node, "note") ?? ""));
            }
        }
        var origins = clients.Values.SelectMany(c => c.RedirectUris).Select(u => new Uri(u).GetLeftPart(UriPartial.Authority))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return new Snapshot(clients, users, origins);
    }

    private static string? Text(JsonNode? node, string key) => node?[key]?.GetValue<string>() is { Length: > 0 } value ? value.Trim() : null;

    private static string[] List(JsonNode? node, string key) =>
        (node?[key] as JsonArray ?? []).Select(v => v!.GetValue<string>().Trim()).ToArray();
}

/// <summary>
/// The RSA key the tokens are signed with. Made on the first run and kept in the user's own
/// application-data folder, outside every repository, so it survives rebuilds and is never committed.
/// </summary>
sealed class Signer
{
    private readonly RSA _rsa;
    private readonly string _keyId;

    public string Path { get; }

    private Signer(RSA rsa, string path)
    {
        _rsa = rsa;
        Path = path;
        _keyId = Token.Base64Url(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()))[..16];
    }

    public static Signer LoadOrCreate()
    {
        var folder = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DevOidc");
        var path = System.IO.Path.Combine(folder, "signing-key.pem");
        var rsa = RSA.Create(2048);
        if (File.Exists(path))
        {
            rsa.ImportFromPem(File.ReadAllText(path));
        }
        else
        {
            Directory.CreateDirectory(folder);
            File.WriteAllText(path, rsa.ExportRSAPrivateKeyPem());
        }
        return new Signer(rsa, path);
    }

    public JsonNode PublicJwk()
    {
        var p = _rsa.ExportParameters(includePrivateParameters: false);
        return new JsonObject
        {
            ["kty"] = "RSA", ["use"] = "sig", ["alg"] = "RS256", ["kid"] = _keyId,
            ["n"] = Token.Base64Url(p.Modulus!), ["e"] = Token.Base64Url(p.Exponent!),
        };
    }

    public string Sign(JsonObject claims)
    {
        var header = new JsonObject { ["alg"] = "RS256", ["typ"] = "JWT", ["kid"] = _keyId };
        var signed = Token.Base64Url(Encoding.UTF8.GetBytes(header.ToJsonString())) + "." + Token.Base64Url(Encoding.UTF8.GetBytes(claims.ToJsonString()));
        return signed + "." + Token.Base64Url(_rsa.SignData(Encoding.ASCII.GetBytes(signed), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    /// <summary>The claims of a token this provider signed, or null for anything else.</summary>
    public JsonObject? Read(string jwt, bool mustBeCurrent)
    {
        try
        {
            var parts = jwt.Split('.');
            if (parts.Length != 3) return null;
            if (!_rsa.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), Token.FromBase64Url(parts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) return null;
            var claims = JsonNode.Parse(Token.FromBase64Url(parts[1])) as JsonObject;
            if (claims is null) return null;
            if (mustBeCurrent && !(claims["exp"]?.GetValue<long>() > DateTimeOffset.UtcNow.ToUnixTimeSeconds())) return null;
            return claims;
        }
        catch (Exception e) when (e is FormatException or JsonException or InvalidOperationException or CryptographicException)
        {
            return null;
        }
    }
}

static class Token
{
    public static string Random() => Base64Url(RandomNumberGenerator.GetBytes(32));

    public static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromBase64Url(string text)
    {
        var padded = text.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '='));
    }

    /// <summary>The same e-mail always gets the same subject, on every computer.</summary>
    public static string Subject(string email) =>
        new Guid(SHA256.HashData(Encoding.UTF8.GetBytes("devoidc:" + email.Trim().ToLowerInvariant())).AsSpan(0, 16)).ToString();
}

/// <summary>The few pages a person sees. Every value shown is HTML-encoded.</summary>
static class Page
{
    private const string Style = """
        :root { color-scheme: light dark; --ink: #1c1b22; --quiet: #5f5d6b; --line: #d9d7e0; --paper: #f6f5f9; --card: #ffffff; --accent: #5a35c9; --warn-ink: #7a4b00; --warn: #fff4d6; }
        @media (prefers-color-scheme: dark) { :root { --ink: #ecebf2; --quiet: #a9a6b8; --line: #3a3846; --paper: #17161c; --card: #201f27; --accent: #b39cff; --warn-ink: #ffd98a; --warn: #3a2f12; } }
        * { box-sizing: border-box; }
        body { margin: 0; font: 16px/1.5 system-ui, "Segoe UI", sans-serif; color: var(--ink); background: var(--paper); }
        main { max-width: 34rem; margin: 6vh auto; padding: 0 1.25rem 3rem; }
        .tag { display: inline-block; margin: 0 0 1rem; padding: .2rem .6rem; border-radius: 1rem; background: var(--warn); color: var(--warn-ink); font-size: .75rem; font-weight: 600; letter-spacing: .06em; }
        h1 { margin: 0 0 .4rem; font-size: 1.5rem; line-height: 1.25; }
        p { margin: 0 0 1.25rem; color: var(--quiet); }
        .user, .other { display: block; width: 100%; margin: 0 0 .6rem; padding: .8rem 1rem; border: 1px solid var(--line); border-radius: .75rem; background: var(--card); color: inherit; font: inherit; text-align: left; }
        .user { cursor: pointer; }
        .user:hover, .user:focus-visible { border-color: var(--accent); outline: none; box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 25%, transparent); }
        .user strong { display: block; }
        .user span { color: var(--quiet); font-size: .9rem; }
        .user em { display: block; color: var(--quiet); font-size: .85rem; font-style: normal; }
        .other { display: flex; gap: .5rem; align-items: end; margin-top: 1.5rem; }
        .other label { flex: 1; font-size: .9rem; color: var(--quiet); }
        .other input { display: block; width: 100%; margin-top: .25rem; padding: .5rem .6rem; border: 1px solid var(--line); border-radius: .5rem; background: var(--paper); color: inherit; font: inherit; }
        .other button { padding: .5rem 1rem; border: 0; border-radius: .5rem; background: var(--accent); color: var(--card); font: inherit; font-weight: 600; cursor: pointer; }
        code, pre { font: .85rem/1.5 ui-monospace, Consolas, monospace; }
        pre { padding: .8rem 1rem; border: 1px solid var(--line); border-radius: .75rem; background: var(--card); overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
        ul { padding-left: 1.2rem; color: var(--quiet); }
        """;

    private static string E(string? text) => WebUtility.HtmlEncode(text ?? "");

    private static IResult Html(string title, string body, int status = 200) => Results.Content(
        $"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{E(title)}</title><style>{Style}</style></head>" +
        $"<body><main><p class=\"tag\">LOCAL TEST SIGN-IN</p>{body}</main></body></html>", "text/html; charset=utf-8", Encoding.UTF8, status);

    public static IResult SignIn(Client client, IReadOnlyList<User> users, IEnumerable<(string Key, string Value)> carried)
    {
        var hidden = string.Concat(carried.Select(p => $"<input type=\"hidden\" name=\"{E(p.Key)}\" value=\"{E(p.Value)}\">"));
        var buttons = string.Concat(users.Select(u =>
            $"<button class=\"user\" name=\"email\" value=\"{E(u.Email)}\"><strong>{E(u.Name)}</strong><span>{E(u.Email)}</span>{(u.Note.Length > 0 ? $"<em>{E(u.Note)}</em>" : "")}</button>"));
        return Html("DevOidc: sign in",
            $"<h1>Sign in to {E(client.Name)}</h1>" +
            "<p>This is DevOidc, a stand-in for the real sign-in, running on this computer. It asks no password: choose who to be.</p>" +
            $"<form method=\"post\" action=\"/authorize\">{hidden}{buttons}</form>" +
            $"<form method=\"post\" action=\"/authorize\" class=\"other\">{hidden}<label>Someone else<input name=\"email\" type=\"email\" required placeholder=\"e-mail address\" autocomplete=\"email\"></label><button>Sign in</button></form>");
    }

    public static IResult Problem(string what, params string[] details) => Html("DevOidc: a problem",
        $"<h1>{E(what)}</h1><p>Nothing was sent anywhere. The request and the registration disagree:</p><pre>{E(string.Join("\n", details))}</pre>" +
        "<p>Clients are registered in the configuration files DevOidc was started with.</p>", StatusCodes.Status400BadRequest);

    public static IResult Message(string what, string detail) => Html("DevOidc", $"<h1>{E(what)}</h1><p>{E(detail)}</p>");

    public static IResult Home(string issuer, Snapshot config, IReadOnlyList<string> paths)
    {
        var first = config.Clients.Values.FirstOrDefault();
        var example = first is null ? "" :
            $"curl -s {issuer}/token -d grant_type=urn:devoidc:user -d client_id={first.ClientId} -d email={(config.Users.Count > 0 ? config.Users[0].Email : "someone@example.test")}";
        return Html("DevOidc",
            "<h1>DevOidc is running</h1>" +
            "<p>A sign-in provider for local testing only. It asks no password, answers this computer only, and must never be deployed.</p>" +
            $"<pre>issuer     {E(issuer)}\ndiscovery  {E(issuer)}/.well-known/openid-configuration\n{E(string.Join("\n", paths.Select(p => "config     " + p)))}</pre>" +
            "<p>Clients</p><ul>" + string.Concat(config.Clients.Values.Select(c => $"<li><code>{E(c.ClientId)}</code> {E(c.Name)}</li>")) + "</ul>" +
            "<p>Users on the sign-in page</p><ul>" + string.Concat(config.Users.Select(u => $"<li>{E(u.Name)}, <code>{E(u.Email)}</code>{(u.Note.Length > 0 ? ": " + E(u.Note) : "")}</li>")) + "</ul>" +
            (example.Length > 0 ? $"<p>A token for a script, without the page:</p><pre>{E(example)}</pre>" : ""));
    }
}
