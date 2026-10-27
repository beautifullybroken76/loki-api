using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;
var conn = config.GetConnectionString("Loki")
    ?? throw new InvalidOperationException(
        "Missing Loki database connection string.");
var jwtKey = config["Jwt:SigningKey"]
    ?? throw new InvalidOperationException(
        "Missing JWT signing key.");
if (string.IsNullOrWhiteSpace(conn) || Encoding.UTF8.GetByteCount(jwtKey) < 32)
    throw new InvalidOperationException("Set ConnectionStrings:Loki and Jwt:SigningKey (at least 32 UTF-8 bytes) in secure hosting configuration.");
var allowed = config.GetSection("AllowedOrigins").Get<string[]>() ?? [];
builder.Services.AddCors(o => o.AddPolicy("Game", p => p.WithOrigins(allowed).AllowAnyHeader().AllowAnyMethod()));
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o => {
    o.RequireHttpsMetadata = true;
    o.TokenValidationParameters = new TokenValidationParameters {
        ValidateIssuer = true, ValidIssuer = config["Jwt:Issuer"],
        ValidateAudience = true, ValidAudience = config["Jwt:Audience"],
        ValidateIssuerSigningKey = true, IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        ValidateLifetime = true, ClockSkew = TimeSpan.FromMinutes(1)
    };
});
builder.Services.AddAuthorization();
builder.Services.AddSingleton<IPasswordHasher<Player>, PasswordHasher<Player>>();
builder.Services.AddRateLimiter(o => {
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("auth", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new FixedWindowRateLimiterOptions {
            PermitLimit = 12, Window = TimeSpan.FromMinutes(5), QueueLimit = 0, AutoReplenishment = true
        }));
});
var app = builder.Build();
app.UseHttpsRedirection();
app.UseCors("Game");
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/api/auth/register", async (Credentials request, IPasswordHasher<Player> hasher) => {
    var name = request.UserName?.Trim() ?? "";
    if (name.Length < 3 || name.Length > 60 || !name.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.'))
        return Results.BadRequest(new { error = "Username must be 3–60 letters, numbers, dots, hyphens or underscores." });
    if (request.Password is null || request.Password.Length < 12 || request.Password.Length > 256)
        return Results.BadRequest(new { error = "Password must be 12–256 characters." });
    var player = new Player(Guid.NewGuid(), name, "");
    var hash = hasher.HashPassword(player, request.Password);
    try {
        await using var db = new SqlConnection(conn); await db.OpenAsync();
        await using var cmd = new SqlCommand("INSERT INTO dbo.LokiPlayers(PlayerId,UserName,NormalizedUserName,PasswordHash) VALUES (@id,@name,@norm,@hash)", db);
        cmd.Parameters.AddWithValue("@id", player.Id);
        cmd.Parameters.AddWithValue("@name", name);
        cmd.Parameters.AddWithValue("@norm", name.ToUpperInvariant());
        cmd.Parameters.AddWithValue("@hash", hash);
        await cmd.ExecuteNonQueryAsync();
        return Results.Ok(new { token = Token(player), userName = name });
    } catch (SqlException ex) when (ex.Number is 2601 or 2627) { return Results.Conflict(new { error = "Username already taken." }); }
}).RequireRateLimiting("auth");

app.MapPost("/api/auth/login", async (Credentials request, IPasswordHasher<Player> hasher) => {
    var name = request.UserName?.Trim() ?? "";
    await using var db = new SqlConnection(conn); await db.OpenAsync();
    await using var cmd = new SqlCommand("SELECT PlayerId,UserName,PasswordHash FROM dbo.LokiPlayers WHERE NormalizedUserName=@name", db);
    cmd.Parameters.AddWithValue("@name", name.ToUpperInvariant());
    await using var r = await cmd.ExecuteReaderAsync();
    if (!await r.ReadAsync()) return Results.Unauthorized();
    var player = new Player(r.GetGuid(0), r.GetString(1), r.GetString(2));
    var check = hasher.VerifyHashedPassword(player, player.PasswordHash, request.Password ?? "");
    if (check == PasswordVerificationResult.Failed) return Results.Unauthorized();
    return Results.Ok(new { token = Token(player), userName = player.UserName });
}).RequireRateLimiting("auth");

app.MapGet("/api/progress", async (ClaimsPrincipal user) => {
    var id = Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);
    await using var db = new SqlConnection(conn); await db.OpenAsync();
    await using var cmd = new SqlCommand("SELECT SaveJson,Revision,UpdatedUtc FROM dbo.LokiProgress WHERE PlayerId=@id", db);
    cmd.Parameters.AddWithValue("@id", id);
    await using var r = await cmd.ExecuteReaderAsync();
    if (!await r.ReadAsync()) return Results.Ok(new { revision = 0, save = (JsonElement?)null });
    return Results.Ok(new { revision = r.GetInt32(1), save = JsonDocument.Parse(r.GetString(0)).RootElement.Clone(), updatedUtc = r.GetDateTime(2) });
}).RequireAuthorization();

app.MapPut("/api/progress", async (ClaimsPrincipal user, SaveRequest req) => {
    if (req.Revision < 0 || req.Save.ValueKind != JsonValueKind.Object) return Results.BadRequest(new { error = "Invalid save or revision." });
    var json = req.Save.GetRawText();
    if (Encoding.UTF8.GetByteCount(json) > 100_000) return Results.BadRequest(new { error = "Save exceeds 100 KB." });
    var id = Guid.Parse(user.FindFirstValue(ClaimTypes.NameIdentifier)!);
    await using var db = new SqlConnection(conn); await db.OpenAsync();
    await using var transaction = (SqlTransaction)await db.BeginTransactionAsync(System.Data.IsolationLevel.Serializable);
    await using var get = new SqlCommand("SELECT Revision FROM dbo.LokiProgress WITH (UPDLOCK,HOLDLOCK) WHERE PlayerId=@id", db, transaction);
    get.Parameters.AddWithValue("@id", id);
    var value = await get.ExecuteScalarAsync();
    var current = value is null ? 0 : Convert.ToInt32(value);
    if (current != req.Revision) { await transaction.RollbackAsync(); return Results.Conflict(new { error = "Cloud save changed on another device.", revision = current }); }
    await using var write = new SqlCommand(current == 0
        ? "INSERT INTO dbo.LokiProgress(PlayerId,SaveJson,Revision) VALUES(@id,@json,1)"
        : "UPDATE dbo.LokiProgress SET SaveJson=@json,Revision=Revision+1,UpdatedUtc=SYSUTCDATETIME() WHERE PlayerId=@id", db, transaction);
    write.Parameters.AddWithValue("@id", id);
    write.Parameters.AddWithValue("@json", json);
    await write.ExecuteNonQueryAsync();
    await transaction.CommitAsync();
    return Results.Ok(new { revision = current + 1 });
}).RequireAuthorization();

app.Run();

string Token(Player player) {
    var claims = new[] { new Claim(ClaimTypes.NameIdentifier, player.Id.ToString()), new Claim(ClaimTypes.Name, player.UserName) };
    var token = new JwtSecurityToken(config["Jwt:Issuer"], config["Jwt:Audience"], claims,
        expires: DateTime.UtcNow.AddHours(12), signingCredentials: new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)), SecurityAlgorithms.HmacSha256));
    return new JwtSecurityTokenHandler().WriteToken(token);
}
record Player(Guid Id, string UserName, string PasswordHash);
record Credentials(string? UserName, string? Password);
record SaveRequest(int Revision, JsonElement Save);
