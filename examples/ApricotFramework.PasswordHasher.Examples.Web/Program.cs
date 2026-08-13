using ApricotFramework.PasswordHasher;
using ApricotFramework.PasswordHasher.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

// One call wires the hasher, binds the "PasswordHasher" configuration section and validates it
// at startup. Try setting Iterations to 100 in appsettings.json to see the host refuse to boot.
builder.Services.AddPasswordHasher(builder.Configuration);

var app = builder.Build();

// Reports the parameters new hashes will be written with.
app.MapGet("/settings", (IPasswordHasher hasher) => Results.Ok(new
{
    Algorithm = hasher.GetAlgorithm(),
    Iterations = hasher.GetIterations(),
}));

// Hashes a password. The value to persist is AsHash(); the individual fields are shown only so
// the encoding is visible.
app.MapPost("/hash", (string password, IPasswordHasher hasher) =>
{
    var hash = hasher.Hash(password);

    return Results.Ok(new
    {
        Stored = hash.AsHash(),
        hash.Algorithm,
        hash.Iterations,
        hash.Salt,
        hash.Key,
    });
});

// Checks a candidate password against a stored hash.
app.MapPost("/verify", (string hash, string password, IPasswordHasher hasher) =>
{
    var result = hasher.Verify(hash, password);

    return Results.Ok(new { result.Verified, result.NeedsUpgrade });
});

// The pattern worth copying: when a hash verifies but was written with older parameters, the
// plain password is in hand exactly once, so rewrite the hash now rather than forcing a reset.
app.MapPost("/login", (string hash, string password, IPasswordHasher hasher) =>
{
    var result = hasher.Verify(hash, password);

    if (!result.Verified)
    {
        return Results.Unauthorized();
    }

    var upgraded = result.NeedsUpgrade ? hasher.Hash(password).AsHash() : null;

    return Results.Ok(new
    {
        Authenticated = true,
        Rehashed = upgraded is not null,
        StoreThis = upgraded ?? hash,
    });
});

// Walks the whole story end to end, including a hash written by the pre-migration library.
app.MapGet("/demo", (IPasswordHasher hasher) =>
{
    const string Password = "correct horse battery staple";

    // Written by an earlier version of this library, under the legacy "RFC" algorithm name at
    // 100 iterations. It still verifies, and is flagged for rehashing because it no longer
    // matches current policy.
    const string Legacy = "RFC.100.AAECAwQFBgcICQoLDA0ODw==.0TUH1s1kMis2AwiquIy+99NwRsZ4ceYxeMbjdYbdQhE=";

    var fresh = hasher.Hash(Password).AsHash();

    return Results.Ok(new
    {
        Current = new { Algorithm = hasher.GetAlgorithm(), Iterations = hasher.GetIterations() },
        FreshHash = fresh,
        FreshVerifies = hasher.Verify(fresh, Password),
        LegacyHash = Legacy,
        LegacyVerifies = hasher.Verify(Legacy, Password),
        WrongPassword = hasher.Verify(fresh, "wrong"),
        CorruptedHash = hasher.Verify("RFC.100.not-base64!.also-not", Password),
    });
});

app.Run();
