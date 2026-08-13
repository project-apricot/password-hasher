# ApricotFramework.PasswordHasher

[![NuGet](https://img.shields.io/nuget/v/ApricotFramework.PasswordHasher.svg?label=ApricotFramework.PasswordHasher)](https://www.nuget.org/packages/ApricotFramework.PasswordHasher/)
[![NuGet](https://img.shields.io/nuget/v/ApricotFramework.PasswordHasher.AspNetCore.svg?label=ApricotFramework.PasswordHasher.AspNetCore)](https://www.nuget.org/packages/ApricotFramework.PasswordHasher.AspNetCore/)
[![CI](https://github.com/project-apricot/password-hasher/actions/workflows/ci.yml/badge.svg)](https://github.com/project-apricot/password-hasher/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/project-apricot/password-hasher/blob/main/LICENSE)

Password hashing for .NET: PBKDF2 with a per-hash salt, the parameters recorded alongside the
hash, constant-time verification, and a signal telling you when to rehash.

`ApricotFramework.PasswordHasher` is the **zero-dependency** core.

## Install

```bash
dotnet add package ApricotFramework.PasswordHasher
dotnet add package ApricotFramework.PasswordHasher.AspNetCore
```

## Usage

```csharp
using ApricotFramework.PasswordHasher.AspNetCore.Extensions;

builder.Services.AddPasswordHasher(builder.Configuration);
```

```csharp
using ApricotFramework.PasswordHasher;

// Store the encoded string. It carries the algorithm, iteration count and salt with it.
var stored = hasher.Hash(password).AsHash();

var result = hasher.Verify(stored, candidate);

if (result.Verified && result.NeedsUpgrade)
{
    // The password is in hand exactly once. Rewrite the hash with current parameters.
    stored = hasher.Hash(candidate).AsHash();
}
```

Note that the encoded form, `{algorithm}.{iterations}.{salt}.{key}`, is what consumers persist,
so it is a compatibility contract and will not change without a major version. Hashes written by
earlier versions under the `RFC` algorithm name still verify and are reported as needing an
upgrade. Verification always uses the parameters stored inside the hash, so raising the
configured iteration count never locks anyone out.

Full documentation: <https://projectapricot.dev>
