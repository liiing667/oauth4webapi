# Interface: ExportedJWKSCache

[💗 Help the project](https://github.com/sponsors/panva)

Support from the community to continue maintaining and improving this module is welcome. If you find the module useful, please consider supporting the project by [becoming a sponsor](https://github.com/sponsors/panva).

***

A JSON Web Key Set cache value suitable for external persistence.

## Properties

### jwks

• **jwks**: [`JWKS`](JWKS.md)

***

### uat

• **uat**: `number`

***

### issuer?

• `optional` **issuer?**: `string`

The [`as.issuer`](AuthorizationServer.md#issuer) value the cached JSON Web Key Set belongs to.
A cache recorded for another issuer is never used to select JWT verification keys.
