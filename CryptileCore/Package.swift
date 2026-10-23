// swift-tools-version: 5.9
// CryptileCore — the auditable crypto core of Cryptile (encrypted photo/file vault).
// Pure Swift + Apple CryptoKit/CommonCrypto. No third-party dependencies, no network.
// The byte-level specification is reference/cryptile_ref.py; the test suite proves
// this package matches it on every vector in Tests/CryptileCoreTests/Resources/vectors.json.
import PackageDescription

let package = Package(
    name: "CryptileCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "CryptileCore", targets: ["CryptileCore"]),
    ],
    targets: [
        .target(name: "CryptileCore"),
        .testTarget(
            name: "CryptileCoreTests",
            dependencies: ["CryptileCore"],
            resources: [.copy("Resources/vectors.json")]
        ),
    ]
)
