// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftAccessMechanism",
    platforms: [.macOS(.v11), .iOS(.v14)], // Due to the use of the CryptoKit framework (iOS 13) and HKDF (iOS 14)
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftAccessMechanism",
            targets: ["SwiftAccessMechanism"]
        ),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/leif-ibsen/SwiftECC", .upToNextMajor(from: "5.5.0")),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftAccessMechanism",
            dependencies: ["SwiftECC"]
        ),
        .testTarget(
            name: "SwiftAccessMechanismTests",
            dependencies: ["SwiftAccessMechanism"]
        ),
    ]
)
