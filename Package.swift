// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftAccessMechanism",
    platforms: [.macOS(.v14), .iOS(.v16)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftAccessMechanism",
            targets: ["SwiftAccessMechanism"]
        ),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/airsidemobile/JOSESwift.git", .upToNextMajor(from: "3.0.0")),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftAccessMechanism",
            dependencies: [.target(name: "OpaqueKE_UniFFI"), "JOSESwift"]
        ),
        .binaryTarget(name: "OpaqueKE_UniFFI", path: "external/opaque_ke_uniffiFFI.xcframework"),
        .testTarget(
            name: "SwiftAccessMechanismTests",
            dependencies: ["SwiftAccessMechanism"]
        )
    ]

)
