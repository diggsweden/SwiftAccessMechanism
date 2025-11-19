//
//  OpaqueKEBuffer.swift
//  SwiftAccessMechanism
//
//  Created by Fredrik Thulin on 2025-11-13.
//

import Foundation
import OpaqueKE

/// RAII wrapper for a buffer allocated by the underlying OpaqueKE library.
/// The wrapper owns the handle and will free it in `deinit`.
public final class OpaqueKEBuffer {
    fileprivate var _ptr: UnsafeMutableRawPointer?

    public init(_ ptr: UnsafeMutableRawPointer) {
        self._ptr = ptr
    }

    public init?(handle: UnsafeMutableRawPointer?) {
        if handle == nil {
            return nil
        }
        self._ptr = handle
    }

    /// Create a new OpaqueKEBuffer by allocating a buffer in the Rust library
    /// and copying the provided `data` into it via `opaque_ke_buffer_new()`.
    /// This is a convenience initializer that wraps the returned handle.
    public convenience init(data: Data?) {
        guard let data else {
            self.init()
            return
        }

        let rawHandle: UnsafeMutableRawPointer?
        rawHandle = data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> UnsafeMutableRawPointer? in
            let base = buffer.baseAddress!.assumingMemoryBound(to: UInt8.self)
            return opaque_ke_buffer_new(base, UInt(buffer.count))
        }

        guard let p = rawHandle else {
            fatalError("opaque_ke_buffer_new returned null handle (input length: \(data.count))")
        }

        self.init(p)
    }

    /// Create an empty (uninitialized) wrapper that does not own any handle yet.
    /// Use `assignRawHandle(_:)` after an FFI call has produced a raw handle.
    public init() {
        self._ptr = nil
    }

    deinit {
        if let p = _ptr {
            opaque_ke_buffer_free(p)
        }
    }

    var data: Data? {
        if let p = _ptr {
            let len = Int(opaque_ke_buffer_len(p))
            return Data(bytes: opaque_ke_buffer_data(p), count: len)
        }
        return nil
    }

    /// Temporarily access the raw pointer without transferring ownership.
    /// The closure is executed with the raw pointer while the wrapper retains ownership.
    ///
    /// Example:
    /// try buffer.withRawHandle { ptr in
    ///     // call C functions using `ptr` but do NOT free it
    /// }
    public func withRawHandle<T>(_ body: (UnsafeMutableRawPointer) throws -> T) rethrows -> T {
        guard let p = self._ptr else {
            fatalError("OpaqueKEBuffer.withRawHandle: invalid handle")
        }
        return try body(p)
    }

    public func withRawHandleOrNull<T>(_ body: (UnsafeMutableRawPointer?) throws -> T) rethrows -> T {
        return try body(self._ptr)
    }
}

/// A distinct type for client login data passed between OpaqueKE functions
public struct ClientLoginHandle {
    let value: OpaqueKEBuffer

    public init(_ ptr: OpaqueKEBuffer) {
        self.value = ptr
    }
}

/// A distinct type for client registration handles passed between OpaqueKE functions
public struct ClientRegistrationHandle {
    let value: OpaqueKEBuffer

    public init(_ ptr: UnsafeMutableRawPointer) {
        self.value = OpaqueKEBuffer(ptr)
    }
}

public final class ServerSetupHandle {
    public let value: OpaqueKEBuffer

    public init(_ ptr: UnsafeMutableRawPointer) {
        self.value = OpaqueKEBuffer(ptr)
    }
}
